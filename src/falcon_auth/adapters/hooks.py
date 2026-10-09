"""Falcon integration: hook factories + error-handler registration.

The hooks are **closure factories** (Shape A) — the caller binds a specific
:class:`~falcon_auth.eastwest.verifier.Verifier` at decoration time. This avoids
module-level state, keeps two verifiers in the same process independent, and
makes each route file's identity gate visible in its imports.

Typical wiring::

    # boot (app/http.py or equivalent)
    from falcon_auth.eastwest import Verifier, build_allow_list
    from falcon_auth.adapters.hooks import register_error_handlers

    verifier = Verifier(build_allow_list(settings.svcplane.allow_list))
    register_error_handlers(http_app)

    # per route. Binding happens at DECORATION time -- when this module is imported -- so the
    # verifier must already be constructed. A module-level singleton built at boot satisfies
    # that; a container that populates later, or a `configure()` that runs after routes import,
    # does not. Each factory CHECKS this and raises here rather than leaving a hook holding a
    # placeholder that 500s at request time.
    from falcon_auth.adapters.hooks import require_service_capability
    from app.services import verifier   # constructed at boot, BEFORE routes import

    class InternalRevocationsRoute:
        @falcon.before(require_service_capability(verifier, "revocations.sessions:read"))
        async def on_get_sessions(self, req, resp): ...

The verifier stashes the authenticated :class:`~falcon_auth.eastwest.verifier.Principal`
on ``req.context.eastwest_principal`` — handlers that need to know *who*
called them can read it with :func:`principal_from_request`.
"""

from __future__ import annotations

import dataclasses
import warnings
from typing import Any, Awaitable, Callable

import falcon
import falcon.asgi
from structlog import get_logger

from ..assurance.operation import BodyHasher, OperationVerifier, raw_body_hash, verify_operation
from ..assurance.stepup import check_session_elevated
from ..entitlement.enforcer import CapabilityEnforcer
from ..entitlement.grants import select as select_grants
from ..entitlement.resolver import Resolver
from ..errors import ActorTypeNotAdmitted, CapabilityDenied, Unauthenticated
from ..eastwest.errors import MissingCapabilityError
from ..eastwest.verifier import Principal, Verifier
from ..planes import SERVICE
from .middleware import ACTOR_TYPES_ATTR
from .rawbody import raw_body
from .routing import UnregisteredRoute
from ..trustcontext import TrustContextClient


_PRINCIPAL_CTX_ATTR = "eastwest_principal"

#: C-053 §3: the header that names the subject a request acts on (RUL-124). A selector, never
#: authority -- see `require`.
SUBJECT_REF_HEADER = "Subject-Ref"

logger = get_logger("falcon_auth.adapters.hooks")

#: Where the resolved USER-plane principal is parked, for the rest of the request. A
#: separate slot from the east-west one above on purpose: the two models share no field,
#: so a single slot would leave a handler unable to tell which kind it had been given.
PRINCIPAL_ATTR = "principal"


HookFn = Callable[
    [falcon.asgi.Request, falcon.asgi.Response, object, dict[str, Any]],
    Awaitable[None],
]



def _bind(collaborator: Any, method: str, *, param: str, factory: str) -> Any:
    """Check a hook's collaborator is usable NOW, because the hook binds it now.

    ``@falcon.before(require_service_capability(verifier, "x:read"))`` calls the factory while the
    class body executes -- at module import. Whatever ``verifier`` is at that moment is what the
    closure keeps forever. A DI container that has not populated yet, a ``configure()`` that
    runs after routes import, a test that patches the module attribute afterwards: each leaves
    the hook holding the placeholder, and nothing says so.

    The failure without this check is the shape the package closes everywhere else -- a 500 on a
    gated route, at request time, from an ``AttributeError`` on ``None``. Here it is a clear
    error at import, naming the argument and what it needs to be.

    Duck-typed rather than isinstance: a consumer may legitimately pass a wrapper, a test double
    or a lazy proxy. What matters is that the method the hook will call exists NOW.
    """
    if collaborator is None or not callable(getattr(collaborator, method, None)):
        raise TypeError(
            f"{factory}({param}=...) needs an object with a callable .{method}(); got "
            f"{collaborator!r}. Hooks bind at DECORATION time -- when the route module is "
            f"imported -- so this must already be constructed. If a container builds it, build "
            f"it before the route modules import rather than passing a placeholder"
        )
    return collaborator


def require_service_capability(
    verifier: Verifier,
    capability: str,
    *,
    enforcer: CapabilityEnforcer | None = None,
) -> HookFn:
    """Return a Falcon ``before`` hook that gates a SERVICE route on ``capability``.

    Fail-closed: no client cert →
    :class:`~falcon_auth.eastwest.errors.MissingClientCertError` (401), unknown CN
    → :class:`~falcon_auth.eastwest.errors.UnknownCNError` (403), capability not held →
    :class:`~falcon_auth.eastwest.errors.MissingCapabilityError` (403).

    **Two modes, chosen by** ``enforcer``:

        None       allow-list mode (C-018). The peer's capabilities are the allow-list row's.
                   The demand is checked against nothing: ``"kyc:raed"`` mounts cleanly and no
                   peer can ever open the route (falcon-auth#8).
        given      policy mode (C-056, proposed). The peer's logical name -- the allow-list's
                   ``source`` -- is the subject, and the enforcer walks its ``g`` rows. The
                   demand is checked **at decoration time**, exactly as :func:`require` does on
                   the user plane: a capability with no registry row raises here, at import,
                   with a human watching.

    A CALLBACK principal on a SERVICE route is refused in both modes. It carries no capabilities
    by contract, and in policy mode its ``source`` is not a declared peer either -- the refusal
    is stated here rather than left to that coincidence.
    """

    _bind(verifier, "authenticate", param="verifier", factory="require_service_capability")
    if enforcer is not None:
        _bind(enforcer, "allows_peer", param="enforcer", factory="require_service_capability")
        if not enforcer.knows(capability):
            raise ValueError(
                f"capability {capability!r} is not in the capability registry -- add a row for "
                f"it (a new route means a new row; absence must never mean ungated)"
            )

    async def hook(
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        resource: object,
        params: dict[str, Any],
        *_a: Any,
        **_kw: Any,
    ) -> None:
        principal = verifier.authenticate(req.scope)
        if enforcer is None:
            verifier.require_capability(principal, capability)
        elif principal.kind != SERVICE or not enforcer.allows_peer(principal.source, capability):
            raise MissingCapabilityError(capability, code=verifier.codes.missing_capability)
        setattr(req.context, _PRINCIPAL_CTX_ATTR, principal)

    return hook


def require_service_scope(verifier: Verifier, scope: str) -> HookFn:
    """Deprecated: the pre-C-055 name of :func:`require_service_capability` in allow-list mode.

    Warns once, where the route is decorated -- at import, in the deploy log -- not per request.
    """
    warnings.warn(
        "require_service_scope is deprecated; use require_service_capability",
        DeprecationWarning,
        stacklevel=2,
    )
    return require_service_capability(verifier, scope)


def require_callback(verifier: Verifier) -> HookFn:
    """Return a Falcon ``before`` hook that gates a CALLBACK route.

    CALLBACK principals carry no scopes — the mere fact that the caller
    presented a known cert-bound identity is the whole authorization. Body is
    treated as data, not a command.
    """

    _bind(verifier, "authenticate", param="verifier", factory="require_callback")

    async def hook(
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        resource: object,
        params: dict[str, Any],
        *_a: Any,
        **_kw: Any,
    ) -> None:
        principal = verifier.authenticate(req.scope)
        setattr(req.context, _PRINCIPAL_CTX_ATTR, principal)

    return hook


def principal_from_request(req: falcon.asgi.Request) -> Principal | None:
    """Return the verified east-west principal on ``req``, or ``None``."""
    return getattr(req.context, _PRINCIPAL_CTX_ATTR, None)


#: How a service finds the two references on a request. The package cannot know this: the
#: session claim lands wherever that service's authenticator put it, which is a consumer
#: convention, not a fact about auth.
RefExtractor = Callable[[falcon.asgi.Request], tuple[str, str]]


def require_elevated(client: TrustContextClient, refs: RefExtractor) -> HookFn:
    """Return a Falcon ``before`` hook that gates a route on an ELEVATED session.

    The hook's **presence is the requirement** -- there is no tier argument, because there
    are two tiers and "authenticated is enough" is expressed by not applying it.

    Apply it **after** the entitlement gate. C-033 makes that ordering load-bearing: a
    principal who holds no entitlement at all should get a clean refusal, not be sent away to
    complete a challenge that was never going to help them::

        @falcon.before(require("orders:read"), is_async=True)
        @falcon.before(require_elevated_for_this_service, is_async=True)
        async def on_get_object(self, req, resp, order_id): ...

    Raises `StepUpRequired` (the client raises a challenge and retries), `SessionMiss` (the
    session is gone -- re-authenticate instead), or `AuthzUnavailable` (the lookup failed --
    a challenge cannot fix that).
    """

    _bind(client, "fetch", param="client", factory="require_elevated")
    if not callable(refs):
        raise TypeError(
            f"require_elevated(refs=...) needs a callable (req) -> (session_ref, user_ref); "
            f"got {refs!r}"
        )

    async def hook(
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        resource: object,
        params: dict[str, Any],
        *_a: Any,
        **_kw: Any,
    ) -> None:
        # `*_a, **_kw` absorb what `falcon.before(action, *args, **kwargs)` forwards --
        # notably the `is_async=True` callers across this ecosystem still pass, believing
        # Falcon consumes it. Falcon 3 did; Falcon 4 detects hooks automatically and the
        # parameter is gone, so a strict signature raises TypeError: a 500 on a gated route.
        # Nothing is read from them on purpose -- a gate that varied with decorator kwargs
        # would be a second, invisible configuration surface.
        session_ref, user_ref = refs(req)
        await check_session_elevated(client, session_ref, user_ref)

    return hook



#: Where the client's operation id arrives. Spelled as the estate spells it. `get_header` is
#: case-insensitive, so the casing is a readability choice, not a functional one.
DEFAULT_OPERATION_HEADER = "X-Operation-ID"


async def verify_operation_for(
    req: falcon.asgi.Request,
    verifier: OperationVerifier,
    refs: RefExtractor,
    *,
    expected_purpose: str,
    bind_body: bool = False,
    body_hash: BodyHasher | None = None,
    operation_header: str = DEFAULT_OPERATION_HEADER,
) -> Any:
    """Consume this request's step-up challenge. **Call it from inside the handler.**

    THERE IS DELIBERATELY NO `before` HOOK FOR THIS, and the reason is the whole design.

    ``X-Operation-ID`` is also the idempotency key, so a route using per-operation step-up has
    idempotency by construction -- and in this estate the idempotency reservation is taken
    INLINE in the responder, after every hook has already run. A hook would therefore consume
    the challenge on every replay, before ``reserve`` was ever called, and the replay path
    (answer the stored response) would answer "challenge already consumed" instead. That is the
    exact retry the operation id exists to make safe.

    So the ordering cannot be expressed with decorators; it belongs to the handler, which is the
    only thing that knows whether this is a genuine first execution::

        reservation, stored = await idempotency.reserve(key=key, fingerprint=fingerprint)
        if reservation is Reservation.MISMATCH:
            raise IdempotencyKeyReusedError()
        if reservation is Reservation.REPLAY:
            resp.media = stored                      # never verify -- already spent
            return
        if reservation is Reservation.IN_PROGRESS:
            resp.status = falcon.HTTP_202            # never verify -- still running
            return

        # RESERVED: a genuine first execution, and the only branch that may spend a challenge.
        await verify_operation_for(
            req, verifier, refs, expected_purpose="order_create", bind_body=True
        )
        ...perform the write...

    :param expected_purpose: the purpose this route accepts, passed straight through. Required,
        with no default -- see :func:`~falcon_auth.assurance.operation.verify_operation`.
    :param bind_body: hash the request body as C-058 (`v28`) defines it -- base64url, unpadded,
        SHA-256 over the exact bytes received, before any decode -- and compare it with the hash
        the challenge was bound to. Needs the app wrapped in
        :class:`~falcon_auth.adapters.rawbody.RawBodyBuffer`, which keeps those bytes; without
        it this raises ``RuntimeError`` rather than compare against anything else.
    :param body_hash: ⚠ deprecated -- a host hasher over the PARSED media. C-058 superseded the
        canonicalized binding, and no hash of a parsed body can equal one over the client's
        bytes. Warns; passing it with ``bind_body`` is refused.

    Raises `Unauthenticated` (no operation id), `OperationChallengeMiss` (run step-up again
    under a new id), `OperationPurposeMismatch` (a challenge for a different act),
    `OperationBodyMismatch` (not the body that was authorized) or `AuthzUnavailable`.
    """
    operation_id = req.get_header(operation_header)
    if not operation_id:
        raise Unauthenticated(
            f"this operation requires step-up; no {operation_header} on the request"
        )

    session_ref, user_ref = refs(req)

    if bind_body and body_hash is not None:
        raise TypeError("pass bind_body=True or the deprecated body_hash=, not both")

    computed: str | None = None
    if bind_body:
        # The bytes RawBodyBuffer kept below Falcon -- never req.stream, which would leave a
        # handler's later get_media() with b''.
        body = raw_body(req.scope)
        if body is None:
            raise RuntimeError(
                "bind_body=True needs the request's raw bytes, and none were kept: wrap the ASGI "
                "app in falcon_auth.adapters.rawbody.RawBodyBuffer (C-058 hashes the exact bytes "
                "received, which a parsed body cannot reproduce)"
            )
        computed = raw_body_hash(body)
    elif body_hash is not None:
        warnings.warn(
            "verify_operation_for(body_hash=...) hashes the parsed body, which C-058 superseded; "
            "wrap the app in RawBodyBuffer and pass bind_body=True",
            DeprecationWarning,
            stacklevel=2,
        )
        computed = body_hash(await req.get_media())

    return await verify_operation(
        verifier,
        session_ref,
        operation_id,
        user_ref=user_ref,
        expected_purpose=expected_purpose,
        body_hash=computed,
    )


__all__ = (
    "DEFAULT_OPERATION_HEADER",
    "SUBJECT_REF_HEADER",
    "HookFn",
    "PRINCIPAL_ATTR",
    "RefExtractor",
    "principal_from_request",
    "require",
    "require_callback",
    "require_elevated",
    "require_service_capability",
    "require_service_scope",
    "verify_operation_for",
)


def require(
    enforcer: CapabilityEnforcer,
    resolver: Resolver,
    capability: str,
    *,
    consequential: bool = False,
    user_attr: str = "user",
) -> HookFn:
    """Gate a user-plane route on `capability` -- with C-052's actor type and C-053's grant kinds.

    Raises **at decoration time** -- at import, with a human watching -- if the capability has no
    row in the registry (absence must never mean ungated), or if the enforcer was built without the
    grant register (``build_enforcer(..., grants=...)``): without each grant's actor type and kind,
    neither C-052 §7 nor C-053's kind rule can be applied.

    Per request, after the trust context resolves:

    1. **actor type** -- the caller's (from the feed, never inferred) must be one the route admits
       (the plane middleware stamps them). Not admitted ⇒ Falcon's ``HTTPRouteNotFound``, so the
       host's router miss renders it, ``404 PLAT0006``, byte-identical (C-052 §6, RUL-158). An
       operator on a customer route is admitted only as a SHADOW session (C-053 §9).
    2. **which grants count** (:func:`falcon_auth.entitlement.grants.select`): ``self`` grants with
       no ``Subject-Ref``; live ``subject`` delegations for the named subject with one; ``unbound``
       grants on an OPERATOR-only route, where a ``Subject-Ref`` is refused. Kinds never mix. Every
       subject refusal is one ``404 PLAT0008`` (H2, H4, RUL-177).
    3. **the capability** -- first match per grant (RUL-076); none ⇒ ``CapabilityDenied``.

    The principal left on ``req.context.principal`` carries ``subject_ref`` (the service's
    ownership check and idempotency key, H3, H6), and ``opened_by`` / ``opened_by_delegation`` for
    the audit line (H7). A request carrying ``Subject-Ref`` answers ``Vary: Subject-Ref`` (H5).

    `consequential` marks an operation for which the entitlement is the control. Every trust read
    is fresh regardless; what this selects is the behaviour when the source is DOWN -- fail closed
    rather than serve the last-good copy. Nothing sets it until a service classifies its own
    operations.
    """
    _bind(enforcer, "knows", param="enforcer", factory="require")
    _bind(resolver, "resolve", param="resolver", factory="require")
    if not enforcer.knows(capability):
        raise ValueError(
            f"capability {capability!r} is not in the capability registry -- add a row for it "
            f"(a new route means a new row; absence must never mean ungated)"
        )
    register = getattr(enforcer, "grants", None)
    if register is None:
        raise ValueError(
            "require() needs the grant register: build_enforcer(..., grants={name: (actor_type, "
            "kind)}) from registry/GRANTS.md. Without each grant's actor type and kind, C-052 §7 "
            "and C-053's kind rule cannot be applied, and a delegated grant would count as the "
            "caller's own"
        )

    async def hook(
        req: Any, resp: Any, resource: Any, params: dict[str, Any], *_a: Any, **_kw: Any
    ) -> None:
        # `*_a, **_kw` are deliberate. `falcon.before(action, *args, **kwargs)` forwards EVERY extra
        # argument straight to the action — including `is_async=True`, which callers across this
        # ecosystem pass believing Falcon consumes it. It did in Falcon 3; in Falcon 4 hooks are
        # detected automatically and the parameter is gone, so it now arrives here as a stray kwarg
        # and a strict signature raises `TypeError` — a 500 on a route that should have returned
        # 401/403. Nothing is read from them on purpose.
        user = getattr(req.context, user_attr, None)
        if user is None:
            # The authn hook did not run, or ran and set nothing. Never treat this as "anonymous is
            # fine" -- an unauthenticated request reaching a gated route is a mounting error.
            raise Unauthenticated("no authenticated principal on the request")

        admitted = getattr(req.context, ACTOR_TYPES_ATTR, None)
        if not admitted:
            raise UnregisteredRoute(
                "the actor-type guard (C-052) needs the route's declared actor types, which the "
                "plane middleware stamps -- mount through PlaneRegistry and run "
                "PlaneAuthenticationMiddleware"
            )

        principal = await resolver.resolve(user, consequential=consequential)
        subject_header = req.get_header(SUBJECT_REF_HEADER)
        if subject_header is not None:
            resp.append_header("Vary", SUBJECT_REF_HEADER)          # H5
        try:
            selection = select_grants(
                principal, admitted=admitted, subject_header=subject_header, grants=register,
            )
        except ActorTypeNotAdmitted as e:
            logger.warning(
                "actor_type_mismatch", reason=str(e), actor_type=principal.actor_type,
                session_kind=principal.session_kind, admitted=sorted(admitted),
                uri_template=getattr(req, "uri_template", None),
            )
            raise falcon.HTTPRouteNotFound() from e

        opened = enforcer.opened_by(selection.grants, capability)
        principal = dataclasses.replace(
            principal,
            subject_ref=selection.subject_ref,
            opened_by=opened,
            opened_by_delegation=selection.delegation_for.get(opened) if opened else None,
        )
        setattr(req.context, PRINCIPAL_ATTR, principal)
        if opened is None:
            raise CapabilityDenied(
                f"missing entitlement for {capability}", capability=capability,
            )

    return hook

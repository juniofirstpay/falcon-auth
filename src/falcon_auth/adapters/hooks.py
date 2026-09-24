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
    from falcon_auth.adapters.hooks import require_service_scope
    from app.services import verifier   # constructed at boot, BEFORE routes import

    class InternalRevocationsRoute:
        @falcon.before(require_service_scope(verifier, "revocations.sessions:read"))
        async def on_get_sessions(self, req, resp): ...

The verifier stashes the authenticated :class:`~falcon_auth.eastwest.verifier.Principal`
on ``req.context.eastwest_principal`` — handlers that need to know *who*
called them can read it with :func:`principal_from_request`.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import falcon
import falcon.asgi

from ..assurance.operation import BodyHasher, OperationVerifier, verify_operation
from ..assurance.stepup import check_session_elevated
from ..entitlement.enforcer import CapabilityEnforcer
from ..entitlement.resolver import Resolver
from ..errors import CapabilityDenied, Unauthenticated
from ..eastwest.verifier import Principal, Verifier
from ..trustcontext import TrustContextClient


_PRINCIPAL_CTX_ATTR = "eastwest_principal"

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

    ``@falcon.before(require_service_scope(verifier, "x:read"))`` calls the factory while the
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


def require_service_scope(verifier: Verifier, scope: str) -> HookFn:
    """Return a Falcon ``before`` hook that gates a SERVICE route on ``scope``.

    Fail-closed: no client cert →
    :class:`~falcon_auth.eastwest.errors.MissingClientCertError` (401), unknown CN
    → :class:`~falcon_auth.eastwest.errors.UnknownCNError` (403), missing scope →
    :class:`~falcon_auth.eastwest.errors.MissingScopeError` (403).
    """

    _bind(verifier, "authenticate", param="verifier", factory="require_service_scope")

    async def hook(
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        resource: object,
        params: dict[str, Any],
        *_a: Any,
        **_kw: Any,
    ) -> None:
        principal = verifier.authenticate(req.scope)
        verifier.require_scope(principal, scope)
        setattr(req.context, _PRINCIPAL_CTX_ATTR, principal)

    return hook


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
            req, verifier, refs, expected_purpose="order_create", body_hash=quote_digest
        )
        ...perform the write...

    Reuse the fingerprint the idempotency reservation already computes rather than writing a
    second canonicalizer: two definitions of "canonical" over one body will drift, and the day
    they do, a body-bound challenge silently stops matching.

    :param expected_purpose: the purpose this route accepts, passed straight through. Required,
        with no default -- see :func:`~falcon_auth.assurance.operation.verify_operation`.
    :param body_hash: this service's canonicalizer, taking the parsed media and returning the
        hash to compare with the one the challenge was bound to.

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

    computed: str | None = None
    if body_hash is not None:
        # get_media(), NEVER stream.read(). Falcon caches the DESERIALIZED media, so a handler
        # that already called get_media() shares this object and one that calls it afterwards
        # still gets a body. Reading the stream would leave whichever runs second with b''.
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
    "HookFn",
    "PRINCIPAL_ATTR",
    "RefExtractor",
    "principal_from_request",
    "require",
    "require_callback",
    "require_elevated",
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
    """Gate a user-plane route on `capability`.

    Raises `ValueError` **at decoration time** -- so at import, with a human watching -- if the
    capability has no row in the §9.1 registry. A route asking for a capability nobody registered is
    a wiring bug, and §9.1 is explicit that absence must never quietly mean ungated.

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

    async def hook(
        req: Any, resp: Any, resource: Any, params: dict[str, Any], *_a: Any, **_kw: Any
    ) -> None:
        # `*_a, **_kw` are deliberate. `falcon.before(action, *args, **kwargs)` forwards EVERY extra
        # argument straight to the action — including `is_async=True`, which callers across this
        # ecosystem pass believing Falcon consumes it. It did in Falcon 3; in Falcon 4 hooks are
        # detected automatically and the parameter is gone, so it now arrives here as a stray kwarg
        # and a strict signature raises `TypeError: hook() got an unexpected keyword argument
        # 'is_async'` — a 500 on a route that should have returned 401/403.
        #
        # Absorbing them keeps a hook from failing over how it was decorated rather than what it
        # decides, which is the same thing `falcon_utils`' authentication hook does. Nothing is read
        # from them on purpose: a gate that changed behaviour based on decorator kwargs would be a
        # second, invisible configuration surface.
        user = getattr(req.context, user_attr, None)
        if user is None:
            # The authn hook did not run, or ran and set nothing. Never treat this as "anonymous is
            # fine" -- an unauthenticated request reaching a gated route is a mounting error.
            raise Unauthenticated("no authenticated principal on the request")

        principal = await resolver.resolve(user, consequential=consequential)
        setattr(req.context, PRINCIPAL_ATTR, principal)

        if not enforcer.allows_principal(principal, capability):
            raise CapabilityDenied(
                f"missing entitlement for {capability}", capability=capability,
            )

    return hook

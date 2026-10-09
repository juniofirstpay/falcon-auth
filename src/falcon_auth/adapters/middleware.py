"""The per-request half of the plane system: which credential may open this endpoint.

:mod:`falcon_auth.adapters.routing` decides at startup which plane an endpoint is on. This
decides, per request, whether the caller presented the credential the endpoint accepts -- the
second of RUL-046's two guards, and the half C-006 records as "the comparison is missing
everywhere". Built from C-038's resolution table, as C-060 (`v30`) refines it:

    1  the endpoint's ONE declared credential is the primary
    2  primary credential present but INVALID          -> 401
    3  primary credential ABSENT                       -> look for a credential of ANOTHER
                                                          plane -- only one verifiable WITHOUT
                                                          I/O: a JWT, or the TLS peer (C-060 §6)
    4  a VALID credential for a DIFFERENT plane        -> 404 PLAT0006, byte-identical to a
                                                          router miss, logged and flagged
    5  no credential of any kind                       -> 401

WHY 404 AND NOT 403 AT STEP 4. C-038 supersedes C-006's `403 PLAT0107` here. A 403 confirms the
endpoint exists, which hands an attacker holding a user token a map of the service plane: probe
a path, read the status, learn whether an internal route sits behind it. A 404 tells them
nothing they did not already know -- and it must be the ROUTE not-found, `PLAT0006`, the body a
path that does not exist at all would get (RUL-158). `PLAT0008` is record-level only (C-015):
answering a wrong-plane credential with it would let a caller tell an existing route from a
missing one, the very oracle step 4 exists to close. By default this raises Falcon's own
:class:`falcon.HTTPRouteNotFound`, so whatever the host renders for a router miss is what a
wrong-plane caller sees -- identical by construction, not by care.

WHY AN INVALID FOREIGN CREDENTIAL IS NOT A STEP-4 MISMATCH. Step 4 says a *valid* credential for
another plane. Garbage in an ``Authorization`` header on a service-plane route is not evidence
that a user-plane caller wandered in; it is evidence of a caller with no usable credential at
all, which is step 5 and a 401. Treating it as a mismatch would answer 404 to callers who are
merely broken, and would let anyone map the estate by sending nonsense.

WHY ONLY I/O-FREE CREDENTIALS IN THE SEARCH (C-060 §6). Checking a reference token, a one-shot
token or a client-key proof needs a lookup. Searching them would let any probe carrying junk
turn the 404 rule into database load; they count as absent there, giving step 5's 401. The
**forwarding hop's** certificate is transport, never a caller credential: see
``MTLSAuthenticator(transport_peers=...)``.

WHICH CREDENTIAL A ROUTE ACCEPTS. **Exactly one** (C-060 §3; C-031's reason at route grain: a
request that may prove itself two ways is a request an attacker may prove one way). A route pins
it with ``mount(..., credential=)``, or, pinning none, takes the ONE authenticator on its plane;
a plane carrying two (CALLBACK's HMAC and one-shot token) needs every route to pin. Authenticators
come in one of two shapes:

    {Method: callable}         the original shape: one per method, placed on the plane C-060 puts
                               that method on for a resource service. Unchanged.
    {name: PlaneAuthenticator} named, configured credentials, each on its one plane.

A credential of the SAME plane that this route does not accept is not foreign -- its holder
gets step 5's 401, and learns nothing about the plane.

THE FOUR THINGS IT STAMPS. ``req.context.plane``, ``req.context.auth_method``,
``req.context.auth_principal`` and ``req.context.auth_credential`` (the name of the authenticator
that opened the route -- the method itself, in the original shape). It deliberately does NOT
write ``principal`` or ``eastwest_principal``: those are the existing hooks' slots, holding two
models that share no field, and a middleware that cannot tell which it is holding must not pick
one of them.
"""
from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, get_args

import falcon
from structlog import get_logger

from ..errors import Unauthenticated
from ..planes import (
    METHODS_BY_PLANE,
    PLANE_BY_METHOD,
    PUBLIC,
    RESOURCE_SERVICE_PLANES,
    USER,
    SEARCHABLE_METHODS,
    Method,
    Plane,
    methods_for,
)
from .routing import (
    DEFAULT_PROBE_PATHS,
    PlaneConflict,
    PlaneRegistry,
    Registration,
    UnregisteredRoute,
)

__all__ = (
    "ACTOR_TYPES_ATTR",
    "AUTH_CREDENTIAL_ATTR",
    "AUTH_METHOD_ATTR",
    "AUTH_PRINCIPAL_ATTR",
    "Authenticator",
    "ConventionDeviation",
    "PLANE_ATTR",
    "PlaneAuthenticationMiddleware",
)

logger = get_logger(__name__)

#: Where the endpoint's plane is stamped, for the rest of the request.
PLANE_ATTR = "plane"
#: Which method actually authenticated the caller. ``None`` on the PUBLIC plane.
AUTH_METHOD_ATTR = "auth_method"
#: Whatever the method's authenticator returned, un-interpreted. See the module docstring on why
#: this is a separate slot from the hooks' own principal attributes.
AUTH_PRINCIPAL_ATTR = "auth_principal"
#: The name of the authenticator that opened the route. ``None`` on the PUBLIC plane. A handler
#: that must spend a single-use credential reads this to know which one it holds.
AUTH_CREDENTIAL_ATTR = "auth_credential"
#: The actor types the route admits (C-052 §5), for the user-plane gate (`require`), which knows
#: the caller's actor type only once the trust context resolves. ``None`` off the USER plane.
ACTOR_TYPES_ATTR = "actor_types"

_METHOD_NAMES: frozenset[str] = frozenset(get_args(Method))


class ConventionDeviation(PlaneConflict):
    """An authenticator is wired in a way C-060 does not allow -- refused at construction.

    A method on a plane C-060 does not put it on, or on a plane a resource service may not mount.
    A subclass of :class:`PlaneConflict`, so a host already failing its startup on that keeps
    doing so.
    """


class Authenticator(Protocol):
    """Attempts ONE authentication method against a request.

    The contract is TRI-STATE, and C-038's table needs all three to be distinguishable:

        returns a principal   a credential of this kind is present and valid
        returns ``None``      no credential of this kind is present -- say nothing about others
        raises                a credential of this kind is present and INVALID

    Collapsing "absent" and "invalid" into ``None`` would make step 2 unreachable: a forged
    token would fall through to the step-3 search and be answered 404 instead of 401, which
    tells an attacker that a bad token and no token are different things and that the endpoint
    is on some other plane. Collapsing them the other way -- raising on absent -- would make
    step 3 unreachable.
    """

    async def __call__(self, req: Any) -> Any | None: ...


@dataclass(frozen=True)
class _Entry:
    """One authenticator as the middleware sees it, whichever shape it was supplied in."""

    name: str
    method: Method | None
    plane: Plane
    attempt: Authenticator
    selector: Any | None  # a Selector; typed loosely to keep this module free of the adapters'


class PlaneAuthenticationMiddleware:
    """Falcon middleware enforcing which credential may open each endpoint.

    Mount it with the app and give it the same registry the routes were mounted through::

        registry = PlaneRegistry()
        middleware = PlaneAuthenticationMiddleware(
            registry,
            authenticators={
                planes.JWT: jwt_authenticator(verifier, User, scheme="DPoP",
                                              binding=PROVEN_AT_PERIMETER),
                planes.MTLS: mtls_authenticator(allow_list_verifier),
            },
        )
        app = falcon.asgi.App(middleware=[middleware])
        mount(registry, app, "/v1/orders", OrdersResource(), plane=planes.USER)
        verify_app(app, registry)
        middleware.verify()
    """

    def __init__(
        self,
        registry: PlaneRegistry,
        *,
        authenticators: Mapping[Any, Authenticator],
        not_found_error: Callable[[], BaseException] = falcon.HTTPRouteNotFound,
        on_plane_mismatch: Callable[[str, Plane, Method], None] | None = None,
        exempt_paths: Collection[str] = DEFAULT_PROBE_PATHS,
    ) -> None:
        """
        :param registry: the registry the routes were mounted through. Shared, not rebuilt: a
            second registry would be empty, and an empty registry refuses every request.

        :param authenticators: ``{Method: callable}`` -- one per method, on the plane C-060 puts
            it for a resource service -- or ``{name: PlaneAuthenticator}``, each on its one plane.
            Keys that are all method names select the first reading; a mix is refused. A method
            with no entry is one this service cannot verify, so a credential of that kind is
            invisible here.

        :param not_found_error: builds the exception raised on a step-4 plane mismatch. The body
            must be the ROUTE not-found -- `PLAT0006`, byte-identical to a router miss (RUL-158).
            The default, :class:`falcon.HTTPRouteNotFound`, is the exception Falcon itself raises
            on a router miss, so the host's own handler renders both and they cannot differ.
            Override only with something that renders exactly as that does.

        :param on_plane_mismatch: called as ``(uri_template, endpoint_plane, credential_method)``
            when step 4 fires. C-038 requires the mismatch be "logged and flagged"; the log
            happens here regardless, and this is the flag -- a metric, an alert, a security
            event. It is deliberately not a raise: the 404 is the answer to the caller, and the
            flag is the answer to the operator.

        :param exempt_paths: route templates the middleware stands aside for when they were
            NEVER REGISTERED -- health and readiness probes, which sit outside the plane system
            (RUL-033, RUL-135). The same default as
            :func:`~falcon_auth.adapters.routing.verify_app`; pass the same value to both. A
            registered route is never exempt: naming a USER route here cannot make it public.

        :raises ConventionDeviation: an authenticator on a plane this package's hosts may not
            mount (CLIENT, C-060 §2), or carrying a method C-060 does not put on its plane.
        :raises PlaneConflict: authenticators on different planes reading the same carrier.
        """
        self._registry = registry
        self._entries, self._legacy = _normalise(authenticators)
        self._not_found_error = not_found_error
        self._on_plane_mismatch = on_plane_mismatch
        self._exempt_paths = frozenset(exempt_paths)
        _refuse_off_convention(self._entries.values())
        _refuse_cross_plane_overlap(self._entries.values())

    # -- boot ---------------------------------------------------------------------------

    def verify(self) -> None:
        """Refuse to start if any mounted route has no single credential that can open it.

        Call it once, after every route is mounted, beside
        :func:`falcon_auth.adapters.routing.verify_app`. :meth:`_accepted` makes the same check
        on the FIRST REQUEST to a route, which is too late once this middleware is the only
        thing authenticating: a mis-wired plane looks healthy through deploy and smoke tests,
        and is found by a caller. C-061 §1: a broken property refuses start.

        Refused, naming every route at fault:

            a plane with mounted routes and no authenticator for it
            a pin naming an authenticator that does not exist, or one on another plane
            an unpinned route on a plane carrying two authenticators -- it would accept
            "any of" two credentials (C-060 §3); pin one

        Refused earlier, at construction and at mount: an authenticator off C-060's table, two
        planes' authenticators on one carrier, a CLIENT route, a PUBLIC route naming a
        credential, ``credential=`` given a list.

        PUBLIC is skipped: no method authenticates there, which is a declaration rather than a
        gap (see :data:`falcon_auth.planes.METHODS_BY_PLANE`).

        :raises UnregisteredRoute: naming every plane at fault, what it needs, and up to three
            example routes, so a service with two mis-wired planes fixes both in one pass.
        """
        gaps: dict[Plane, tuple[list[str], list[str]]] = {}
        wrong: list[str] = []
        undeclared: list[str] = []
        for registration in self._registry.routes().values():
            if registration.plane == PUBLIC:
                continue
            if registration.plane == USER and not registration.actor_types:
                undeclared.append(str(registration.endpoint))
            try:
                self._accepted(registration)
            except _Gap as gap:
                endpoint = str(registration.endpoint)
                if gap.kind == "missing":
                    _, examples = gaps.setdefault(registration.plane, (gap.missing, []))
                    if len(examples) < 3:
                        examples.append(endpoint)
                else:
                    wrong.append(f"{endpoint}: {gap}")

        if gaps:
            detail = "; ".join(
                f"{plane} needs {missing} (e.g. {', '.join(examples)})"
                for plane, (missing, examples) in sorted(gaps.items())
            )
            raise UnregisteredRoute(
                f"these planes have mounted routes but no authenticator was supplied for their "
                f"method, so nothing could open them: {detail}"
            )
        if wrong:
            raise UnregisteredRoute(
                "these routes do not resolve to exactly one credential: " + "; ".join(wrong)
            )
        if undeclared:
            raise UnregisteredRoute(
                "these USER routes declare no actor types -- mount(..., actor_types={...}); a "
                "route admits at least one, never 'any' (C-052 §5): " + "; ".join(undeclared)
            )

    # -- per request ----------------------------------------------------------------------

    async def process_resource(
        self, req: Any, resp: Any, resource: object, params: dict[str, Any]
    ) -> None:
        """Falcon's post-routing hook -- the earliest point with both the route and the resource.

        ``process_request`` would be too early: it runs before routing, so there is no
        ``uri_template`` to look the plane up by. Falcon skips this hook entirely when no route
        matches, so an unrouted path never reaches here and needs no branch.
        """
        template = req.uri_template
        method = req.method.upper()

        registration = self._registry.registration_of(method, template)
        if registration is None:
            # Falcon DOES run this hook for a wrong-verb request -- a DELETE against a GET-only
            # resource -- and the registry has no row for that pair. If the template has other
            # rows, the route is known and this method simply is not served: Falcon's own 405 is
            # the right answer and this hook stands aside (RUL-158: 405 stays).
            if self._registry.registered_methods(template):
                return
            # A probe, deliberately left out of the plane system (RUL-033). Only ever for a route
            # with no registration at all -- see `exempt_paths`.
            if template in self._exempt_paths:
                return
            # Otherwise the route never reached the registry, so nothing is known about who may
            # call it. Refusing is the fail-closed direction; `verify_app` is what should have
            # caught this at boot, and this is the net under it.
            raise UnregisteredRoute(
                f"{method} {template} is mounted but was never registered, so no "
                f"authentication method can be required of its callers -- mount it through "
                f"falcon_auth.adapters.routing.mount and call verify_app at startup"
            )

        plane = registration.plane

        if plane == USER and not registration.actor_types:
            raise UnregisteredRoute(
                f"{method} {template} is a USER route that declares no actor types, so nothing "
                f"can say who it admits (C-052 §5) -- mount(..., actor_types={{...}})"
            )
        setattr(req.context, ACTOR_TYPES_ATTR, registration.actor_types)

        if plane == PUBLIC:
            # A stated-reason PUBLIC route establishes no caller principal (C-060 §5). No
            # credential is demanded, and none is inspected: looking would invite a handler to
            # start trusting one that was never verified. Evidence the route needs is payload.
            self._stamp(req, plane, None)
            return

        try:
            entry = self._accepted(registration)
        except _Gap as gap:
            raise UnregisteredRoute(f"{template}: {gap}") from None

        # Steps 1-2. A raise here propagates as a 401 and is NOT caught: a present-but-invalid
        # credential is a final answer, not a reason to go looking for another.
        principal = await entry.attempt(req)
        if principal is not None:
            self._stamp(req, plane, entry, principal)
            return

        # Steps 3-4. The endpoint's credential is absent. Does the caller hold a valid
        # credential belonging to some other plane?
        foreign = await self._find_foreign_credential(req, plane)
        if foreign is not None:
            self._refuse_wrong_plane(req, template, plane, foreign)

        # Step 5. Nothing usable at all.
        raise Unauthenticated(f"this endpoint is on the {plane} plane and requires {entry.name}")

    # -- the pieces -----------------------------------------------------------------------

    def _accepted(self, registration: Registration) -> _Entry:
        """The ONE authenticator this endpoint accepts.

        Pinned: that one, which must exist and sit on the route's plane. Unpinned: the one
        authenticator on the plane; none is a wiring bug, and two means the route would accept
        "any of" them (C-060 §3) -- it must pin. Either fails loudly rather than answering 401
        to every caller forever, which is the shape of outage that gets diagnosed as a credential
        problem for a day and a half.
        """
        plane = registration.plane
        name = registration.credential
        if name is not None:
            entry = self._entries.get(name)
            if entry is None:
                raise _Gap(f"no authenticator named {name!r} was supplied", "pin")
            if entry.plane != plane:
                raise _Gap(f"{name!r} authenticates on {entry.plane}, not {plane}", "pin")
            return entry

        on_plane = sorted((e for e in self._entries.values() if e.plane == plane),
                          key=lambda e: e.name)
        if not on_plane:
            raise _Gap(
                f"no authenticator was supplied for the {plane} plane",
                "missing",
                missing=sorted(methods_for(plane)),
            )
        if len(on_plane) > 1:
            raise _Gap(
                f"the {plane} plane carries {[e.name for e in on_plane]}, so an unpinned route "
                f"would accept any of them; a route declares exactly one (C-060 §3) -- pass "
                f"credential=",
                "ambiguous",
            )
        return on_plane[0]

    async def _find_foreign_credential(self, req: Any, plane: Plane) -> _Entry | None:
        """A valid, I/O-free credential from an authenticator on another plane, if any.

        Only JWT and the TLS peer are tried (C-060 §6) -- anything needing a lookup counts as
        absent. A forwarding hop's certificate counts as absent too. Only authenticators this
        host supplied are considered: a credential nobody here can verify is not a credential
        anybody here can recognise as foreign.
        """
        for entry in sorted(self._entries.values(), key=lambda e: e.name):
            if entry.plane == plane or entry.method not in SEARCHABLE_METHODS:
                continue
            try:
                principal = await entry.attempt(req)
            except Exception:
                # Present but INVALID. That is a verification -- it did cryptographic work -- so
                # by C-038 Q88 it is the one secondary this step is allowed, and the search stops
                # here. It is also not a mismatch: garbage is a caller with no usable credential,
                # which is step 5's 401. See the module docstring.
                return None
            if principal is None:
                # No credential of THIS kind is present. Nothing was verified, so this does not
                # count against Q88's budget and the search continues.
                continue
            is_transport = getattr(entry.attempt, "is_transport", None)
            if is_transport is not None and is_transport(principal):
                # The forwarding hop's certificate: transport, never a caller credential.
                continue
            return entry
        return None

    def _refuse_wrong_plane(self, req: Any, template: str, plane: Plane, foreign: _Entry) -> None:
        """Step 4: log, flag, and answer as though the route did not exist."""
        logger.warning(
            "plane_mismatch",
            uri_template=template,
            method=req.method,
            endpoint_plane=plane,
            credential=foreign.name,
            credential_method=foreign.method,
            credential_plane=foreign.plane,
        )
        if self._on_plane_mismatch is not None and foreign.method is not None:
            self._on_plane_mismatch(template, plane, foreign.method)
        raise self._not_found_error()

    def _stamp(
        self, req: Any, plane: Plane, entry: _Entry | None, principal: Any | None = None
    ) -> None:
        setattr(req.context, PLANE_ATTR, plane)
        setattr(req.context, AUTH_METHOD_ATTR, entry.method if entry else None)
        setattr(req.context, AUTH_PRINCIPAL_ATTR, principal)
        setattr(req.context, AUTH_CREDENTIAL_ATTR, entry.name if entry else None)


class _Gap(Exception):
    """A route without exactly one credential. Becomes UnregisteredRoute at request or boot."""

    def __init__(self, message: str, kind: str, *, missing: list[str] | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.missing = missing or []


def _normalise(authenticators: Mapping[Any, Authenticator]) -> tuple[dict[str, _Entry], bool]:
    """Read either shape into one: ``{name: _Entry}``, and whether it was the original shape."""
    keys = list(authenticators)
    as_methods = [k for k in keys if k in _METHOD_NAMES]
    if keys and len(as_methods) == len(keys):
        entries = {}
        for method, attempt in authenticators.items():
            if method not in PLANE_BY_METHOD:
                raise ConventionDeviation(
                    f"{method!r} authenticates on no plane a resource service mounts (C-060 §2-§3)"
                )
            entries[method] = _Entry(
                name=method,
                method=method,
                plane=PLANE_BY_METHOD[method],
                attempt=attempt,
                selector=getattr(attempt, "selector", None),
            )
        return entries, True
    if as_methods:
        raise TypeError(
            f"authenticators mixes method keys {sorted(as_methods)} with names "
            f"{sorted(set(keys) - set(as_methods))}; use one shape"
        )
    entries = {}
    for name, attempt in authenticators.items():
        planes = getattr(attempt, "planes", None)
        if not planes:
            raise TypeError(
                f"authenticator {name!r} declares no plane. Named authenticators must be "
                f"PlaneAuthenticator instances (JWTAuthenticator, ReferenceAuthenticator, "
                f"MTLSAuthenticator, CustomAuthenticator) so the middleware knows where it belongs"
            )
        if len(planes) != 1:
            raise ConventionDeviation(
                f"authenticator {name!r} is on {sorted(planes)}; a credential authenticates on "
                f"one plane (C-060 §3)"
            )
        entries[name] = _Entry(
            name=name,
            method=getattr(attempt, "method", None),
            plane=next(iter(planes)),
            attempt=attempt,
            selector=getattr(attempt, "selector", None),
        )
    return entries, False


def _refuse_off_convention(entries: Iterable[_Entry]) -> None:
    found = []
    for e in sorted(entries, key=lambda e: e.name):
        if e.plane not in RESOURCE_SERVICE_PLANES:
            found.append(f"{e.name} is on {e.plane}, which only the identity provider mounts")
        elif e.method is not None and e.method not in METHODS_BY_PLANE[e.plane]:
            found.append(
                f"{e.name} ({e.method}) is on {e.plane}, which C-060 gives "
                f"{sorted(METHODS_BY_PLANE[e.plane])}"
            )
    if found:
        raise ConventionDeviation("these authenticators depart from C-060: " + "; ".join(found))


def _refuse_cross_plane_overlap(entries: Iterable[_Entry]) -> None:
    found = []
    listed = sorted(entries, key=lambda e: e.name)
    for i, a in enumerate(listed):
        for b in listed[i + 1:]:
            if a.plane != b.plane and a.selector is not None and b.selector is not None \
                    and a.selector.overlaps(b.selector):
                found.append(f"{a.name} ({a.plane}) and {b.name} ({b.plane}) both read {a.selector}")
    if found:
        raise PlaneConflict(
            "authenticators on different planes read the same carrier, so the wrong-plane "
            "search could not tell their credentials apart: " + "; ".join(found)
        )

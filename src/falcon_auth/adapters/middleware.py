"""The per-request half of the plane system: which credential may open this endpoint.

:mod:`falcon_auth.adapters.routing` decides at startup which plane an endpoint is on. This
decides, per request, whether the caller presented the credential that plane accepts -- the
second of RUL-046's two guards, and the half C-006 records as "the comparison is missing
everywhere". There was nothing in the estate to port; this is built from C-038's resolution
table:

    1  the endpoint's declared plane selects the PRIMARY authentication method
    2  primary credential present but INVALID          -> 401
    3  primary credential ABSENT                       -> look for the other methods'
    4  a VALID credential for a DIFFERENT plane        -> 404, body identical to a genuine
                                                          not-found, and the mismatch is
                                                          logged and flagged
    5  no credential of any kind                       -> 401

WHY 404 AND NOT 403 AT STEP 4. C-038 supersedes C-006's `403 PLAT0107` here. A 403 confirms the
endpoint exists, which hands an attacker holding a user token a map of the service plane: probe
a path, read the status, learn whether an internal route sits behind it. A 404 tells them
nothing they did not already know. The body must be INDISTINGUISHABLE from a real not-found,
which is why :class:`PlaneAuthenticationMiddleware` takes the host's own not-found exception as
a required argument rather than inventing one -- see :paramref:`not_found_error`.

WHY AN INVALID FOREIGN CREDENTIAL IS NOT A STEP-4 MISMATCH. Step 4 says a *valid* credential for
another plane. Garbage in an ``Authorization`` header on a service-plane route is not evidence
that a user-plane caller wandered in; it is evidence of a caller with no usable credential at
all, which is step 5 and a 401. Treating it as a mismatch would answer 404 to callers who are
merely broken, and would let anyone map the estate by sending nonsense.

WHICH CREDENTIALS A ROUTE ACCEPTS (falcon-auth#6). Authenticators come in one of two shapes:

    {Method: callable}         the original shape. One authenticator per method, attached to the
                               plane C-038 puts that method on. Every consumer written before #6
                               uses it, and it keeps working unchanged.
    {name: PlaneAuthenticator} named, configured credentials, each attached to the plane(s) it
                               authenticates on -- the identity provider's shape, where USER
                               carries an access token, a pre-login client session, a link token
                               and a client-key proof.

A route accepts the authenticators it pins with ``mount(..., credential=)``, or, pinning none,
every authenticator on its plane. Exactly one per plane and one per route is what C-038 and
C-031 rule; it is a RECOMMENDATION here, held by ``verify(profile="strict")`` and reported by
``verify(profile="permissive")``. What is NOT optional is listed on :meth:`verify`.

THE WRONG-PLANE SEARCH, GENERALISED. Step 4 looks for a valid credential "for a different plane".
With named authenticators that means: an authenticator registered on NO plane of this route's.
One on the same plane that this route simply does not accept is not foreign -- its holder gets
step 5's 401, and learns nothing about the plane.

THE FOUR THINGS IT STAMPS. ``req.context.plane``, ``req.context.auth_method``,
``req.context.auth_principal`` and ``req.context.auth_credential`` (the name of the authenticator
that opened the route -- the method itself, in the original shape). It deliberately does NOT write ``principal`` or
``eastwest_principal``: those are the existing hooks' slots, holding two models that share no
field, and a middleware that cannot tell which it is holding must not pick one of them.
"""
from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, get_args

from structlog import get_logger

from ..errors import Unauthenticated
from ..planes import (
    METHODS_BY_PLANE,
    PLANE_BY_METHOD,
    PUBLIC,
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
    "AUTH_CREDENTIAL_ATTR",
    "AUTH_METHOD_ATTR",
    "AUTH_PRINCIPAL_ATTR",
    "Authenticator",
    "ConventionDeviation",
    "PLANE_ATTR",
    "PlaneAuthenticationMiddleware",
    "Profile",
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

#: ``strict`` refuses at boot what C-038 / C-031 do not allow; ``permissive`` logs it once.
Profile = Literal["strict", "permissive"]

_METHOD_NAMES: frozenset[str] = frozenset(get_args(Method))


class ConventionDeviation(PlaneConflict):
    """``verify(profile="strict")`` found an arrangement C-038 / C-031 do not allow.

    A subclass of :class:`PlaneConflict` -- a host already failing its startup on that keeps
    doing so -- and distinct from it, so a host can tell "this cannot work" from "this works and
    is not what the conventions recommend".
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
    step 3 unreachable and break the CALLBACK plane, which legitimately tries two methods.
    """

    async def __call__(self, req: Any) -> Any | None: ...


@dataclass(frozen=True)
class _Entry:
    """One authenticator as the middleware sees it, whichever shape it was supplied in."""

    name: str
    method: Method | None
    planes: frozenset[Plane]
    attempt: Authenticator
    selector: Any | None  # a Selector; typed loosely to keep this module free of the adapters'


class PlaneAuthenticationMiddleware:
    """Falcon middleware enforcing which credential may open each endpoint.

    Mount it with the app and give it the same registry the routes were mounted through::

        registry = PlaneRegistry()
        middleware = PlaneAuthenticationMiddleware(
            registry,
            authenticators={
                planes.JWT: jwt_authenticator,
                planes.MTLS: mtls_authenticator,
            },
            not_found_error=lambda: OrderNotFoundError(extras={"order_id": None}),
        )
        app = falcon.asgi.App(middleware=[middleware])
        mount(registry, app, "/v1/orders", OrdersResource(), plane=planes.USER)
        verify_app(app, registry)
        middleware.verify()

    Named credentials, pinned per route (falcon-auth#6)::

        authenticators = {
            "access_token": JWTAuthenticator(..., plane=USER, binding=...),
            "client_session": ReferenceAuthenticator(..., plane=USER, binding=...),
            "mtls": MTLSAuthenticator(verifier),
        }
        mount(registry, app, "/v1/token:create", token_route, suffix="create",
              plane=USER, credential="client_session")
        middleware.verify(profile="permissive")
    """

    def __init__(
        self,
        registry: PlaneRegistry,
        *,
        authenticators: Mapping[Any, Authenticator],
        not_found_error: Callable[[], BaseException],
        on_plane_mismatch: Callable[[str, Plane, Method], None] | None = None,
        exempt_paths: Collection[str] = DEFAULT_PROBE_PATHS,
    ) -> None:
        """
        :param registry: the registry the routes were mounted through. Shared, not rebuilt: a
            second registry would be empty, and an empty registry refuses every request.

        :param authenticators: ``{Method: callable}`` -- one per method, on the plane C-038 puts
            it -- or ``{name: PlaneAuthenticator}``, each attached to its own plane(s). Keys that
            are all method names select the first reading; a mix is refused. A method with no
            entry is one this service cannot verify, so a credential of that kind is invisible
            here -- correct for step 3, and harmless for steps 1-2 because a route whose plane
            has nothing that can open it is refused (at boot by :meth:`verify`, else at first
            request).

        :param not_found_error: builds the exception raised on a step-4 plane mismatch.
            **Required, with no default, and the reason is the whole point of the 404.** The
            body must be indistinguishable from a genuine not-found, and only the host knows
            what its genuine not-found looks like. A default here would emit a *recognisably
            different* 404 -- which is a 403 wearing a costume, and hands back exactly the
            signal the status code was chosen to withhold.

        :param on_plane_mismatch: called as ``(uri_template, endpoint_plane, credential_method)``
            when step 4 fires. C-038 requires the mismatch be "logged and flagged"; the log
            happens here regardless, and this is the flag -- a metric, an alert, a security
            event. It is deliberately not a raise: the 404 is the answer to the caller, and the
            flag is the answer to the operator.

        :param exempt_paths: route templates the middleware stands aside for when they were
            NEVER REGISTERED -- health and readiness probes, which sit outside the plane system
            (RUL-033). The same default as :func:`~falcon_auth.adapters.routing.verify_app`, and
            pass the same value to both. Without it, an unregistered probe reached this hook,
            had no registry row, and raised on every probe. A registered route is never exempt:
            naming a USER route here cannot make it public.

        :raises PlaneConflict: when authenticators on different planes read the same carrier --
            see :meth:`verify`, rule 4. Checked here because it needs no routes.
        """
        self._registry = registry
        self._entries, self._legacy = _normalise(authenticators)
        self._not_found_error = not_found_error
        self._on_plane_mismatch = on_plane_mismatch
        self._exempt_paths = frozenset(exempt_paths)
        _refuse_cross_plane_overlap(self._entries.values())

    # -- boot ---------------------------------------------------------------------------

    def verify(self, *, profile: Profile = "strict") -> None:
        """Refuse to start on any wiring gap; and, by profile, on any departure from C-038.

        Call it once, after every route is mounted, beside
        :func:`falcon_auth.adapters.routing.verify_app`. :meth:`_accepted` makes the same gap
        checks on the FIRST REQUEST to a route, which is too late once this middleware is the
        only thing authenticating: a mis-wired plane looks healthy through deploy and smoke
        tests, and is found by a caller.

        **Always refused** -- each would make the middleware give a wrong answer:

            1  a route whose plane has nothing that can open it, or that pins an authenticator
               that does not exist or is not on its plane
            2  two authenticators accepted on ONE route reading the same carrier: a valid
               credential of one kind would be an invalid one of the other, and a legitimate
               caller would get a 401
            3  (at mount) a PUBLIC route naming a credential
            4  (at construction) authenticators on different planes reading the same carrier:
               the wrong-plane search would turn a valid credential of one plane into an
               invalid one of the other

        **By profile** -- what C-038 and C-031 rule, and this package recommends:

            R1  a plane carries a method C-038 does not put there (METHODS_BY_PLANE)
            R2  an authenticator is attached to more than one plane
            R3  a route accepts two authenticators of the SAME method -- two ways to prove one
                thing, and the caller picks the weaker (C-031). Two different methods both in
                the plane's map, as CALLBACK's HMAC and one-shot token, are C-038's own
                allowance and pass

        ``strict`` raises :class:`ConventionDeviation` naming every finding; ``permissive``
        logs each once and starts. The identity provider runs permissive (falcon-auth#6); a
        resource service should not need to.

        PUBLIC is skipped: no method authenticates there, which is a declaration rather than a
        gap (see :data:`falcon_auth.planes.METHODS_BY_PLANE`).

        :raises UnregisteredRoute: rule 1, naming every plane at fault, what it needs, and up to
            three example routes, so a service with two mis-wired planes fixes both in one pass.
        :raises PlaneConflict: rule 2.
        :raises ConventionDeviation: R1-R3, under ``strict``.
        """
        if profile not in ("strict", "permissive"):
            raise ValueError(f"profile must be 'strict' or 'permissive'; got {profile!r}")

        gaps: dict[Plane, tuple[list[str], list[str]]] = {}
        pin_errors: list[str] = []
        overlaps: list[str] = []
        same_method: list[str] = []
        for registration in self._registry.routes().values():
            plane = registration.plane
            if plane == PUBLIC:
                continue
            endpoint = str(registration.endpoint)
            try:
                accepted = self._accepted(registration)
            except _Gap as gap:
                if gap.pinned:
                    pin_errors.append(f"{endpoint}: {gap}")
                else:
                    _, examples = gaps.setdefault(plane, (gap.missing, []))
                    if len(examples) < 3:
                        examples.append(endpoint)
                continue
            overlaps.extend(_route_overlaps(endpoint, accepted))
            by_method: dict[Method | None, list[str]] = {}
            for entry in accepted:
                by_method.setdefault(entry.method, []).append(entry.name)
            same_method.extend(
                f"{endpoint} accepts {names} -- all {method}"
                for method, names in by_method.items()
                if method is not None and len(names) > 1
            )

        if gaps:
            detail = "; ".join(
                f"{plane} needs {missing} (e.g. {', '.join(examples)})"
                for plane, (missing, examples) in sorted(gaps.items())
            )
            raise UnregisteredRoute(
                f"these planes have mounted routes but no authenticator was supplied for their "
                f"method, so nothing could open them: {detail}"
            )
        if pin_errors:
            raise UnregisteredRoute(
                "these routes pin credentials that cannot open them: " + "; ".join(pin_errors)
            )
        if overlaps:
            raise PlaneConflict(
                "these routes accept two authenticators reading the same carrier, so a valid "
                "credential of one kind would be an invalid one of the other: "
                + "; ".join(overlaps)
            )

        deviations = {
            "R1 a plane carries a method C-038 does not put there": [
                f"{e.name} ({e.method}) on {plane}"
                for e in self._entries.values()
                for plane in sorted(e.planes)
                if e.method is not None and e.method not in METHODS_BY_PLANE[plane]
            ],
            "R2 an authenticator is attached to more than one plane": [
                f"{e.name} on {sorted(e.planes)}"
                for e in self._entries.values()
                if len(e.planes) > 1
            ],
            "R3 a route accepts two authenticators of the same method": same_method,
        }
        found = {rule: items for rule, items in deviations.items() if items}
        if not found:
            return
        if profile == "strict":
            raise ConventionDeviation(
                "this wiring departs from C-038 / C-031: "
                + "; ".join(f"{rule}: {', '.join(items)}" for rule, items in found.items())
                + ". verify(profile='permissive') starts anyway and logs each"
            )
        for rule, items in found.items():
            logger.warning("plane_convention_deviation", rule=rule, findings=items)

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
            # the right answer and this hook stands aside.
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

        if plane == PUBLIC:
            # A stated-reason PUBLIC route. No credential is demanded, and none is inspected:
            # looking would invite a handler to start trusting one that was never verified.
            self._stamp(req, plane, None)
            return

        try:
            accepted = self._accepted(registration)
        except _Gap as gap:
            raise UnregisteredRoute(f"{template}: {gap}") from None

        # Steps 1-2. A raise here propagates as a 401 and is NOT caught: a present-but-invalid
        # credential this route accepts is a final answer, not a reason to go looking for another.
        for entry in accepted:
            principal = await entry.attempt(req)
            if principal is not None:
                self._stamp(req, plane, entry, principal)
                return

        # Steps 3-4. Nothing this route accepts is present. Does the caller hold a valid
        # credential belonging to some other plane?
        foreign = await self._find_foreign_credential(req, plane)
        if foreign is not None:
            self._refuse_wrong_plane(req, template, plane, foreign)

        # Step 5. Nothing usable at all.
        raise Unauthenticated(
            f"this endpoint is on the {plane} plane and requires "
            f"{' or '.join(e.name for e in accepted)}"
        )

    # -- the pieces -----------------------------------------------------------------------

    def _accepted(self, registration: Registration) -> list[_Entry]:
        """The authenticators this endpoint accepts, in the order they are tried.

        Pinned: exactly those, in the order given. Unpinned: every authenticator on the plane --
        and in the original ``{Method: callable}`` shape, EVERY method C-038 puts on the plane
        must have one. A route whose plane has nothing that can open it is a wiring bug: it
        fails loudly rather than answering 401 to every caller forever, which is the shape of
        outage that gets diagnosed as a credential problem for a day and a half.
        """
        plane = registration.plane
        if registration.credentials is not None:
            entries = []
            for name in registration.credentials:
                entry = self._entries.get(name)
                if entry is None:
                    raise _Gap(f"no authenticator named {name!r} was supplied", [name], True)
                if plane not in entry.planes:
                    raise _Gap(
                        f"{name!r} authenticates on {sorted(entry.planes)}, not {plane}",
                        [name],
                        True,
                    )
                entries.append(entry)
            return entries

        if self._legacy:
            methods = methods_for(plane)
            missing: list[str] = sorted(methods - self._entries.keys())
            if missing:
                raise _Gap(
                    f"{plane} plane authenticates by {sorted(methods)}, but no authenticator "
                    f"was supplied for {missing}",
                    missing,
                    False,
                )
            return [self._entries[m] for m in sorted(methods)]

        entries = sorted(
            (e for e in self._entries.values() if plane in e.planes), key=lambda e: e.name
        )
        if not entries:
            raise _Gap(
                f"no authenticator is attached to the {plane} plane", [f"<any on {plane}>"], False
            )
        return entries

    async def _find_foreign_credential(self, req: Any, plane: Plane) -> _Entry | None:
        """A valid credential from an authenticator on NO plane of this endpoint's, if any.

        Only authenticators this host supplied are considered -- a credential nobody here can
        verify is not a credential anybody here can recognise as foreign. One on the SAME plane
        that this route does not accept is not foreign either: its holder ends at step 5.
        """
        for entry in sorted(self._entries.values(), key=lambda e: e.name):
            if plane in entry.planes:
                continue
            try:
                principal = await entry.attempt(req)
            except Exception:
                # Present but INVALID. That is a verification -- it did cryptographic work -- so
                # by C-038 Q88 it is the one secondary this step is allowed, and the search stops
                # here. It is also not a mismatch: garbage is a caller with no usable credential,
                # which is step 5's 401. See the module docstring.
                return None
            if principal is not None:
                return entry
            # `None` means no credential of THIS kind is present. Nothing was verified, so this
            # does not count against Q88's budget and the search continues. Bounding on lookups
            # rather than verifications would end the search at the first method the caller
            # simply did not use -- which, iterating alphabetically, is usually the first one.
        return None

    def _refuse_wrong_plane(self, req: Any, template: str, plane: Plane, foreign: _Entry) -> None:
        """Step 4: log, flag, and answer as though the endpoint did not exist."""
        logger.warning(
            "plane_mismatch",
            uri_template=template,
            method=req.method,
            endpoint_plane=plane,
            credential=foreign.name,
            credential_method=foreign.method,
            credential_plane="/".join(sorted(foreign.planes)),
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
    """A route nothing can open. Internal: becomes UnregisteredRoute at request or boot time."""

    def __init__(self, message: str, missing: list[str], pinned: bool) -> None:
        super().__init__(message)
        self.missing = missing
        self.pinned = pinned


def _normalise(authenticators: Mapping[Any, Authenticator]) -> tuple[dict[str, _Entry], bool]:
    """Read either shape into one: ``{name: _Entry}``, and whether it was the original shape."""
    keys = list(authenticators)
    as_methods = [k for k in keys if k in _METHOD_NAMES]
    if keys and len(as_methods) == len(keys):
        entries = {}
        for method, attempt in authenticators.items():
            if method not in PLANE_BY_METHOD:
                raise ValueError(
                    f"{method!r} sits under no plane in METHODS_BY_PLANE, so the {{Method: "
                    f"callable}} shape cannot place it; supply it as a named PlaneAuthenticator "
                    f"with plane=..."
                )
            entries[method] = _Entry(
                name=method,
                method=method,
                planes=frozenset([PLANE_BY_METHOD[method]]),
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
                f"MTLSAuthenticator, CustomAuthenticator) so the middleware knows where each "
                f"belongs"
            )
        entries[name] = _Entry(
            name=name,
            method=getattr(attempt, "method", None),
            planes=frozenset(planes),
            attempt=attempt,
            selector=getattr(attempt, "selector", None),
        )
    return entries, False


def _overlap(a: _Entry, b: _Entry) -> bool:
    if a.selector is None or b.selector is None:
        return False
    return bool(a.selector.overlaps(b.selector))


def _refuse_cross_plane_overlap(entries: Iterable[_Entry]) -> None:
    found = []
    listed = sorted(entries, key=lambda e: e.name)
    for i, a in enumerate(listed):
        for b in listed[i + 1:]:
            if not (a.planes & b.planes) and _overlap(a, b):
                found.append(
                    f"{a.name} ({'/'.join(sorted(a.planes))}) and "
                    f"{b.name} ({'/'.join(sorted(b.planes))}) both read {a.selector}"
                )
    if found:
        raise PlaneConflict(
            "authenticators on different planes read the same carrier, so the wrong-plane "
            "search could not tell their credentials apart: " + "; ".join(found)
        )


def _route_overlaps(endpoint: str, accepted: list[_Entry]) -> list[str]:
    return [
        f"{endpoint}: {a.name} and {b.name} both read {a.selector}"
        for i, a in enumerate(accepted)
        for b in accepted[i + 1:]
        if _overlap(a, b)
    ]

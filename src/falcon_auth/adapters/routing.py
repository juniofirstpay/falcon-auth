"""Mounting routes with a plane, and refusing a bad arrangement at startup.

A route belongs to exactly one plane (C-006). Mixing two on one route destroys the single
meaning of every answer the other layers give: the ownership guard's 404 means "not found, or
not yours" on the user plane, and on the service plane there is no "yours" for it to mean -- a
peer backend reading across parties is correct, and is the reason those routes exist. One route
serving both would need every handler to branch on which plane it is on, and the handler that
forgets is a silent hole rather than a loud one.

So this is a REGISTRY, not a middleware. It answers at import or mount time, when a human is
watching, rather than producing a route whose denial semantics depend on which decorator ran
last.

    registry = PlaneRegistry()
    mount(registry, app, "/v1/orders/{order_id}", OrderResource(), plane=planes.USER)
    mount(registry, app, "/v1/orders/{order_id}:refund", RefundResource(),
          plane=planes.SERVICE, suffix="refund")

THESE ARE REFUSED HERE, each a wiring bug rather than a runtime condition:

    one endpoint on two planes       the original conflict -- two principal types reach it
    one resource CLASS on two planes C-006: Falcon binds an INSTANCE serving many endpoints
                                     through suffixed responders, so the class must be pinned
                                     too. A registry keyed only on (method, path) cannot see
                                     this, which is why persona's could not
    one resource class on two API versions   same shape: one object, two contracts, and
                                     nothing to notice when a responder is added
    a PUBLIC route with no stated reason     C-006/RUL-035: "no credential" is a decision
                                     somebody must have made on purpose
    a path whose first segment is not        C-039 (⛔ mandatory): ``^/v\d+/``. Out of its scope,
      the API version                        by RUL-135: ``/.well-known/...`` -- and probes, which
                                     are never mounted here at all (below). A vendor-held
                                     callback URL is served in BOTH forms while the vendor
                                     migrates (C-039's mount-and-retire): ``alias_of=``

WHAT IS DELIBERATELY NOT REFUSED. Health and readiness sit OUTSIDE the plane system entirely
(RUL-033): they answer the platform's probe, not a caller, and are mounted bare and
unregistered. :func:`verify_app` takes them as exemptions rather than pretending they are
PUBLIC routes -- PUBLIC means "a caller may reach this without a credential", which is a
different statement from "this is not a caller-facing route at all".

A PATH PREFIX CARRIES NO AUTHORITY. ``/internal/``, ``/admin/`` and ``/webhooks/`` are names.
The plane comes from the registration and nowhere else, and nothing in this module reads a
path prefix to decide one.
"""
from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

import structlog

from ..planes import CALLBACK, PLANES, PUBLIC, RESOURCE_SERVICE_PLANES, SERVICE, USER, Plane

__all__ = (
    "DEFAULT_PROBE_PATHS",
    "Endpoint",
    "PlaneConflict",
    "PlaneRegistry",
    "Registration",
    "UnregisteredRoute",
    "mount",
    "verify_app",
)

#: Paths outside the plane system (RUL-033). Passed to :func:`verify_app` rather than consulted
#: implicitly, so a service that names its probes differently overrides them in the open instead
#: of discovering that two strings were baked in here.
DEFAULT_PROBE_PATHS = frozenset({"/health", "/ready"})

logger = structlog.get_logger("falcon_auth.adapters")

#: C-039: the API version is the first path segment -- the owed check, as RUL-135 words it.
_VERSIONED = re.compile(r"^/v\d+/")
#: RUL-135: a `/.well-known/` resource evolves by additions and deprecation notices, never
#: outright removal, so it carries no version segment.
_WELL_KNOWN = "/.well-known/"


class PlaneConflict(RuntimeError):
    """A route, or a resource class, was arranged on two planes.

    A wiring bug, so it is raised where the wiring is written -- at import or mount -- and never
    at request time. Converting a security question into a startup failure costs nothing at
    runtime and cannot be missed.
    """


class UnregisteredRoute(PlaneConflict):
    """A route reached the app without going through :func:`mount`.

    Registration is not optional (C-006). A route mounted by a bare ``add_route`` has no plane,
    so the middleware has no method to require of it -- and "no method required" is the one
    outcome the whole arrangement exists to prevent.
    """


@dataclass(frozen=True)
class Endpoint:
    """An endpoint is ``HTTP method + URI template`` (C-038, settling CLARIF-01).

    Method-level splits are legitimate: ``GET /x/{id}`` and ``DELETE /x/{id}`` are two endpoints
    and may sit on different planes. In Falcon that split needs two resource CLASSES, because
    the class-purity rule below binds the instance, not the responder.
    """

    method: str
    path: str

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


@dataclass(frozen=True)
class Registration:
    """What the registry knows about one endpoint."""

    endpoint: Endpoint
    plane: Plane
    resource_type: type
    version: str | None
    #: Required for PUBLIC, ``None`` elsewhere. Kept so the registry can be printed as the
    #: answer to "what is reachable without a credential, and why".
    reason: str | None = None
    #: The ONE named authenticator this endpoint accepts (C-060 §3), or ``None`` for "the one
    #: authenticator on its plane" -- valid only while the plane has exactly one, which the
    #: middleware checks.
    credential: str | None = None
    #: The actor types this endpoint admits (C-052 §5): a USER route declares at least one of
    #: ``CUSTOMER``/``OPERATOR``, ⛔ never "any"; a SERVICE route admits ``SERVICE``; other planes
    #: declare none. ``None`` where none applies.
    actor_types: frozenset[str] | None = None
    #: For a vendor-held CALLBACK URL still served unversioned, the versioned route it is the
    #: retiring twin of (C-039's mount-and-retire). ``None`` for every other route.
    alias_of: str | None = None


class PlaneRegistry:
    """Every mounted route's plane, refusing an arrangement that cannot be enforced.

    Fail-closed: an empty registry means no route is known, so :func:`verify_app` reports every
    mounted route rather than approving silently.
    """

    def __init__(self, *, allow_dev_routes: bool = False) -> None:
        """
        :param allow_dev_routes: whether routes marked ``dev_only`` may mount at all.

            Defaults to **False**, which is the fail-closed direction: a dev route reaches a
            production process only when something explicitly said it may (RUL-035). It is a
            constructor argument rather than a settings lookup because this package reads no
            configuration -- the host passes what its own environment tier says.
        """
        self._by_endpoint: dict[tuple[str, str], Registration] = {}
        self._by_class: dict[type, Registration] = {}
        # The class's API version is tracked SEPARATELY from its pin above, because the pin is
        # whichever endpoint registered first and that one may carry no version segment at all
        # (a callback path, say). Reading the version off the pin would then leave it None
        # forever, and every later version would compare equal to "no version" and pass -- so a
        # class first mounted unversioned could go on to serve v1 and v2 both. This records the
        # first version actually seen, whenever it is seen.
        self._version_by_class: dict[type, str] = {}
        self._allow_dev_routes = allow_dev_routes

    @property
    def allow_dev_routes(self) -> bool:
        return self._allow_dev_routes

    def register(
        self,
        plane: Plane,
        method: str,
        path: str,
        resource_type: type,
        *,
        reason: str | None = None,
        credential: str | None = None,
        actor_types: frozenset[str] | None = None,
        alias_of: str | None = None,
    ) -> Registration:
        """Record one endpoint's plane, or raise explaining which rule it broke."""
        if plane not in PLANES:
            raise PlaneConflict(f"unknown plane {plane!r}; expected one of {sorted(PLANES)}")

        if plane not in RESOURCE_SERVICE_PLANES:
            raise PlaneConflict(
                f"{method.upper()} {path} is on the {plane} plane, which only the identity "
                f"provider mounts (C-060 §2). This package serves resource services (RUL-157)"
            )

        _check_actor_types(plane, method, path, actor_types)

        if plane == PUBLIC and credential is not None:
            raise PlaneConflict(
                f"{method.upper()} {path} is PUBLIC but names credential {credential!r}. A "
                f"PUBLIC route establishes no caller principal (C-060 §5); evidence it needs is "
                f"payload the route validates itself"
            )

        if plane == PUBLIC and not (reason or "").strip():
            raise PlaneConflict(
                f"{method.upper()} {path} is PUBLIC but carries no reason. A route reachable "
                f"with no credential is a decision, and the decision is recorded next to it "
                f"(C-006, RUL-035) -- pass reason=..."
            )

        endpoint = Endpoint(method.upper(), path)
        key = (endpoint.method, endpoint.path)
        version = version_of(path)

        if alias_of is None:
            _check_versioned(endpoint)
        else:
            self._check_alias(plane, endpoint, alias_of, resource_type, credential)

        existing = self._by_endpoint.get(key)
        if existing is not None and existing.plane != plane:
            raise PlaneConflict(
                f"{endpoint} is already registered on the {existing.plane} plane; refusing to "
                f"also mount it on {plane}. An endpoint reachable on two planes is reachable "
                f"by two principal types, and the second is rarely intended"
            )

        # C-006's class-purity rule. Falcon binds an INSTANCE that answers many endpoints through
        # suffixed responders, so pinning the endpoint is not enough: a class spanning two planes
        # is kept apart only by suffix dispatch, with nothing to notice when a bare responder is
        # added later. That is the estate's one known cross-plane class, and this is the check
        # that would have caught it.
        pinned = self._by_class.get(resource_type)
        if pinned is not None and pinned.plane != plane:
            raise PlaneConflict(
                f"{resource_type.__name__} already serves the {pinned.plane} plane (at "
                f"{pinned.endpoint}); refusing to also mount it on {plane}. One resource class "
                f"serves exactly one plane -- split it into two classes"
            )
        held = self._version_by_class.get(resource_type)
        if version is not None and held is not None and held != version:
            raise PlaneConflict(
                f"{resource_type.__name__} already serves API version {held!r}; refusing to "
                f"also mount it under {version!r}. One class, two contracts, and nothing to "
                f"notice when a responder is added -- give the new version its own class"
            )

        registration = Registration(
            endpoint=endpoint,
            plane=plane,
            resource_type=resource_type,
            version=version,
            reason=reason,
            credential=credential,
            actor_types=actor_types,
            alias_of=alias_of,
        )
        self._by_endpoint[key] = registration
        self._by_class.setdefault(resource_type, registration)
        if version is not None:
            self._version_by_class.setdefault(resource_type, version)
        return registration

    def _check_alias(
        self,
        plane: Plane,
        endpoint: Endpoint,
        alias_of: str,
        resource_type: type,
        credential: str | None,
    ) -> None:
        """C-039's mount-and-retire: the unversioned form of a vendor-held callback URL.

        A vendor holds the registered URL, so the platform cannot move it in one release; both
        forms are served while each vendor migrates, then the unversioned one is unmounted. The
        alias is held to exactly that, so it cannot become a general way round C-039 (an
        allow-list of legacy paths would be an exception, and C-039 admits none -- RUL-056 Q99):

            on CALLBACK only          first-party callers re-path big-bang; only a vendor URL
                                      is migrated route by route
            the path is unversioned   a versioned path needs no alias
            its twin is mounted FIRST the versioned route, on CALLBACK, same method, same
                                      resource class, same credential -- one handler, two URLs,
                                      and nothing the alias could do that the twin cannot
        """
        if plane != CALLBACK:
            raise PlaneConflict(
                f"{endpoint} is on the {plane} plane; alias_of= is C-039's mount-and-retire for "
                f"a vendor-held CALLBACK URL only. First-party routes re-path big-bang"
            )
        if _VERSIONED.match(endpoint.path):
            raise PlaneConflict(
                f"{endpoint} already carries a version segment, so it is no alias -- drop "
                f"alias_of={alias_of!r}"
            )
        twin = self._by_endpoint.get((endpoint.method, alias_of))
        if twin is None:
            raise PlaneConflict(
                f"{endpoint} is declared the retiring alias of {alias_of!r}, but "
                f"{endpoint.method} {alias_of} is not mounted. Mount the versioned route first "
                f"(C-039: the vendor migrates TO it)"
            )
        if twin.plane != CALLBACK or twin.alias_of is not None:
            raise PlaneConflict(
                f"{endpoint}: its twin {twin.endpoint} must be a versioned CALLBACK route"
            )
        if twin.resource_type is not resource_type or twin.credential != credential:
            raise PlaneConflict(
                f"{endpoint} must serve exactly what {twin.endpoint} serves: the same resource "
                f"class and the same credential. An alias that differs is a second route"
            )

    # -- reading it back ------------------------------------------------------------------

    def plane_of(self, method: str, path: str) -> Plane | None:
        """The plane of one endpoint, or ``None`` if it was never registered.

        ``None`` is not a plane and must never be treated as PUBLIC by a caller -- it means the
        route is unknown to the registry, which :func:`verify_app` refuses at boot and the
        middleware refuses per request.
        """
        registration = self._by_endpoint.get((method.upper(), path))
        return registration.plane if registration else None

    def registration_of(self, method: str, path: str) -> Registration | None:
        return self._by_endpoint.get((method.upper(), path))

    def registered_methods(self, path: str) -> frozenset[str]:
        """Every HTTP method registered for ``path``.

        The middleware needs this to tell two cases apart, because Falcon runs
        ``process_resource`` for BOTH of them:

            the template has rows, but not for this method   -> Falcon's own 405; not ours
            the template has no rows at all                  -> an unregistered route; refuse

        Without the distinction, a DELETE against a GET-only resource looks exactly like a
        route that never reached the registry, and a clean 405 becomes a 500.
        """
        return frozenset(m for (m, p) in self._by_endpoint if p == path)

    def plane_of_class(self, resource_type: type) -> Plane | None:
        return reg.plane if (reg := self._by_class.get(resource_type)) else None

    def routes(self, plane: Plane | None = None) -> dict[Endpoint, Registration]:
        """Every registration, or only those on ``plane``. A copy -- safe to iterate and filter."""
        found = self._by_endpoint.values()
        return {
            r.endpoint: r for r in found if plane is None or r.plane == plane
        }

    def public_routes(self) -> dict[Endpoint, str]:
        """Everything reachable without a credential, and the stated reason for each.

        The answer to the question an auditor actually asks, available without reading the
        route table.
        """
        return {r.endpoint: (r.reason or "") for r in self.routes(PUBLIC).values()}

    def aliases(self) -> dict[Endpoint, str]:
        """Every unversioned callback URL still served, and the versioned route it retires into.

        C-039's mount-and-retire, as a list: what is left to unmount once each vendor has moved.
        """
        return {r.endpoint: r.alias_of for r in self._by_endpoint.values() if r.alias_of}

    def __len__(self) -> int:
        return len(self._by_endpoint)

    def __repr__(self) -> str:
        by_plane = {p: len(self.routes(p)) for p in sorted(PLANES) if self.routes(p)}
        return f"<PlaneRegistry {len(self)} routes {by_plane}>"


# -- mounting -------------------------------------------------------------------------------


#: The actor types a route on each plane may admit (C-052 §2, §5).
_ADMISSIBLE: dict[str, frozenset[str]] = {
    USER: frozenset({"CUSTOMER", "OPERATOR"}),
    SERVICE: frozenset({"SERVICE"}),
}
#: C-052 §8 / C-051: an OPERATOR-only route lives under `/v<n>/ops/`.
_OPS_PATH = re.compile(r"^/v\d+/ops/")


def _check_versioned(endpoint: Endpoint) -> None:
    """C-039: the API version is the first path segment. ⛔ Mandatory -- no exception exists."""
    if _VERSIONED.match(endpoint.path) or endpoint.path.startswith(_WELL_KNOWN):
        return
    raise PlaneConflict(
        f"{endpoint}: the API version is the first path segment, ^/v\\d+/ (C-039, mandatory). "
        f"Mount it as /v1{endpoint.path}. Out of scope (RUL-135): /.well-known/... and health "
        f"probes -- a probe is mounted bare, outside the plane system, and named in "
        f"verify_app(exempt_paths=). A vendor-held callback URL still being migrated is served "
        f"as alias_of= its versioned twin"
    )


def _check_actor_types(plane: Plane, method: str, path: str, actor_types: frozenset[str] | None) -> None:
    endpoint = f"{method.upper()} {path}"
    allowed = _ADMISSIBLE.get(plane, frozenset())
    if actor_types is None:
        return  # a USER route with none is refused by the middleware's verify() and per request
    if not actor_types:
        raise PlaneConflict(
            f"{endpoint} declares an empty set of actor types: a route admits at least one, "
            f"⛔ never 'any' (C-052 §5)"
        )
    stray = sorted(actor_types - allowed)
    if stray:
        raise PlaneConflict(
            f"{endpoint} is on the {plane} plane, which admits {sorted(allowed) or 'no actor type'}; "
            f"it declares {stray} (C-052 §2)"
        )
    if actor_types == {"OPERATOR"} and not _OPS_PATH.match(path):
        raise PlaneConflict(
            f"{endpoint} admits only OPERATOR, so it lives under /v<n>/ops/ (C-052 §8, RUL-178)"
        )


def mount(
    registry: PlaneRegistry,
    app: Any,
    path: str,
    resource: Any,
    *,
    plane: Plane,
    suffix: str | None = None,
    reason: str | None = None,
    dev_only: bool = False,
    credential: str | None = None,
    actor_types: Collection[str] | None = None,
    alias_of: str | None = None,
) -> bool:
    """``app.add_route(...)`` and record the plane of every method the resource answers.

    Returns whether the route was mounted -- ``False`` only for a ``dev_only`` route in a
    registry that does not allow them.

    The methods are DERIVED from the resource rather than restated at the call site, which is
    what keeps the plane record from drifting the day someone adds an ``on_post`` to an existing
    resource. A resource with no responder for ``suffix`` is a mounting mistake and raises here.

    :param reason: required when ``plane`` is PUBLIC; see :meth:`PlaneRegistry.register`.
    :param dev_only: a route that must not exist in production (RUL-035). It is skipped
        entirely -- not mounted and not registered -- rather than mounted behind a runtime
        check, because a route that exists is a route that can be reached.
    :param credential: the name of the ONE authenticator this route accepts (C-060 §3).
        Omitted, the route takes the one authenticator on its plane -- the right default
        wherever a plane carries one. ⛔ Never a list: a route that accepts "any of" two
        credentials lets the caller choose the weaker (C-031's reason, at route grain).
    :param actor_types: who the route admits (C-052 §5) -- REQUIRED on USER routes, a non-empty
        subset of ``{"CUSTOMER", "OPERATOR"}``. A route admitting only ``OPERATOR`` must live under
        ``/v<n>/ops/`` or it refuses to mount (C-052 §8, RUL-178). SERVICE routes admit
        ``SERVICE`` (the default); CALLBACK and PUBLIC routes declare none.
    :param alias_of: on a CALLBACK route only, the versioned path this UNVERSIONED one is the
        retiring twin of -- C-039's mount-and-retire, while a vendor still calls the URL it was
        given. The twin is mounted first, with the same resource and credential::

            mount(registry, app, "/v1/callbacks/paytm", hook, plane=CALLBACK)
            mount(registry, app, "/callbacks/paytm", hook, plane=CALLBACK,
                  alias_of="/v1/callbacks/paytm")       # unmount once Paytm has moved

        Every other path must open with ``/v<n>/`` (C-039), or ``/.well-known/`` (RUL-135).
    """
    if credential is not None and not isinstance(credential, str):
        raise PlaneConflict(
            f"{path}: credential= takes one authenticator name, got {credential!r}. A route "
            f"declares exactly one credential (C-060 §3); split it into two routes"
        )
    if dev_only and not registry.allow_dev_routes:
        return False

    methods = responder_methods(resource, suffix)
    if not methods:
        raise PlaneConflict(
            f"{path} mounted with suffix={suffix!r} but {type(resource).__name__} has no "
            f"matching on_<method> responder"
        )

    # Register BEFORE adding the route. A conflict must leave the app without the offending
    # route rather than with a mounted route the registry disowns.
    for method in methods:
        registry.register(
            plane, method, path, type(resource), reason=reason, credential=credential,
            actor_types=frozenset(actor_types) if actor_types is not None else None,
            alias_of=alias_of,
        )
    if alias_of is not None:
        # Visible in every deploy log until the vendor has moved and the alias is unmounted.
        logger.warning("callback_unversioned_alias", path=path, alias_of=alias_of)

    if suffix is not None:
        app.add_route(path, resource, suffix=suffix)
    else:
        app.add_route(path, resource)
    return True


def responder_methods(resource: Any, suffix: str | None = None) -> list[str]:
    """The HTTP methods ``resource`` answers for ``suffix``, from its ``on_<method>[_<suffix>]``
    members."""
    tail = f"_{suffix}" if suffix else ""
    found = []
    for name in dir(resource):
        if not name.startswith("on_"):
            continue
        rest = name[len("on_") :]
        if suffix:
            if not rest.endswith(tail):
                continue
            rest = rest[: -len(tail)]
        elif "_" in rest:
            continue  # a suffixed responder; not ours
        if rest and callable(getattr(resource, name, None)):
            found.append(rest.upper())
    return sorted(found)


def version_of(path: str) -> str | None:
    """The API version segment of ``path``, per C-039: the version is the FIRST path segment.

    ``None`` for a path with no version segment. This REPORTS; :meth:`PlaneRegistry.register`
    is what refuses an unversioned path (falcon-auth#1 A9, sequenced by RUL-162 #26).
    """
    head = path.lstrip("/").split("/", 1)[0]
    if len(head) >= 2 and head[0] == "v" and head[1:].isdigit():
        return head
    return None


# -- the boot sweep -------------------------------------------------------------------------


def verify_app(
    app: Any,
    registry: PlaneRegistry,
    *,
    exempt_paths: frozenset[str] = DEFAULT_PROBE_PATHS,
) -> None:
    """Refuse to start if any mounted route never reached the registry.

    :func:`mount` guarantees that what goes through it is registered; this catches what did not
    -- a bare ``app.add_route`` somewhere, which is the failure the registry cannot see from the
    inside. Registration is not optional (C-006): an unregistered route has no plane, so the
    middleware has no method to demand of it.

    Call it once, after every route is mounted and before serving.

    :param exempt_paths: paths outside the plane system -- health and readiness (RUL-033). They
        answer the platform's probe, not a caller.
    :raises UnregisteredRoute: naming every offending route at once, so a service with several
        fixes them in one pass rather than one restart each.
    """
    from falcon import inspect as falcon_inspect

    unregistered: list[str] = []
    for route in falcon_inspect.inspect_routes(app):
        path = route.path
        if path in exempt_paths:
            continue
        for responder in route.methods:
            # Falcon reports EVERY HTTP method it knows for each route -- 24 of them -- because
            # it generates a 405 responder for each one the class does not implement. Those carry
            # `internal=True`. Without this filter the sweep would flag every route on the app.
            if responder.internal:
                continue
            method = responder.method.upper()
            if registry.registration_of(method, path) is None:
                unregistered.append(f"{method} {path} ({route.class_name})")

    if unregistered:
        raise UnregisteredRoute(
            "these routes are mounted but carry no plane, so nothing can be required of "
            "their callers -- mount them through falcon_auth.adapters.routing.mount, or name "
            f"them in exempt_paths if they sit outside the plane system: {sorted(unregistered)}"
        )

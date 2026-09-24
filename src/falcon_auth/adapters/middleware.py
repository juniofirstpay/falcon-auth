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

THE THREE THINGS IT STAMPS. ``req.context.plane``, ``req.context.auth_method`` and
``req.context.auth_principal``. It deliberately does NOT write ``principal`` or
``eastwest_principal``: those are the existing hooks' slots, holding two models that share no
field, and a middleware that cannot tell which it is holding must not pick one of them.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from structlog import get_logger

from ..errors import Unauthenticated
from ..planes import PLANE_BY_METHOD, PUBLIC, Method, Plane, methods_for
from .routing import PlaneRegistry, UnregisteredRoute

__all__ = (
    "AUTH_METHOD_ATTR",
    "AUTH_PRINCIPAL_ATTR",
    "Authenticator",
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


class PlaneAuthenticationMiddleware:
    """Falcon middleware enforcing one authentication method per plane.

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
    """

    def __init__(
        self,
        registry: PlaneRegistry,
        *,
        authenticators: Mapping[Method, Authenticator],
        not_found_error: Callable[[], BaseException],
        on_plane_mismatch: Callable[[str, Plane, Method], None] | None = None,
    ) -> None:
        """
        :param registry: the registry the routes were mounted through. Shared, not rebuilt: a
            second registry would be empty, and an empty registry refuses every request.

        :param authenticators: ``method -> how to attempt it``. A method with no entry is one
            this service cannot verify, so a credential of that kind is invisible here -- which
            is correct for step 3 (it cannot be recognised as belonging elsewhere) and harmless
            for steps 1-2, because the registry would have refused a route on a plane whose
            method the host never supplied. That refusal happens in :meth:`_primary_for`.

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
        """
        self._registry = registry
        self._authenticators = dict(authenticators)
        self._not_found_error = not_found_error
        self._on_plane_mismatch = on_plane_mismatch

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
            self._stamp(req, plane, None, None)
            return

        primary = self._primary_for(plane, template)

        # Steps 1-2. A raise here propagates as a 401 and is NOT caught: a present-but-invalid
        # primary credential is a final answer, not a reason to go looking for another.
        for candidate in sorted(primary):
            principal = await self._authenticators[candidate](req)
            if principal is not None:
                self._stamp(req, plane, candidate, principal)
                return

        # Steps 3-4. The primary is absent. Does the caller hold a valid credential belonging to
        # some other plane?
        foreign = await self._find_foreign_credential(req, primary)
        if foreign is not None:
            self._refuse_wrong_plane(req, template, plane, foreign)

        # Step 5. Nothing usable at all.
        raise Unauthenticated(
            f"this endpoint is on the {plane} plane and requires "
            f"{' or '.join(sorted(primary))}"
        )

    # -- the pieces -----------------------------------------------------------------------

    def _primary_for(self, plane: Plane, template: str) -> frozenset[Method]:
        """The methods that authenticate on ``plane``, all of which this host can attempt.

        A host that mounted a route on a plane whose method it never supplied an authenticator
        for has built a route nobody can open. That is a wiring bug and it fails loudly here
        rather than answering 401 to every caller forever, which is the shape of outage that
        gets diagnosed as a credential problem for a day and a half.
        """
        methods = methods_for(plane)
        missing = methods - self._authenticators.keys()
        if missing:
            raise UnregisteredRoute(
                f"{template} is on the {plane} plane, which authenticates by "
                f"{sorted(methods)}, but no authenticator was supplied for {sorted(missing)}"
            )
        return methods

    async def _find_foreign_credential(
        self, req: Any, primary: frozenset[Method]
    ) -> tuple[Method, Plane] | None:
        """A valid credential belonging to a plane other than this endpoint's, if any.

        Only methods this host can actually attempt are considered -- a credential nobody here
        can verify is not a credential anybody here can recognise as foreign.
        """
        for candidate, owning_plane in sorted(PLANE_BY_METHOD.items()):
            if candidate in primary or candidate not in self._authenticators:
                continue
            try:
                principal = await self._authenticators[candidate](req)
            except Exception:
                # Present but INVALID. That is a verification -- it did cryptographic work -- so
                # by C-038 Q88 it is the one secondary this step is allowed, and the search stops
                # here. It is also not a mismatch: garbage is a caller with no usable credential,
                # which is step 5's 401. See the module docstring.
                return None
            if principal is not None:
                return candidate, owning_plane
            # `None` means no credential of THIS kind is present. Nothing was verified, so this
            # does not count against Q88's budget and the search continues. Bounding on lookups
            # rather than verifications would end the search at the first method the caller
            # simply did not use -- which, iterating alphabetically, is usually the first one.
        return None

    def _refuse_wrong_plane(
        self, req: Any, template: str, plane: Plane, foreign: tuple[Method, Plane]
    ) -> None:
        """Step 4: log, flag, and answer as though the endpoint did not exist."""
        candidate, owning_plane = foreign
        logger.warning(
            "plane_mismatch",
            uri_template=template,
            method=req.method,
            endpoint_plane=plane,
            credential_method=candidate,
            credential_plane=owning_plane,
        )
        if self._on_plane_mismatch is not None:
            self._on_plane_mismatch(template, plane, candidate)
        raise self._not_found_error()

    def _stamp(
        self, req: Any, plane: Plane, method: Method | None, principal: Any | None
    ) -> None:
        setattr(req.context, PLANE_ATTR, plane)
        setattr(req.context, AUTH_METHOD_ATTR, method)
        setattr(req.context, AUTH_PRINCIPAL_ATTR, principal)

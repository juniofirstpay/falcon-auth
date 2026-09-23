"""Tests for the plane registry and the mount wrapper.

Every assertion here is a startup failure rather than a request-time one, which is the point of
the module: a plane arrangement that cannot be enforced should be a wiring error a human sees,
not a route whose denial semantics depend on which decorator ran last.
"""

import falcon.asgi
import falcon.inspect
import pytest

from falcon_auth import planes
from falcon_auth.adapters.routing import (
    DEFAULT_PROBE_PATHS,
    Endpoint,
    PlaneConflict,
    PlaneRegistry,
    UnregisteredRoute,
    mount,
    responder_methods,
    verify_app,
)


class OrdersResource:
    async def on_get(self, req, resp): ...
    async def on_post(self, req, resp): ...


class RefundResource:
    async def on_post_refund(self, req, resp): ...


class ProbeResource:
    async def on_get(self, req, resp): ...


@pytest.fixture
def app():
    return falcon.asgi.App()


@pytest.fixture
def registry():
    return PlaneRegistry()


# ── what mount records ────────────────────────────────────────────────────────


def test_mount_records_every_method_the_resource_answers(app, registry):
    """Derived from the resource, never restated at the call site -- which is what stops the
    plane record drifting the day someone adds an `on_post` to an existing class."""
    mount(registry, app, "/v1/orders", OrdersResource(), plane=planes.USER)
    assert registry.plane_of("GET", "/v1/orders") == planes.USER
    assert registry.plane_of("POST", "/v1/orders") == planes.USER
    assert len(registry) == 2


def test_a_suffixed_responder_is_found(app, registry):
    mount(registry, app, "/v1/orders/{oid}:refund", RefundResource(),
          plane=planes.SERVICE, suffix="refund")
    assert registry.plane_of("POST", "/v1/orders/{oid}:refund") == planes.SERVICE


def test_mounting_a_suffix_the_resource_does_not_answer_is_a_mistake(app, registry):
    with pytest.raises(PlaneConflict, match="no matching on_<method> responder"):
        mount(registry, app, "/v1/x", RefundResource(), plane=planes.USER, suffix="nope")


def test_responder_methods_ignores_suffixed_members_when_no_suffix_asked():
    class Both:
        async def on_get(self, req, resp): ...
        async def on_get_refund(self, req, resp): ...

    assert responder_methods(Both()) == ["GET"]
    assert responder_methods(Both(), "refund") == ["GET"]


# ── one endpoint, one plane ───────────────────────────────────────────────────


def test_the_same_endpoint_on_two_planes_is_refused(app, registry):
    """The original conflict: an endpoint reachable on two planes is reachable by two principal
    types, and the second is rarely intended."""
    mount(registry, app, "/v1/orders", OrdersResource(), plane=planes.USER)
    with pytest.raises(PlaneConflict, match="already registered on the USER plane"):
        registry.register(planes.SERVICE, "GET", "/v1/orders", OrdersResource)


def test_re_registering_the_same_endpoint_on_the_same_plane_is_fine(registry):
    registry.register(planes.USER, "GET", "/v1/orders", OrdersResource)
    registry.register(planes.USER, "GET", "/v1/orders", OrdersResource)
    assert len(registry) == 1


# ── one CLASS, one plane -- the rule persona's registry could not see ─────────


def test_one_resource_class_may_not_serve_two_planes(registry):
    """C-006. Falcon binds an INSTANCE answering many endpoints through suffixed responders, so
    pinning (method, path) is not enough: a class spanning two planes is kept apart only by
    suffix dispatch, with nothing to notice when a bare responder is added later."""
    registry.register(planes.USER, "GET", "/v1/orders", OrdersResource)
    with pytest.raises(PlaneConflict, match="already serves the USER plane"):
        registry.register(planes.SERVICE, "POST", "/v1/internal/orders", OrdersResource)


def test_the_class_rule_fires_even_on_a_different_path(registry):
    """Which is exactly the case a (method, path) registry misses."""
    registry.register(planes.SERVICE, "POST", "/v1/a", RefundResource)
    with pytest.raises(PlaneConflict, match="split it into two classes"):
        registry.register(planes.CALLBACK, "POST", "/v1/b", RefundResource)


def test_one_class_may_serve_many_endpoints_on_its_own_plane(registry):
    registry.register(planes.USER, "GET", "/v1/orders", OrdersResource)
    registry.register(planes.USER, "POST", "/v1/orders", OrdersResource)
    registry.register(planes.USER, "GET", "/v1/orders/{oid}", OrdersResource)
    assert registry.plane_of_class(OrdersResource) == planes.USER


def test_one_class_may_not_serve_two_api_versions(registry):
    """Same shape as the plane rule: one object, two contracts, and nothing to notice when a
    responder is added."""
    registry.register(planes.USER, "GET", "/v1/orders", OrdersResource)
    with pytest.raises(PlaneConflict, match="already serves API version 'v1'"):
        registry.register(planes.USER, "GET", "/v2/orders", OrdersResource)


def test_the_version_rule_survives_an_unversioned_first_mount(registry):
    """The class pin is whichever endpoint registered FIRST, and that one may carry no version
    segment. Reading the version off the pin left it None forever, so every later version
    compared equal to "no version" and passed -- a class first mounted unversioned could then
    serve v1 and v2 both. The version is tracked separately for exactly this."""
    registry.register(planes.CALLBACK, "POST", "/webhooks/sms", RefundResource)
    registry.register(planes.CALLBACK, "POST", "/v1/hooks", RefundResource)
    with pytest.raises(PlaneConflict, match="already serves API version 'v1'"):
        registry.register(planes.CALLBACK, "POST", "/v2/hooks", RefundResource)


def test_an_unversioned_path_may_sit_beside_a_versioned_one(registry):
    """No version segment is not a contract claim, so it conflicts with nothing."""
    registry.register(planes.USER, "GET", "/v1/orders", OrdersResource)
    registry.register(planes.USER, "GET", "/orders-legacy", OrdersResource)
    assert len(registry) == 2


# ── PUBLIC carries a reason ───────────────────────────────────────────────────


def test_a_public_route_without_a_reason_is_refused(registry):
    """"No credential" is a decision somebody made on purpose, and it is recorded next to the
    route (RUL-035)."""
    with pytest.raises(PlaneConflict, match="PUBLIC but carries no reason"):
        registry.register(planes.PUBLIC, "GET", "/v1/status", ProbeResource)


def test_a_blank_reason_does_not_count(registry):
    with pytest.raises(PlaneConflict, match="PUBLIC but carries no reason"):
        registry.register(planes.PUBLIC, "GET", "/v1/status", ProbeResource, reason="   ")


def test_public_routes_are_reportable_with_their_reasons(app, registry):
    """The answer to the question an auditor actually asks, without reading the route table."""
    mount(registry, app, "/v1/terms", ProbeResource(), plane=planes.PUBLIC,
          reason="unauthenticated by design: served before any account exists")
    assert registry.public_routes() == {
        Endpoint("GET", "/v1/terms"): "unauthenticated by design: served before any account exists"
    }


def test_a_reason_is_not_demanded_of_other_planes(registry):
    registry.register(planes.USER, "GET", "/v1/orders", OrdersResource)
    assert registry.plane_of("GET", "/v1/orders") == planes.USER


# ── dev-only routes ───────────────────────────────────────────────────────────


def test_a_dev_route_does_not_mount_by_default(app, registry):
    """Skipped entirely rather than mounted behind a runtime check: a route that exists is a
    route that can be reached."""
    mounted = mount(registry, app, "/v1/debug", OrdersResource(), plane=planes.USER,
                    dev_only=True)
    assert mounted is False
    assert len(registry) == 0
    assert [r.path for r in falcon.inspect.inspect_routes(app)] == []


def test_a_dev_route_mounts_where_they_are_allowed(app):
    registry = PlaneRegistry(allow_dev_routes=True)
    assert mount(registry, app, "/v1/debug", OrdersResource(), plane=planes.USER,
                 dev_only=True) is True
    assert registry.plane_of("GET", "/v1/debug") == planes.USER


def test_allow_dev_routes_defaults_to_closed():
    assert PlaneRegistry().allow_dev_routes is False


# ── ordering: a conflict leaves no route behind ───────────────────────────────


def test_a_conflicting_mount_does_not_add_the_route(app, registry):
    """Register before add_route. Otherwise a rejected mount leaves the app serving a route the
    registry disowns -- which is precisely a route with no plane."""
    mount(registry, app, "/v1/orders", OrdersResource(), plane=planes.USER)
    with pytest.raises(PlaneConflict):
        mount(registry, app, "/v1/other", OrdersResource(), plane=planes.SERVICE)
    assert [r.path for r in falcon.inspect.inspect_routes(app)] == ["/v1/orders"]


# ── the boot sweep ────────────────────────────────────────────────────────────


def test_verify_app_passes_when_everything_went_through_mount(app, registry):
    mount(registry, app, "/v1/orders", OrdersResource(), plane=planes.USER)
    mount(registry, app, "/v1/orders/{oid}:refund", RefundResource(),
          plane=planes.SERVICE, suffix="refund")
    verify_app(app, registry)


def test_verify_app_catches_a_bare_add_route(app, registry):
    """The failure the registry cannot see from the inside: a route that never reached it has
    no plane, so nothing can be required of its callers."""
    mount(registry, app, "/v1/orders", OrdersResource(), plane=planes.USER)
    app.add_route("/v1/sneaky", OrdersResource())
    with pytest.raises(UnregisteredRoute, match="/v1/sneaky"):
        verify_app(app, registry)


def test_verify_app_names_every_offender_at_once(app, registry):
    app.add_route("/v1/a", OrdersResource())
    app.add_route("/v1/b", ProbeResource())
    with pytest.raises(UnregisteredRoute) as excinfo:
        verify_app(app, registry)
    message = str(excinfo.value)
    assert "/v1/a" in message and "/v1/b" in message


def test_verify_app_ignores_falcons_own_405_responders(app, registry):
    """Falcon reports all 24 HTTP methods per route because it generates a 405 responder for
    each one the class does not implement. Counting those would flag every route on the app."""
    mount(registry, app, "/v1/orders", OrdersResource(), plane=planes.USER)
    verify_app(app, registry)  # OrdersResource answers GET and POST only


def test_probe_paths_are_outside_the_plane_system(app, registry):
    """They answer the platform's probe, not a caller -- so they are exempt rather than PUBLIC.
    PUBLIC would say "a caller may reach this without a credential", a different statement."""
    app.add_route("/healthz", ProbeResource())
    app.add_route("/readyz", ProbeResource())
    verify_app(app, registry)
    assert registry.public_routes() == {}


def test_a_service_may_name_its_probes_differently(app, registry):
    app.add_route("/-/live", ProbeResource())
    with pytest.raises(UnregisteredRoute):
        verify_app(app, registry)
    verify_app(app, registry, exempt_paths=frozenset({"/-/live"}))


def test_the_default_probe_paths_are_the_documented_two():
    assert DEFAULT_PROBE_PATHS == {"/healthz", "/readyz"}


# ── lookups fail safe ─────────────────────────────────────────────────────────


def test_an_unregistered_route_has_no_plane_which_is_not_public(registry):
    """`None` means "unknown to the registry", never "reachable without a credential"."""
    assert registry.plane_of("GET", "/v1/nothing") is None
    assert registry.plane_of("GET", "/v1/nothing") != planes.PUBLIC


def test_an_unknown_plane_is_refused(registry):
    with pytest.raises(PlaneConflict, match="unknown plane"):
        registry.register("ADMIN", "GET", "/v1/x", OrdersResource)


# ── C-039 version extraction ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/v1/orders", "v1"),
        ("/v12/orders", "v12"),
        ("v1/orders", "v1"),
        ("/orders/v1", None),
        ("/webhooks/sms", None),
        ("/healthz", None),
        ("/version/x", None),
    ],
)
def test_the_version_is_the_first_path_segment(path, expected):
    """C-039. A `v1` deeper in the path is not a version segment, and `/version/x` is a noun."""
    from falcon_auth.adapters.routing import version_of

    assert version_of(path) == expected

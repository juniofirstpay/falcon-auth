"""falcon-auth#38 / RUL-206: the route-table lint -- advisory, from verify_app.

    L1  plane prefix after the version (C-051 §4)          warning, never a refusal (C-051 §6)
    L4  lowercase-hyphenated literals and verbs (C-068 §1)  warning until persona renames (#213)
    L5  `mock` only for a dev/test route (C-051 §4)          warning
    L2, L3 (RUL-178, C-039) still refuse at mount -- unchanged.
"""
from __future__ import annotations

import falcon.asgi
import pytest
from structlog.testing import capture_logs

from falcon_auth import planes
from falcon_auth.adapters.routing import PlaneRegistry, lint_routes, mount, verify_app


class _R:
    async def on_get(self, req, resp): ...


def _app(routes, *, dev=False):
    registry, app = PlaneRegistry(allow_dev_routes=dev), falcon.asgi.App()
    for path, plane, kw in routes:
        cls = type(f"R{abs(hash((path, plane)))}", (_R,), {})   # one class per route (C-006)
        extra = {"reason": "r"} if plane == planes.PUBLIC else {}
        if plane == planes.USER:
            extra["actor_types"] = kw.pop("actor_types", {"CUSTOMER"})
        mount(registry, app, path, cls(), plane=plane, **extra, **kw)
    return app, registry


def _checks(routes, **kw):
    _, registry = _app(routes, **kw)
    return {(f.check, f.route) for f in lint_routes(registry).findings}


# ─── a conforming table is silent ────────────────────────────────────────────


def test_a_conforming_table_reports_nothing():
    app, registry = _app([
        ("/v1/orders/{order_id}:refund-request", planes.USER, {}),
        ("/v1/ops/refunds", planes.USER, {"actor_types": {"OPERATOR"}}),
        ("/v1/svc/orders/{id}", planes.SERVICE, {}),
        ("/v1/callbacks/paytm", planes.CALLBACK, {}),
        ("/v1/public/terms", planes.PUBLIC, {}),
        ("/.well-known/jwks.json", planes.PUBLIC, {}),
        ("/v1/mock/webview", planes.PUBLIC, {"dev_only": True}),
    ], dev=True)
    with capture_logs() as logs:
        report = verify_app(app, registry)
    assert not report and not [e for e in logs if e["event"] == "route_lint"]


# ─── L1: the prefix names the plane ──────────────────────────────────────────


@pytest.mark.parametrize("path, plane, kw", [
    ("/v1/orders/{id}", planes.SERVICE, {}),                       # SERVICE without svc
    ("/v1/internal/sessions", planes.SERVICE, {}),                  # auth's old /internal/
    ("/v1/webhooks/paytm", planes.CALLBACK, {}),                    # CALLBACK without callbacks
    ("/v1/redirects/digilocker", planes.PUBLIC, {}),                # persona's /redirects/
    ("/v1/svc/orders", planes.USER, {}),                            # USER under another's prefix
    ("/v1/ops/orders", planes.USER, {"actor_types": {"CUSTOMER", "OPERATOR"}}),
])
def test_a_prefix_naming_the_wrong_plane_warns(path, plane, kw):
    assert {c for c, _ in _checks([(path, plane, kw)])} == {"L1"}


def test_l1_never_refuses_start():
    app, registry = _app([("/v1/orders", planes.SERVICE, {})])
    with capture_logs() as logs:
        report = verify_app(app, registry)
    (finding,) = report.by_check("L1")
    assert finding.rule == "C-051 §4" and "svc" in finding.detail
    assert [e["route"] for e in logs if e["event"] == "route_lint"] == ["GET /v1/orders"]


# ─── L4: casing ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", [
    "/v1/persons/{ref}:kycStatus",               # persona's verbs, C-068's own list
    "/v1/onboarding/{ref}/tasks:panVerification",
    "/v1/ckyc/{ref}:generate_otp",
    "/v1/Orders",
])
def test_a_camel_case_or_snake_case_literal_warns(path):
    assert ("L4", f"GET {path}") in _checks([(path, planes.USER, {})])


def test_path_parameters_and_their_converters_are_out_of_scope():
    assert not _checks([("/v1/orders/{order_id:int}/items/{itemRef}", planes.USER, {})])


def test_the_finding_names_the_bad_pieces():
    _, registry = _app([("/v1/persons/{ref}:kycStatus", planes.USER, {})])
    (finding,) = lint_routes(registry).by_check("L4")
    assert finding.rule == "C-068 §1" and "'kycStatus'" in finding.detail


# ─── L5: mock is dev/test only ───────────────────────────────────────────────


def test_a_mock_route_that_is_not_dev_only_warns():
    assert {c for c, _ in _checks([("/v1/mock/webview", planes.PUBLIC, {})])} == {"L5"}


def test_a_dev_only_route_outside_mock_warns():
    """Persona's `/internal/invite-intents:consume`: a dev-only mock on PUBLIC -- a label that lies."""
    checks = _checks([("/v1/public/invite-intents:consume", planes.PUBLIC, {"dev_only": True})],
                     dev=True)
    assert {c for c, _ in checks} == {"L5"}


# ─── out of scope ────────────────────────────────────────────────────────────


def test_a_vendor_held_callback_alias_is_not_linted():
    """Its path is the vendor's registered URL; RUL-211 retires it before go-live."""
    registry, app = PlaneRegistry(), falcon.asgi.App()
    hook = type("Hook", (_R,), {})()
    mount(registry, app, "/v1/callbacks/paytm", hook, plane=planes.CALLBACK)
    mount(registry, app, "/paytmCallback", hook, plane=planes.CALLBACK,
          alias_of="/v1/callbacks/paytm")
    assert not lint_routes(registry)


def test_methods_on_one_path_are_one_finding():
    class Both:
        async def on_get(self, req, resp): ...
        async def on_post(self, req, resp): ...

    registry, app = PlaneRegistry(), falcon.asgi.App()
    mount(registry, app, "/v1/orders", Both(), plane=planes.SERVICE)
    assert [f.route for f in lint_routes(registry).findings] == ["GET,POST /v1/orders"]

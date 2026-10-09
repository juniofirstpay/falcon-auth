"""falcon-auth#17 items 3-4: C-052 actor types and C-053 grant kinds / Subject-Ref.

Readings implemented (ruled: RUL-158, RUL-162, RUL-177, RUL-178; the rest put to the platform):
    actor type not admitted                      404 PLAT0006, as the host's router miss
    customer route, no Subject-Ref               `self` grants
    customer route, Subject-Ref                  live `subject` delegations for that subject
    OPERATOR-only route                          `unbound` grants; a Subject-Ref is refused
    operator on a customer route                 only as a SHADOW session (C-053 §9)
    shadow session                               must name its delegation's subject (H2)
    every subject refusal                        one 404 PLAT0008, byte-identical
    grant outside the session's actor type       503 (C-052 §7)
"""
from __future__ import annotations

from dataclasses import replace

import falcon
import falcon.asgi
import falcon.testing
import pytest
from structlog.testing import capture_logs

from falcon_auth import planes
from falcon_auth.adapters import (
    PlaneAuthenticationMiddleware,
    PlaneConflict,
    PlaneRegistry,
    UnregisteredRoute,
    mount,
    register_error_handlers,
)
from falcon_auth.adapters.authenticators import CustomAuthenticator, Selector
from falcon_auth.adapters.hooks import require
from falcon_auth.entitlement import build_enforcer
from falcon_auth.entitlement.grants import GrantRow, select
from falcon_auth.errors import ActorTypeNotAdmitted, AuthzUnavailable, SubjectNotReachable
from falcon_auth.principal import Principal
from falcon_auth.trustcontext import Delegation

GRANTS = {
    "CUSTOMER_GRANT": GrantRow("CUSTOMER", "self"),
    "DELEGATED_CUSTOMER_GRANT": GrantRow("CUSTOMER", "subject"),
    "CUSTOMER_IMPERSONATION_GRANT": GrantRow("OPERATOR", "subject", "AGENT"),
    "AGENT_GRANT": GrantRow("OPERATOR", "unbound", "AGENT"),
}
FUTURE, PAST = "2099-01-01T00:00:00.000Z", "2000-01-01T00:00:00.000Z"


def dlg(subject, grant="DELEGATED_CUSTOMER_GRANT", until=FUTURE, ref="dlg_1", case=None):
    return Delegation(ref=ref, grant=grant, subject_ref=subject, valid_until=until, case_ref=case)


CUSTOMER = Principal(user_ref="u-1", entitlements=["CUSTOMER_GRANT"], actor_type="CUSTOMER",
                     session_kind="NORMAL", delegations=(dlg("u-2"), dlg("u-3", until=PAST)))
OPERATOR = Principal(user_ref="op-1", entitlements=["AGENT_GRANT"], actor_type="OPERATOR",
                     actor_kind="AGENT", session_kind="NORMAL")
SHADOW = Principal(user_ref="op-1", entitlements=[], actor_type="OPERATOR", actor_kind="AGENT",
                   session_kind="SHADOW",
                   delegations=(dlg("u-9", "CUSTOMER_IMPERSONATION_GRANT", ref="dlg_s", case="c-1"),))
BOTH = {"CUSTOMER", "OPERATOR"}


def sel(principal, admitted, header=None):
    return select(principal, admitted=admitted, subject_header=header, grants=GRANTS)


# ─── select(): the rules on their own ────────────────────────────────────────


def test_a_customer_without_subject_ref_uses_only_self_grants():
    s = sel(CUSTOMER, BOTH)
    assert (s.grants, s.subject_ref) == (["CUSTOMER_GRANT"], None)


def test_a_subject_ref_uses_only_live_delegations_for_that_subject():
    s = sel(CUSTOMER, BOTH, "u-2")
    assert s.grants == ["DELEGATED_CUSTOMER_GRANT"] and s.subject_ref == "u-2"
    assert s.delegation_for == {"DELEGATED_CUSTOMER_GRANT": "dlg_1"}
    assert "CUSTOMER_GRANT" not in s.grants          # ⛔ kinds never mix (C-053 §3)


@pytest.mark.parametrize("subject", ["u-404", "u-3"], ids=["unknown", "expired-delegation"])
def test_an_unreachable_subject_is_one_refusal(subject):
    with pytest.raises(SubjectNotReachable):
        sel(CUSTOMER, BOTH, subject)


def test_an_actor_type_the_route_does_not_admit_is_refused():
    with pytest.raises(ActorTypeNotAdmitted):
        sel(CUSTOMER, {"OPERATOR"})


def test_an_assumed_customer_never_opens_an_operator_route():
    """RUL-162: under the C-052 §3 deviation, operator-only routes always refuse."""
    with pytest.raises(ActorTypeNotAdmitted):
        sel(replace(CUSTOMER, actor_type_assumed=True), {"OPERATOR"})


def test_an_operator_only_route_counts_unbound_grants():
    assert sel(OPERATOR, {"OPERATOR"}).grants == ["AGENT_GRANT"]


def test_a_subject_ref_on_an_operator_only_route_is_refused():
    """RUL-177: kinds never mix."""
    with pytest.raises(SubjectNotReachable):
        sel(OPERATOR, {"OPERATOR"}, "u-2")


def test_an_operator_on_a_customer_route_must_be_a_shadow_session():
    """C-053 §9."""
    with pytest.raises(ActorTypeNotAdmitted):
        sel(OPERATOR, BOTH)


def test_a_shadow_session_naming_its_subject_uses_its_delegation():
    s = sel(SHADOW, BOTH, "u-9")
    assert s.grants == ["CUSTOMER_IMPERSONATION_GRANT"]
    assert s.delegation_for["CUSTOMER_IMPERSONATION_GRANT"] == "dlg_s"


@pytest.mark.parametrize("header", [None, "u-2"], ids=["missing", "another-subject"])
def test_a_shadow_session_without_its_subject_is_refused(header):
    """H2: answered as H4."""
    with pytest.raises(SubjectNotReachable):
        sel(SHADOW, BOTH, header)


@pytest.mark.parametrize(
    "principal",
    [
        replace(CUSTOMER, entitlements=["AGENT_GRANT"]),
        replace(CUSTOMER, entitlements=["NOT_REGISTERED"]),
    ],
    ids=["grant-of-another-actor-type", "unregistered-grant"],
)
def test_a_grant_outside_the_session_actor_type_is_a_503(principal):
    """C-052 §7: a configuration mismatch, not the caller's fault."""
    with pytest.raises(AuthzUnavailable):
        sel(principal, BOTH)


def test_a_delegation_carrying_a_non_subject_grant_is_a_503():
    bad = replace(CUSTOMER, delegations=(dlg("u-2", grant="CUSTOMER_GRANT"),))
    with pytest.raises(AuthzUnavailable):
        sel(bad, BOTH, "u-2")


# ─── declaration at mount (C-052 §5, §8; RUL-178) ────────────────────────────


class _R:
    async def on_get(self, req, resp):
        resp.media = {}


@pytest.mark.parametrize(
    "path, plane, actor_types, match",
    [
        ("/v1/x", planes.USER, set(), "never 'any'"),
        ("/v1/x", planes.USER, {"SERVICE"}, "C-052 §2"),
        ("/v1/refunds", planes.USER, {"OPERATOR"}, "/v<n>/ops/"),
        ("/v1/x", planes.PUBLIC, {"CUSTOMER"}, "no actor type"),
    ],
    ids=["empty", "wrong-plane-type", "operator-only-outside-ops", "public"],
)
def test_a_bad_declaration_refuses_to_mount(path, plane, actor_types, match):
    with pytest.raises(PlaneConflict, match=match):
        mount(PlaneRegistry(), falcon.asgi.App(), path, _R(), plane=plane,
              actor_types=actor_types, reason="r")


def test_an_operator_only_route_under_ops_mounts():
    mount(PlaneRegistry(), falcon.asgi.App(), "/v1/ops/refunds", _R(), plane=planes.USER,
          actor_types={"OPERATOR"})


def test_a_user_route_without_actor_types_refuses_to_start():
    registry = PlaneRegistry()
    mw = PlaneAuthenticationMiddleware(registry, authenticators={planes.JWT: _jwt()})
    app = falcon.asgi.App(middleware=[mw])
    mount(registry, app, "/v1/x", _R(), plane=planes.USER)
    with pytest.raises(UnregisteredRoute, match="C-052"):
        mw.verify()
    assert falcon.testing.TestClient(app).simulate_get(
        "/v1/x", headers={"Authorization": "u"}).status_code == 500


def test_require_needs_the_grant_register():
    with pytest.raises(ValueError, match="grant register"):
        require(build_enforcer({"orders:read": "ORDER_READ"}), _Resolver({}), "orders:read")


# ─── end to end ──────────────────────────────────────────────────────────────

REGISTRY = {"orders:read": "ORDER_READ", "refunds:create": "REFUND_CREATE"}
EXPANSION = {
    "CUSTOMER_GRANT": ["ORDER_READ"],
    "DELEGATED_CUSTOMER_GRANT": ["ORDER_READ"],
    "CUSTOMER_IMPERSONATION_GRANT": ["ORDER_READ"],
    "AGENT_GRANT": ["REFUND_CREATE"],
}
WHO = {"customer": CUSTOMER, "operator": OPERATOR, "shadow": SHADOW,
       "mismatch": replace(CUSTOMER, entitlements=["AGENT_GRANT"])}


def _jwt():
    async def attempt(req):
        who = req.get_header("Authorization")
        if who is None:
            return None
        req.context.user = type("U", (), {"id": who})()
        return who

    return CustomAuthenticator(attempt, plane=planes.USER, method=planes.JWT,
                               selector=Selector("Authorization"))


class _Resolver:
    def __init__(self, who):
        self._who = who

    async def resolve(self, user, *, consequential=False):
        return self._who[user.id]


def _client():
    enforcer = build_enforcer(REGISTRY, expansion=EXPANSION, grants=GRANTS)
    registry = PlaneRegistry()
    app = falcon.asgi.App(middleware=[
        PlaneAuthenticationMiddleware(registry, authenticators={planes.JWT: _jwt()})])
    register_error_handlers(app)

    async def router_miss(req, resp, ex, params):            # the host's C-001 serializer
        resp.status, resp.media = falcon.HTTP_404, {
            "code": "PLAT0006", "message": "The requested resource was not found."}

    app.add_error_handler(falcon.HTTPRouteNotFound, router_miss)

    def view(capability):
        class V:
            @falcon.before(require(enforcer, _Resolver(WHO), capability))
            async def on_get(self, req, resp):
                p = req.context.principal
                resp.media = {"opened_by": p.opened_by, "subject_ref": p.subject_ref,
                              "delegation": p.opened_by_delegation}

        return V

    mount(registry, app, "/v1/orders", view("orders:read")(), plane=planes.USER,
          actor_types=BOTH)
    mount(registry, app, "/v1/ops/refunds", view("refunds:create")(), plane=planes.USER,
          actor_types={"OPERATOR"})
    return falcon.testing.TestClient(app)


def get(path, who, subject=None):
    headers = {"Authorization": who}
    if subject is not None:
        headers["Subject-Ref"] = subject
    with capture_logs():
        return _client().simulate_get(path, headers=headers)


def test_a_customer_reads_their_own():
    r = get("/v1/orders", "customer")
    assert r.status_code == 200 and r.json == {
        "opened_by": "CUSTOMER_GRANT", "subject_ref": None, "delegation": None}


def test_a_customer_reads_a_delegated_subject_and_the_response_varies():
    r = get("/v1/orders", "customer", "u-2")
    assert r.json == {"opened_by": "DELEGATED_CUSTOMER_GRANT", "subject_ref": "u-2",
                      "delegation": "dlg_1"}
    assert "Subject-Ref" in r.headers["Vary"]                  # H5


def test_unknown_and_undelegated_subjects_answer_byte_identically():
    unknown, expired = get("/v1/orders", "customer", "u-404"), get("/v1/orders", "customer", "u-3")
    assert unknown.status_code == expired.status_code == 404
    assert unknown.content == expired.content
    assert unknown.json["code"] == "PLAT0008"


def test_a_customer_on_an_operator_route_gets_the_router_miss():
    wrong_actor = get("/v1/ops/refunds", "customer")
    router_miss = _client().simulate_get("/v1/nowhere")
    assert wrong_actor.status_code == 404 and wrong_actor.content == router_miss.content


def test_an_operator_opens_an_ops_route_by_an_unbound_grant():
    assert get("/v1/ops/refunds", "operator").json["opened_by"] == "AGENT_GRANT"


def test_a_subject_ref_on_an_ops_route_is_the_subject_refusal():
    r = get("/v1/ops/refunds", "operator", "u-2")
    assert r.status_code == 404 and r.json["code"] == "PLAT0008"


def test_an_operator_normal_session_on_a_customer_route_gets_the_router_miss():
    assert get("/v1/orders", "operator").json["code"] == "PLAT0006"


def test_a_shadow_session_reads_its_subject():
    r = get("/v1/orders", "shadow", "u-9")
    assert r.json == {"opened_by": "CUSTOMER_IMPERSONATION_GRANT", "subject_ref": "u-9",
                      "delegation": "dlg_s"}


def test_a_shadow_session_without_its_subject_is_the_subject_refusal():
    assert get("/v1/orders", "shadow").json["code"] == "PLAT0008"


def test_a_grant_outside_the_actor_type_is_a_503():
    r = get("/v1/orders", "mismatch")
    assert r.status_code == 503 and r.json["code"] == "PLAT0302"

"""falcon-auth#29 / RUL-193: `delegations[].valid_until` is nullable, and the GRANT decides.

    D1  `null` = no time bound; it ends only when auth stops emitting the delegation
    D2  `registry/GRANTS.md`'s *time bound*: DELEGATED_CUSTOMER_GRANT optional; the two
        impersonation grants required
    D3  `null` on a required grant: that delegation counts as none -- H4's 404 PLAT0008,
        ⛔ never perpetual, ⛔ never a session-wide 503
"""
from __future__ import annotations

import pytest
from structlog.testing import capture_logs

from falcon_auth.entitlement.grants import GrantRow, normalise_grants, select
from falcon_auth.errors import SubjectNotReachable
from falcon_auth.principal import Principal
from falcon_auth.trustcontext import Delegation, TrustContext

# registry/GRANTS.md at v34, the rows this file needs.
GRANTS = {
    "CUSTOMER_GRANT": GrantRow("CUSTOMER", "self"),
    "DELEGATED_CUSTOMER_GRANT": GrantRow("CUSTOMER", "subject", time_bound="optional"),
    "CUSTOMER_IMPERSONATION_GRANT": GrantRow("OPERATOR", "subject", "AGENT", "required"),
}
FUTURE = "2099-01-01T00:00:00.000Z"
FEED = {
    "session_ref": "s", "user_ref": "u-1", "client_ref": "c", "device_ref": None,
    "session_state": 1, "device_trust_level": 3, "session_trust_level": 1,
    "trust_elevated_until": None, "grants": ["CUSTOMER_GRANT"], "actor_type": "CUSTOMER",
    "session_kind": "NORMAL",
}


def dlg(grant="DELEGATED_CUSTOMER_GRANT", until=None, subject="u-2", ref="dlg_1", case=None):
    return Delegation(ref=ref, grant=grant, subject_ref=subject, valid_until=until, case_ref=case)


def customer(*delegations):
    return Principal(user_ref="u-1", entitlements=["CUSTOMER_GRANT"], actor_type="CUSTOMER",
                     session_kind="NORMAL", delegations=delegations)


def shadow(delegation):
    return Principal(user_ref="op-1", entitlements=[], actor_type="OPERATOR",
                     actor_kind="AGENT", session_kind="SHADOW", delegations=(delegation,))


# ─── D1: the feed parses a null ───────────────────────────────────────────────


def test_a_null_valid_until_parses_and_is_live():
    """Before: a null failed the parse and every gated route of the session answered 503
    (persona#189, staging)."""
    ctx = TrustContext.model_validate({**FEED, "delegations": [
        {"ref": "dlg_1", "grant": "DELEGATED_CUSTOMER_GRANT", "subject_ref": "u-2",
         "valid_until": None}]})
    assert ctx.delegations[0].valid_until is None and ctx.delegations[0].live()


def test_valid_until_is_still_required():
    """Nullable, not optional: a missing key is still a broken feed (S4)."""
    with pytest.raises(ValueError):
        TrustContext.model_validate({**FEED, "delegations": [
            {"ref": "dlg_1", "grant": "DELEGATED_CUSTOMER_GRANT", "subject_ref": "u-2"}]})


def test_a_present_value_is_still_c009():
    with pytest.raises(ValueError, match="C-009"):
        dlg(until="2099-01-01T00:00:00+05:30")


# ─── D2/D3: the grant decides ────────────────────────────────────────────────


def test_null_on_an_optional_grant_is_a_perpetual_delegation():
    s = select(customer(dlg()), admitted={"CUSTOMER"}, subject_header="u-2", grants=GRANTS)
    assert s.grants == ["DELEGATED_CUSTOMER_GRANT"] and s.delegation_for == {
        "DELEGATED_CUSTOMER_GRANT": "dlg_1"}


def test_null_on_a_required_grant_counts_as_no_delegation():
    """A shadow session whose impersonation grant came unbounded: 404 PLAT0008, logged."""
    p = shadow(dlg("CUSTOMER_IMPERSONATION_GRANT", subject="u-9", case="case-1"))
    with capture_logs() as logs, pytest.raises(SubjectNotReachable):
        select(p, admitted={"CUSTOMER", "OPERATOR"}, subject_header="u-9", grants=GRANTS)
    assert any(e["event"] == "delegation_unbounded_on_required_grant" for e in logs)


def test_the_same_grant_with_a_bound_is_served():
    p = shadow(dlg("CUSTOMER_IMPERSONATION_GRANT", until=FUTURE, subject="u-9", case="case-1"))
    s = select(p, admitted={"CUSTOMER", "OPERATOR"}, subject_header="u-9", grants=GRANTS)
    assert s.grants == ["CUSTOMER_IMPERSONATION_GRANT"]


def test_the_defect_is_scoped_to_its_delegation_never_the_session():
    """⛔ Never a session-wide 503: the customer's own grants, and a sound delegation to
    someone else, keep working."""
    bad = GrantRow("CUSTOMER", "subject", time_bound="required")
    grants = {**GRANTS, "BOUND_ONLY": bad}
    p = customer(dlg("BOUND_ONLY", subject="u-3", ref="dlg_bad"), dlg(subject="u-2"))
    assert select(p, admitted={"CUSTOMER"}, subject_header=None, grants=grants).grants == [
        "CUSTOMER_GRANT"]
    assert select(p, admitted={"CUSTOMER"}, subject_header="u-2", grants=grants).grants == [
        "DELEGATED_CUSTOMER_GRANT"]
    with pytest.raises(SubjectNotReachable):
        select(p, admitted={"CUSTOMER"}, subject_header="u-3", grants=grants)


def test_a_subject_row_that_declares_no_bound_reads_as_required():
    """Fail closed: a host that did not copy the column never gets a perpetual delegation."""
    grants = {**GRANTS, "DELEGATED_CUSTOMER_GRANT": GrantRow("CUSTOMER", "subject")}
    with pytest.raises(SubjectNotReachable):
        select(customer(dlg()), admitted={"CUSTOMER"}, subject_header="u-2", grants=grants)


# ─── the register row ────────────────────────────────────────────────────────


def test_only_a_subject_grant_has_a_time_bound():
    with pytest.raises(ValueError, match="only a subject grant"):
        GrantRow("CUSTOMER", "self", time_bound="optional")


def test_a_time_bound_is_optional_or_required():
    with pytest.raises(ValueError, match="time bound"):
        GrantRow("CUSTOMER", "subject", time_bound="sometimes")  # type: ignore[arg-type]


def test_the_tuple_form_carries_the_bound():
    rows = normalise_grants({"D": ("CUSTOMER", "subject", None, "optional")})
    assert rows["D"].unbounded_allowed

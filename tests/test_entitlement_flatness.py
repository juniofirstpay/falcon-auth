"""Tests for the build-time policy checks.

Both checks exist because the engine cannot make them itself, so the tests are written against
policies casbin would happily run.
"""

import pytest

from falcon_auth.entitlement.enforcer import build_enforcer
from falcon_auth.entitlement.flatness import (
    FlatnessError,
    UnregisteredGrant,
    check_flatness,
    check_grants_registered,
    verify_policy,
)

REGISTRY = {"orders:list": "ORDER_READ", "orders:create": "ORDER_CREATE"}


# ── flatness ──────────────────────────────────────────────────────────────────


def test_a_two_hop_expansion_passes():
    check_flatness({"RETAIL_USER": ["ORDER_READ", "ORDER_CREATE"]}, REGISTRY)


def test_an_empty_expansion_passes():
    """Which is the state today: nothing grants, so there are no rows."""
    check_flatness({}, REGISTRY)


def test_a_name_on_both_sides_is_refused():
    """A -> B and B -> C. casbin resolves A to C's capabilities and raises no objection, so the
    lint is the only thing standing between the policy and a third hop."""
    with pytest.raises(FlatnessError, match="BOTH sides"):
        check_flatness({"A": ["B"], "B": ["C"]}, REGISTRY)


def test_the_refused_policy_is_one_casbin_would_happily_run():
    """The point of the lint, demonstrated: the engine's verdict on the same rows is `allow`."""
    chained = build_enforcer({"x:read": "C"}, expansion={"A": ["B"], "B": ["C"]})
    assert chained.allows(["A"], "x:read"), "casbin chained it"
    with pytest.raises(FlatnessError):
        check_flatness({"A": ["B"], "B": ["C"]}, {"x:read": "C"})


def test_a_self_link_is_refused():
    with pytest.raises(FlatnessError, match="expand to themselves"):
        check_flatness({"A": ["A"]}, REGISTRY)


def test_a_name_used_as_both_grant_and_entitlement_is_refused():
    """GRANTS.md rule 4. The name would be in the platform register and in this service's
    vocabulary at once, and the two layers stop being distinguishable."""
    with pytest.raises(FlatnessError, match="as a grant AND as an entitlement"):
        check_flatness({"ORDER_READ": ["ORDER_CREATE"]}, REGISTRY)


def test_the_registry_check_is_skipped_when_no_registry_is_given():
    check_flatness({"ORDER_READ": ["ORDER_CREATE"]})


def test_every_offender_is_named_at_once():
    with pytest.raises(FlatnessError) as excinfo:
        check_flatness({"A": ["B"], "B": ["C"], "C": ["D"]}, REGISTRY)
    assert "B" in str(excinfo.value) and "C" in str(excinfo.value)


# ── the grant register ────────────────────────────────────────────────────────


def test_a_registered_grant_passes():
    check_grants_registered({"RETAIL_USER": ["ORDER_READ"]}, ["RETAIL_USER", "MERCHANT_USER"])


def test_an_unregistered_grant_refuses_boot():
    """Never resolved to "holds nothing" and allowed to continue -- that reads as a permissions
    problem and is really a deployment fault."""
    with pytest.raises(UnregisteredGrant, match="INVENTED"):
        check_grants_registered({"INVENTED": ["ORDER_READ"]}, ["RETAIL_USER"])


def test_an_empty_register_demands_an_empty_expansion():
    """The honest state today: the platform register is deliberately empty because nothing
    grants, so any `g` row at all is a row against a name nobody allocated."""
    check_grants_registered({}, [])
    with pytest.raises(UnregisteredGrant):
        check_grants_registered({"ANYTHING": ["ORDER_READ"]}, [])


# ── the combined entry point ──────────────────────────────────────────────────


def test_verify_policy_runs_both_checks():
    verify_policy(REGISTRY, {"RETAIL_USER": ["ORDER_READ"]}, grant_register=["RETAIL_USER"])


def test_verify_policy_catches_flatness_before_registration():
    """Flatness first: a chained policy is malformed whatever the register says."""
    with pytest.raises(FlatnessError):
        verify_policy(REGISTRY, {"A": ["B"], "B": ["C"]}, grant_register=["A", "B"])


def test_verify_policy_catches_an_unregistered_grant():
    with pytest.raises(UnregisteredGrant):
        verify_policy(REGISTRY, {"GHOST": ["ORDER_READ"]}, grant_register=[])


def test_omitting_the_register_skips_only_that_check():
    """A deliberate escape hatch for a host with no copy of the register, not a default anyone
    should settle for -- flatness is still enforced."""
    verify_policy(REGISTRY, {"GHOST": ["ORDER_READ"]})
    with pytest.raises(FlatnessError):
        verify_policy(REGISTRY, {"A": ["B"], "B": ["C"]})


def test_todays_configuration_passes_both():
    """No expansion, empty register -- what every service runs right now."""
    verify_policy(REGISTRY, grant_register=[])

"""Tests for the plane vocabulary.

These read as restatements of C-038 and C-060 (`v30`) on purpose. The map is the one place in the package where
a single wrong entry silently changes which credential opens which endpoint, and it has no
behaviour of its own to catch it -- so the convention is asserted directly.
"""

import pytest

from falcon_auth import planes
from falcon_auth.planes import (
    CALLBACK,
    EAST_WEST_KINDS,
    HMAC,
    JWT,
    METHODS_BY_PLANE,
    MTLS,
    ONE_SHOT_TOKEN,
    PLANES,
    PUBLIC,
    SERVICE,
    USER,
    methods_for,
    plane_for,
)


# ── the closed sets ─────────────────────────────────────────────────────────


def test_there_are_exactly_five_planes():
    """C-060 §1. CLIENT is the identity provider's pre-user plane."""
    assert PLANES == {"USER", "CLIENT", "SERVICE", "CALLBACK", "PUBLIC"}


def test_the_map_is_c060s_table():
    assert dict(METHODS_BY_PLANE) == {
        "USER": {"JWT"},
        "CLIENT": {"DPOP_PROOF", "REFERENCE_TOKEN", "ONE_SHOT_TOKEN"},
        "SERVICE": {"MTLS"},
        "CALLBACK": {"HMAC", "ONE_SHOT_TOKEN"},
        "PUBLIC": set(),
    }


def test_a_resource_service_never_mounts_client():
    """C-060 §2: CLIENT is mounted by the identity provider only, and the identity provider does
    not use this package (RUL-157)."""
    assert planes.RESOURCE_SERVICE_PLANES == PLANES - {"CLIENT"}


def test_the_wrong_plane_search_verifies_only_io_free_credentials():
    """C-060 §6: the TLS peer and a JWT's signature, expiry and audience -- nothing that needs a
    lookup."""
    assert planes.SEARCHABLE_METHODS == {"JWT", "MTLS"}


def test_every_plane_has_a_row_in_the_map():
    """A plane with no row would raise from `methods_for` at request time, not at boot."""
    assert set(METHODS_BY_PLANE) == PLANES


def test_the_method_set_is_closed_and_excludes_api_key():
    """The absence is load-bearing. An api-key caller is the shape that was removed from the
    entitlement resolver: it proposed its own grants, and no plane authenticates it."""
    assert set(planes.PLANE_BY_METHOD) == {"JWT", "MTLS", "HMAC", "ONE_SHOT_TOKEN"}
    assert "API_KEY" not in planes.PLANE_BY_METHOD


# ── the pinning ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("plane,method", [(USER, JWT), (SERVICE, MTLS)])
def test_user_and_service_are_pinned_to_exactly_one_method(plane, method):
    """One authentication method per plane is literal for these two. A second method here would
    let a request prove itself two ways -- and an attacker need satisfy only the weaker one."""
    assert methods_for(plane) == {method}


def test_callback_is_the_one_plane_carrying_two():
    """A source proves itself by signing the body or by presenting a token we minted, and the
    estate has both kinds of counterparty. C-031 still pins each individual SOURCE to one of
    them; this set is the union of what any source may use, not a per-request choice."""
    assert methods_for(CALLBACK) == {HMAC, ONE_SHOT_TOKEN}


def test_public_is_empty_not_none():
    """An empty set is a fact -- nothing authenticates here. `None` would be "unknown", and
    every caller would branch on it with the fail-open branch being the short one."""
    assert methods_for(PUBLIC) == frozenset()
    assert methods_for(PUBLIC) is not None


# ── the inverse, which the wrong-plane 404 depends on ───────────────────────


@pytest.mark.parametrize(
    "method,plane",
    [(JWT, USER), (MTLS, SERVICE), (HMAC, CALLBACK), (ONE_SHOT_TOKEN, CALLBACK)],
)
def test_each_method_names_exactly_one_plane(method, plane):
    """C-038 step 4: a VALID credential belonging to another plane gets a 404, body identical
    to a genuine not-found. "Another plane" is only answerable while this inverse is a
    function."""
    assert plane_for(method) == plane


def test_a_method_under_two_planes_refuses_to_build():
    """The guard, exercised. Were it absent, the wrong-plane 404 would quietly resolve to
    whichever plane the iteration happened to reach last."""
    with pytest.raises(ValueError, match="listed under two planes"):
        planes._invert({USER: frozenset({JWT}), PUBLIC: frozenset({JWT})})


def test_the_inverse_covers_every_resource_service_method():
    """Over all five planes ONE_SHOT_TOKEN has two homes; over a resource service's, one."""
    assert set(planes.PLANE_BY_METHOD) == {
        m for p, ms in METHODS_BY_PLANE.items() if p in planes.RESOURCE_SERVICE_PLANES for m in ms
    }
    assert planes.PLANE_BY_METHOD[ONE_SHOT_TOKEN] == CALLBACK


# ── lookups fail loudly ─────────────────────────────────────────────────────


def test_an_unknown_plane_raises_rather_than_reading_as_public():
    """The two facts are opposite: PUBLIC is a declaration, an unknown plane is a typo. Collapse
    them and a misspelled plane behaves exactly like the one that needs no credential."""
    with pytest.raises(ValueError, match="unknown plane"):
        methods_for("USERS")


def test_an_unknown_method_raises():
    with pytest.raises(ValueError, match="no resource-service plane"):
        plane_for("API_KEY")
    with pytest.raises(ValueError, match="no resource-service plane"):
        plane_for("REFERENCE_TOKEN")  # CLIENT's only


# ── the east-west seam ──────────────────────────────────────────────────────


def test_east_west_kinds_are_planes():
    """The `kind` on an allow-list row IS the caller's plane. Two vocabularies here would let a
    row be valid as a kind and unknown as a plane."""
    assert EAST_WEST_KINDS == {SERVICE, CALLBACK}
    assert EAST_WEST_KINDS <= PLANES


def test_the_user_and_public_planes_never_appear_in_an_allow_list():
    """An allow-list is keyed by CN, so only the cert-bearing planes belong in it."""
    assert USER not in EAST_WEST_KINDS
    assert PUBLIC not in EAST_WEST_KINDS


def test_adopting_this_module_changes_no_consumers_config():
    """The values are byte-identical to the `KIND_*` constants eastwest defined before, so no
    deployed allow-list YAML needs an edit."""
    from falcon_auth.eastwest.verifier import KIND_CALLBACK, KIND_SERVICE

    assert (KIND_SERVICE, KIND_CALLBACK) == ("SERVICE", "CALLBACK")
    assert KIND_SERVICE is SERVICE and KIND_CALLBACK is CALLBACK

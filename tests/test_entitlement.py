"""Tests for the entitlement layer: the enforcer, the resolver, and the gate.

Uses orders' real capability registry, so the fixtures are the estate's vocabulary rather
than invented names. Grant names are invented -- the platform register is deliberately empty
because nothing grants yet.
"""

import pytest

from falcon_auth.entitlement.enforcer import build_enforcer, normalise_registry
from falcon_auth.entitlement.resolver import AuthServiceResolver, GrantAllResolver
from falcon_auth.errors import AuthzUnavailable, CapabilityDenied, SessionMiss
from falcon_auth.principal import Principal
from falcon_auth.trustcontext import (
    NullCache,
    SESSION_TRUST_AUTHENTICATED,
    TrustContext,
    TrustContextCache,
)

# orders' real registry (app/hooks/authz.py) -- note the many-to-one shape and that
# tasks:deeplink is a GET requiring a WRITE entitlement, because it mints a payment link.
REGISTRY = {
    "orders:validate": "ORDER_CREATE",
    "orders:create": "ORDER_CREATE",
    "orders:list": "ORDER_READ",
    "orders:read": "ORDER_READ",
    "tasks:list": "TASK_READ",
    "tasks:read": "TASK_READ",
    "tasks:deeplink": "ORDER_CREATE",
    "orders:read_any": "ORDER_READ_ANY",
}

CTX = {
    "session_ref": "sess-1",
    "user_ref": "user-1",
    "session_state": 1,
    "device_trust_level": 3,
    "session_trust_level": SESSION_TRUST_AUTHENTICATED,
}


class _Client:
    def __init__(self, grants=("RETAIL_USER",), raises=None):
        self._grants = list(grants)
        self._raises = raises
        self.calls = 0

    async def fetch(self, session_ref: str, *, user_ref: str) -> TrustContext:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return TrustContext.model_validate({**CTX, "grants": self._grants})


class _User:
    def __init__(self, id="user-1", type="user", **claims):
        self.id, self.type, self._claims = id, type, claims

    def get(self, key):
        return self._claims.get(key)


def _resolver(client=None, **kw):
    return AuthServiceResolver(
        client or _Client(), TrustContextCache(NullCache()), **kw
    )


# ── the enforcer ──────────────────────────────────────────────────────────────


def test_a_held_entitlement_opens_its_capability():
    e = build_enforcer(REGISTRY)
    riya = Principal(user_ref="riya", entitlements=["ORDER_READ"])
    assert e.allows_principal(riya, "orders:list")
    assert e.allows_principal(riya, "orders:read")


def test_an_unheld_entitlement_does_not():
    e = build_enforcer(REGISTRY)
    riya = Principal(user_ref="riya", entitlements=["ORDER_READ"])
    assert not e.allows_principal(riya, "orders:create")


def test_holding_nothing_denies():
    e = build_enforcer(REGISTRY)
    assert not e.allows_principal(Principal(user_ref="nobody"), "orders:list")


def test_one_entitlement_opens_several_capabilities():
    """The registry is many-to-one by design: 12 of ledger's entitlements govern 2-4
    capabilities each, and that fan-out is healthy while the blast radius is the same."""
    e = build_enforcer(REGISTRY)
    riya = Principal(user_ref="riya", entitlements=["ORDER_CREATE"])
    assert all(e.allows_principal(riya, c) for c in ("orders:validate", "orders:create", "tasks:deeplink"))


def test_an_unregistered_capability_is_denied_and_reportable():
    e = build_enforcer(REGISTRY)
    riya = Principal(user_ref="riya", entitlements=["ORDER_READ"])
    assert not e.allows_principal(riya, "orders:delete")
    assert not e.knows("orders:delete"), "a host's startup check can say this is a wiring bug"


# ── any-of alternatives (RUL-073) ─────────────────────────────────────────────


def test_a_capability_may_list_alternatives_and_either_opens_it():
    """Many entitlements over ONE capability. `txn:read` opened by TXN_READ or SUPPORT_READ is a
    single row listing both -- not two capabilities, which would split the route in two."""
    e = build_enforcer({**REGISTRY, "txn:read": ["TXN_READ", "SUPPORT_READ"]})
    by_own = Principal(user_ref="riya", entitlements=["TXN_READ"])
    by_support = Principal(user_ref="agent", entitlements=["SUPPORT_READ"])
    assert e.allows_principal(by_own, "txn:read")
    assert e.allows_principal(by_support, "txn:read")


def test_holding_neither_alternative_still_denies():
    e = build_enforcer({**REGISTRY, "txn:read": ["TXN_READ", "SUPPORT_READ"]})
    assert not e.allows_principal(Principal(user_ref="x", entitlements=["ORDER_READ"]), "txn:read")


def test_a_bare_string_still_works_and_reads_as_one_alternative():
    """The 8 rows in orders and 15 in onboarding are all bare strings. RUL-073 makes the list the
    authored form; it does not make a migration a precondition."""
    e = build_enforcer(REGISTRY)
    assert e.registry["orders:list"] == ["ORDER_READ"]
    assert e.allows_principal(Principal(user_ref="r", entitlements=["ORDER_READ"]), "orders:list")


def test_the_registry_reads_back_normalised_whatever_was_authored():
    """So a caller reading it never branches on the two shapes."""
    e = build_enforcer({"a:read": "A", "b:read": ["B1", "B2"]})
    assert e.registry == {"a:read": ["A"], "b:read": ["B1", "B2"]}


def test_an_empty_list_refuses_at_build_like_an_empty_string():
    with pytest.raises(ValueError, match="empty entitlement"):
        build_enforcer({**REGISTRY, "orders:ghost": []})


def test_a_list_of_blanks_refuses_too():
    with pytest.raises(ValueError, match="empty entitlement"):
        build_enforcer({**REGISTRY, "orders:ghost": ["  ", ""]})


def test_a_capability_mapped_to_nothing_refuses_at_build():
    """That row would deny every caller forever WHILE LOOKING CONFIGURED, so it fails at
    import rather than at 3am."""
    with pytest.raises(ValueError, match="empty entitlement"):
        build_enforcer({**REGISTRY, "orders:ghost": ""})


def test_no_user_identifier_enters_the_policy():
    """Casbin's `sub` is the entitlement, not the user -- which is what makes the policy a
    pure function of the registry, buildable once at import and shared without a lock."""
    e = build_enforcer(REGISTRY)
    a = Principal(user_ref="riya", entitlements=["ORDER_READ"])
    b = Principal(user_ref="someone-else", entitlements=["ORDER_READ"])
    assert e.allows_principal(a, "orders:list") == e.allows_principal(b, "orders:list")


# ── the g layer: grant -> entitlement -> capability (C1) ──────────────────────


def test_a_grant_opens_the_capabilities_of_the_entitlements_it_expands_to():
    """One Enforce(grant, capability): casbin walks g(grant, entitlement) then matches
    p(entitlement, capability). The expansion is policy data now, not a callable."""
    e = build_enforcer(REGISTRY, expansion={"RETAIL_USER": ["ORDER_READ"]})
    assert e.allows(["RETAIL_USER"], "orders:list")
    assert not e.allows(["RETAIL_USER"], "orders:create"), "only what it expands to"


def test_an_entitlement_still_works_directly_which_is_what_makes_this_non_breaking():
    """The default role manager counts name1 == name2 as a link, so every existing call site
    keeps answering identically once g rows exist."""
    e = build_enforcer(REGISTRY, expansion={"RETAIL_USER": ["ORDER_READ"]})
    assert e.allows(["ORDER_READ"], "orders:list")


def test_no_expansion_is_the_correct_state_today():
    """Auth emits no grants and the platform register is deliberately empty, so the layer lands
    inert and the gate answers exactly as it did before it existed."""
    with_layer = build_enforcer(REGISTRY)
    riya = Principal(user_ref="riya", entitlements=["ORDER_READ"])
    assert with_layer.allows_principal(riya, "orders:list")


def test_the_model_text_is_the_platform_artifact_two_layer_form():
    """Casbin is a mandated stack element and this text is a platform artifact, never
    re-authored per service."""
    from falcon_auth.entitlement.enforcer import MODEL_TEXT

    assert "[role_definition]" in MODEL_TEXT
    assert "g = _, _" in MODEL_TEXT
    assert "m = g(r.sub, p.sub) && r.obj == p.obj" in MODEL_TEXT


def test_casbin_chains_a_third_hop_silently():
    """The reproduction RUL-075 is built on, and the whole reason a build-time lint is required.

    g is transitive to maxHierarchyLevel and CANNOT express flatness itself. A -> B and B -> C
    means A reaches C's capabilities, with nothing in the engine to object. Exactly two hops is
    a property the lint must enforce from outside -- see falcon_auth.entitlement.flatness.
    """
    chained = build_enforcer({"x:read": "C"}, expansion={"A": ["B"], "B": ["C"]})
    assert chained.allows(["A"], "x:read"), "three hops, and casbin allowed it"


# ── per-grant first match (C4) ────────────────────────────────────────────────


def test_opened_by_names_which_subject_opened_the_route():
    """C-032's audit line needs to record WHICH grant was responsible. A boolean cannot."""
    e = build_enforcer(REGISTRY, expansion={"RETAIL_USER": ["ORDER_READ"]})
    assert e.opened_by(["RETAIL_USER"], "orders:list") == "RETAIL_USER"


def test_opened_by_is_none_when_nothing_opens_it():
    e = build_enforcer(REGISTRY)
    assert e.opened_by(["ORDER_READ"], "orders:create") is None


def test_first_match_wins_in_the_callers_order():
    """Grants compose as a union and the model has no deny effect, so ordering cannot change the
    VERDICT -- only which of several sufficient subjects is recorded."""
    e = build_enforcer({**REGISTRY, "txn:read": ["A", "B"]})
    assert e.opened_by(["A", "B"], "txn:read") == "A"
    assert e.opened_by(["B", "A"], "txn:read") == "B"


def test_allows_and_opened_by_never_disagree():
    e = build_enforcer({**REGISTRY, "txn:read": ["A", "B"]})
    for held in (["A"], ["B"], ["A", "B"], ["ORDER_READ"], []):
        assert e.allows(held, "txn:read") == (e.opened_by(held, "txn:read") is not None)


def test_principal_opened_by_is_the_audit_line_form():
    e = build_enforcer(REGISTRY)
    riya = Principal(user_ref="riya", entitlements=["ORDER_READ"])
    assert e.principal_opened_by(riya, "orders:list") == "ORDER_READ"


# ── the resolver ──────────────────────────────────────────────────────────────


async def test_grants_from_the_feed_become_entitlements():
    """The one line the rename forced: the feed carries auth's coarse GRANTS, and this is
    where they are expanded into the service's own vocabulary."""
    resolver = _resolver(_Client(grants=["RETAIL_USER"]))
    p = await resolver.resolve(_User(sid="sess-1"))
    assert p.entitlements == ["RETAIL_USER"], "pass-through until `expand` is wired"
    assert p.user_ref == "user-1"


async def test_supplying_an_expansion_callable_is_refused_not_ignored():
    """The expansion is `g` rows now (RUL-075). Refusing beats ignoring: a host whose expansion
    silently stopped applying would keep resolving callers to the coarse vocabulary and only
    find out from a denial."""
    with pytest.raises(ValueError, match="no longer a callable"):
        _resolver(_Client(grants=["RETAIL_USER"]), expand=lambda g: ["ORDER_READ"])


async def test_the_expansion_now_happens_in_the_policy():
    """What the resolver produces is the grants; the gate walks grant -> entitlement ->
    capability in one call."""
    resolver = _resolver(_Client(grants=["RETAIL_USER"]))
    p = await resolver.resolve(_User(sid="sess-1"))
    assert p.entitlements == ["RETAIL_USER"]

    gate = build_enforcer(REGISTRY, expansion={"RETAIL_USER": ["ORDER_READ"]})
    assert gate.allows_principal(p, "orders:list")


async def test_the_local_veto_is_the_only_subtractive_lever():
    """Grants are additive only -- the model has no deny effect -- so a suspension can never
    be expressed as a grant. The service's own state is what removes access."""
    resolver = _resolver(
        _Client(grants=["RETAIL_USER", "MERCHANT_USER"]),
        veto=lambda user_ref, held: [g for g in held if g != "MERCHANT_USER"],
    )
    p = await resolver.resolve(_User(sid="sess-1"))
    assert p.entitlements == ["RETAIL_USER"], "suspended for the merchant grant, locally"


async def test_a_token_with_no_session_claim_is_denied():
    """An identity we cannot ask about. Fail closed rather than guess."""
    resolver = _resolver()
    with pytest.raises(CapabilityDenied):
        await resolver.resolve(_User())


async def test_the_trust_fields_travel_with_the_entitlements():
    """They arrive from one lookup and ride one Principal, so a route cannot read
    entitlements while forgetting assurance."""
    resolver = _resolver()
    p = await resolver.resolve(_User(sid="sess-1"))
    assert p.session_ref == "sess-1"
    assert p.session_trust_level == SESSION_TRUST_AUTHENTICATED
    assert p.is_elevated is False


async def test_a_token_cannot_resolve_as_a_service_account():
    """The branch that did this is removed.

    It served an authentication method C-038's closed per-plane set does not include, neither
    consumer registers one, and it was the path the claim allowlist exists to keep unreachable:
    type="service-account" -> entitlements from the caller -> ORDER_READ_ANY -> ownership off.

    A peer backend reading across parties now authenticates by certificate on the SERVICE
    plane, where the CN allow-list carries its capabilities.
    """
    resolver = _resolver()
    with pytest.raises(CapabilityDenied):
        await resolver.resolve(_User(type="service-account", entitlements=["ORDER_READ_ANY"]))


async def test_a_consequential_operation_fails_closed_when_the_source_is_down():
    """The entitlement IS the control there, so degrading to last-good would be the wrong
    direction."""
    resolver = _resolver(_Client(raises=AuthzUnavailable("down")))
    with pytest.raises(AuthzUnavailable):
        await resolver.resolve(_User(sid="sess-1"), consequential=True)


async def test_a_dead_session_propagates_as_a_denial_not_an_outage():
    """A logged-out session is a DENY: telling the client to retry a request that will never
    succeed is the wrong answer."""
    resolver = _resolver(_Client(raises=SessionMiss("gone")))
    with pytest.raises(SessionMiss):
        await resolver.resolve(_User(sid="sess-1"))


# ── the dev escape hatch ──────────────────────────────────────────────────────


async def test_grant_all_keeps_each_callers_own_identity():
    """The instructive half. Resolving everyone to one dev subject would make every object
    look like it belongs to the same person, so ownership bugs become invisible in dev and
    appear in production. Grant-all is about ENTITLEMENTS only."""
    resolver = GrantAllResolver(["ORDER_READ", "ORDER_CREATE"])
    a = await resolver.resolve(_User(id="riya"))
    b = await resolver.resolve(_User(id="arjun"))
    assert a.user_ref == "riya" and b.user_ref == "arjun"
    assert a.entitlements == b.entitlements


async def test_grant_all_reports_no_trust_posture():
    """It knows nothing about assurance, and a fabricated tier would let an assurance rule
    pass in dev on evidence that does not exist."""
    p = await GrantAllResolver(["ORDER_READ"]).resolve(_User())
    assert p.session_trust_level is None

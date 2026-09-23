"""Tests for the entitlement layer: the enforcer, the resolver, and the gate.

Uses orders' real capability registry, so the fixtures are the estate's vocabulary rather
than invented names. Grant names are invented -- the platform register is deliberately empty
because nothing grants yet.
"""

import pytest

from falcon_auth.entitlement.enforcer import build_enforcer
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


# ── the resolver ──────────────────────────────────────────────────────────────


async def test_grants_from_the_feed_become_entitlements():
    """The one line the rename forced: the feed carries auth's coarse GRANTS, and this is
    where they are expanded into the service's own vocabulary."""
    resolver = _resolver(_Client(grants=["RETAIL_USER"]))
    p = await resolver.resolve(_User(sid="sess-1"))
    assert p.entitlements == ["RETAIL_USER"], "pass-through until `expand` is wired"
    assert p.user_ref == "user-1"


async def test_expand_maps_coarse_grants_to_local_entitlements():
    resolver = _resolver(
        _Client(grants=["RETAIL_USER"]),
        expand=lambda granted: ["ORDER_READ", "TASK_READ"] if "RETAIL_USER" in granted else [],
    )
    p = await resolver.resolve(_User(sid="sess-1"))
    assert p.entitlements == ["ORDER_READ", "TASK_READ"]


async def test_the_local_veto_is_the_only_subtractive_lever():
    """Grants are additive only -- the model has no deny effect -- so a suspension can never
    be expressed as a grant. The service's own state is what removes access."""
    resolver = _resolver(
        _Client(grants=["RETAIL_USER"]),
        expand=lambda g: ["ORDER_READ", "ORDER_CREATE"],
        veto=lambda user_ref, ents: [e for e in ents if e != "ORDER_CREATE"],
    )
    p = await resolver.resolve(_User(sid="sess-1"))
    assert p.entitlements == ["ORDER_READ"], "suspended for writes, locally"


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

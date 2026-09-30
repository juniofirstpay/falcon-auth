"""Issue #8: the service plane speaks `capability`, and can join the Casbin policy.

Two proposed conventions drive this file (platform-conventions RUL-132):

    C-055  one word for a route's demand -- capability -- on every plane. The old names keep
           working, with a DeprecationWarning, and the wire does not change yet.
    C-056  service-plane authorization is the same two-layer policy: the allow-list says which
           peer a certificate IS (`cn -> source`), and `g, <peer>, <entitlement>` rows in code
           say what it may do.
"""
from __future__ import annotations

import datetime as dt
import warnings

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from structlog.testing import capture_logs

from falcon_auth import (
    FlatnessError,
    MissingCapabilityError,
    MissingScopeError,
    Principal,
    SvcPlaneErrorCodes,
    Verifier,
    build_allow_list,
    build_enforcer,
    check_peers,
    verify_policy,
)
from falcon_auth.adapters.hooks import (
    principal_from_request,
    require_service_capability,
    require_service_scope,
)


# ─── helpers ─────────────────────────────────────────────────────────────────


def _cert(common_name: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class _Ctx:
    pass


class _Req:
    def __init__(self, cn: str | None):
        self.scope: dict = {"type": "http"}
        if cn is not None:
            self.scope["extensions"] = {"tls": {"peer_cert_der": _cert(cn)}}
        self.context = _Ctx()


#: A service's capability registry -- the same shape on both planes.
REGISTRY = {
    "kyc:read": "SVC_KYC_READ",
    "kyc:write": "SVC_KYC_WRITE",
    "orders:read": "ORDER_READ",
}
#: What each peer holds, by logical name. In code, in the owning service.
PEERS = {"payments": ["SVC_KYC_READ"], "orders": ["SVC_KYC_READ", "SVC_KYC_WRITE"]}

#: Config, per environment: which certificate is which peer. No capabilities.
ROWS = [
    {"cn": "payments.preprod.internal", "kind": "SERVICE", "source": "payments"},
    {"cn": "orders.preprod.internal", "kind": "SERVICE", "source": "orders"},
    {"cn": "rail.preprod.internal", "kind": "CALLBACK", "source": "rail"},
]


def _policy():
    enforcer = build_enforcer(REGISTRY, peers=PEERS)
    verifier = Verifier(build_allow_list(ROWS, peers=enforcer.peers))
    return enforcer, verifier


# ─── C-055: the rename is non-breaking ───────────────────────────────────────


def test_the_old_error_name_is_the_same_class():
    """An `except MissingScopeError` in a consumer keeps catching everything it caught."""
    assert MissingScopeError is MissingCapabilityError


def test_the_wire_is_unchanged_until_the_convention_is_ratified():
    body = MissingCapabilityError("kyc:read", code=9002).json()
    assert body == {
        "code": 9002,
        "title": "MissingScopeError",
        "description": "certificate identity is not granted kyc:read",
        "extras": {"scope": "kyc:read"},
    }


def test_old_raise_sites_still_construct_the_error():
    err = MissingScopeError(scope="kyc:read", code=5002)
    assert err.capability == "kyc:read" and err.code == 5002


def test_the_error_takes_exactly_one_spelling():
    with pytest.raises(TypeError):
        MissingCapabilityError("a:b", scope="a:b")
    with pytest.raises(TypeError):
        MissingCapabilityError()


def test_the_old_code_keyword_warns_and_still_sets_the_code():
    with pytest.warns(DeprecationWarning):
        codes = SvcPlaneErrorCodes(missing_scope=5002)
    assert codes.missing_capability == 5002
    with pytest.warns(DeprecationWarning):
        assert codes.missing_scope == 5002


def test_both_code_keywords_are_refused():
    with pytest.raises(TypeError):
        SvcPlaneErrorCodes(missing_capability=1, missing_scope=2)


def test_the_old_principal_names_warn_and_read_the_same_set():
    with pytest.warns(DeprecationWarning):
        p = Principal("a.svc", "SERVICE", "a", scopes=["x:y"])
    assert p.capabilities == frozenset({"x:y"})
    with pytest.warns(DeprecationWarning):
        assert p.scopes == frozenset({"x:y"})
    with pytest.warns(DeprecationWarning):
        assert p.has_scope("x:y")


# ─── C-055: the config key (falcon-auth#8, second comment) ───────────────────


def test_the_new_key_is_read():
    allow = build_allow_list(
        [{"cn": "a.svc", "kind": "SERVICE", "source": "a", "capabilities": ["x:y"]}]
    )
    assert allow["a.svc"].capabilities == frozenset({"x:y"})


def test_the_old_key_still_works_and_warns_once_at_boot_naming_every_cn():
    """A missing key reads as an empty set, so a package that stopped reading `scopes` would give
    every peer nothing -- silently. The old key is read, and the deploy log says where it is."""
    rows = [
        {"cn": "a.svc", "kind": "SERVICE", "source": "a", "scopes": ["x:y"]},
        {"cn": "b.svc", "kind": "SERVICE", "source": "b", "scopes": ["x:z"]},
    ]
    with capture_logs() as logs:
        allow = build_allow_list(rows)
    assert allow["a.svc"].capabilities == frozenset({"x:y"})
    old = [e for e in logs if e["event"] == "svcplane_allow_list_old_key"]
    assert len(old) == 1
    assert old[0]["cns"] == ["a.svc", "b.svc"]


def test_a_row_with_both_keys_is_refused():
    with pytest.raises(ValueError, match="both"):
        build_allow_list(
            [{"cn": "a.svc", "kind": "SERVICE", "source": "a",
              "scopes": ["x:y"], "capabilities": ["x:y"]}]
        )


# ─── C-056: the policy holds the peers ───────────────────────────────────────


def test_a_peer_opens_what_its_rows_grant_and_nothing_else():
    enforcer = build_enforcer(REGISTRY, peers=PEERS)
    assert enforcer.allows_peer("payments", "kyc:read")
    assert not enforcer.allows_peer("payments", "kyc:write")
    assert enforcer.allows_peer("orders", "kyc:write")


def test_an_undeclared_peer_is_refused_even_when_spelled_like_an_entitlement():
    """casbin links name1 == name2. Without the declared-peer check, a peer called
    `SVC_KYC_READ` would open kyc:read with no row at all -- the #1 A2 shape."""
    enforcer = build_enforcer(REGISTRY, peers=PEERS)
    assert enforcer._enforcer.enforce("SVC_KYC_READ", "kyc:read")  # the hazard is real
    assert not enforcer.allows_peer("SVC_KYC_READ", "kyc:read")


def test_the_enforcer_exposes_peer_names_as_a_plain_set():
    assert build_enforcer(REGISTRY, peers=PEERS).peers == frozenset({"payments", "orders"})
    assert build_enforcer(REGISTRY).peers == frozenset()


# ─── C-056: the allow-list in policy mode ────────────────────────────────────


def test_policy_mode_refuses_a_row_still_carrying_capabilities():
    rows = [{"cn": "a.svc", "kind": "SERVICE", "source": "payments", "capabilities": ["kyc:read"]}]
    with pytest.raises(ValueError, match="C-056"):
        build_allow_list(rows, peers={"payments"})


def test_policy_mode_refuses_the_old_key_too():
    rows = [{"cn": "a.svc", "kind": "SERVICE", "source": "payments", "scopes": ["kyc:read"]}]
    with pytest.raises(ValueError, match="C-056"):
        build_allow_list(rows, peers={"payments"})


def test_an_empty_capability_list_is_not_a_leftover():
    """Callback rows are often written `scopes: []`. An empty list grants nothing, so it is not
    refused -- only a list that would have granted something is."""
    rows = [{"cn": "rail.svc", "kind": "CALLBACK", "source": "rail", "scopes": []}]
    build_allow_list(rows, peers={"payments"})


def test_policy_mode_refuses_a_service_row_naming_an_unknown_peer():
    rows = [{"cn": "a.svc", "kind": "SERVICE", "source": "paymnets"}]
    with pytest.raises(ValueError, match="paymnets"):
        build_allow_list(rows, peers={"payments"})


def test_callback_rows_are_not_peers():
    rows = [{"cn": "rail.svc", "kind": "CALLBACK", "source": "rail"}]
    build_allow_list(rows, peers={"payments"})


def test_a_declared_peer_bound_by_no_cn_is_a_warning_not_a_refusal():
    with capture_logs() as logs:
        build_allow_list(ROWS[:1], peers={"payments", "orders"})
    unbound = [e for e in logs if e["event"] == "svcplane_peers_unbound"]
    assert unbound and unbound[0]["peers"] == ["orders"]


def test_two_certificates_may_bind_one_peer():
    """A certificate rotation, or two regions, is two CNs for one peer -- legitimate."""
    rows = [
        {"cn": "payments.a.internal", "kind": "SERVICE", "source": "payments"},
        {"cn": "payments.b.internal", "kind": "SERVICE", "source": "payments"},
    ]
    assert len(build_allow_list(rows, peers={"payments"})) == 2


# ─── C-056: the boot lint over peer rows ─────────────────────────────────────


def test_the_example_policy_passes_the_lint():
    verify_policy(REGISTRY, grant_register=["CUSTOMER_GRANT"], peers=PEERS)


@pytest.mark.parametrize(
    "peers, register, match",
    [
        ({"CUSTOMER_GRANT": ["SVC_KYC_READ"]}, ["CUSTOMER_GRANT"], "peer and a grant"),
        ({"ORDER_READ": ["SVC_KYC_READ"]}, [], "also entitlements"),
        ({"payments": ["orders"], "orders": ["SVC_KYC_READ"]}, [], "third hop"),
        ({"payments": ["SVC_KYC_RAED"]}, [], "opens no capability"),
    ],
    ids=["named-like-a-grant", "named-like-an-entitlement", "third-hop", "typo-in-a-holding"],
)
def test_the_lint_refuses(peers, register, match):
    with pytest.raises(FlatnessError, match=match):
        check_peers(peers, REGISTRY, grant_register=register)


def test_a_peer_named_like_a_grant_in_the_expansion_is_refused():
    with pytest.raises(FlatnessError, match="peer and a grant"):
        verify_policy(
            REGISTRY,
            {"CUSTOMER_GRANT": ["ORDER_READ"]},
            peers={"CUSTOMER_GRANT": ["SVC_KYC_READ"]},
        )


# ─── the hook ────────────────────────────────────────────────────────────────


def test_policy_mode_refuses_an_unregistered_capability_at_decoration():
    """The #8 typo: `kyc:raed` mounted cleanly and no peer could ever open it."""
    enforcer, verifier = _policy()
    with pytest.raises(ValueError, match="kyc:raed"):
        require_service_capability(verifier, "kyc:raed", enforcer=enforcer)


async def test_policy_mode_admits_a_peer_holding_the_capability():
    enforcer, verifier = _policy()
    hook = require_service_capability(verifier, "kyc:read", enforcer=enforcer)
    req = _Req("payments.preprod.internal")
    await hook(req, None, None, {})
    assert principal_from_request(req).source == "payments"


async def test_policy_mode_refuses_a_peer_lacking_the_capability():
    enforcer, verifier = _policy()
    hook = require_service_capability(verifier, "kyc:write", enforcer=enforcer)
    with pytest.raises(MissingCapabilityError) as e:
        await hook(_Req("payments.preprod.internal"), None, None, {})
    assert e.value.code == 9002 and e.value.capability == "kyc:write"


async def test_policy_mode_refuses_a_callback_principal():
    enforcer, verifier = _policy()
    hook = require_service_capability(verifier, "kyc:read", enforcer=enforcer)
    with pytest.raises(MissingCapabilityError):
        await hook(_Req("rail.preprod.internal"), None, None, {})


async def test_policy_mode_still_refuses_an_unknown_cn_first():
    from falcon_auth import UnknownCNError

    enforcer, verifier = _policy()
    hook = require_service_capability(verifier, "kyc:read", enforcer=enforcer)
    with pytest.raises(UnknownCNError):
        await hook(_Req("stranger.internal"), None, None, {})


async def test_allow_list_mode_is_unchanged():
    verifier = Verifier(
        build_allow_list(
            [{"cn": "a.svc", "kind": "SERVICE", "source": "a", "capabilities": ["x:y"]}]
        )
    )
    await require_service_capability(verifier, "x:y")(_Req("a.svc"), None, None, {})
    with pytest.raises(MissingCapabilityError):
        await require_service_capability(verifier, "x:z")(_Req("a.svc"), None, None, {})


def test_the_old_hook_name_warns_where_it_is_decorated_not_per_request():
    verifier = Verifier(build_allow_list([]))
    with pytest.warns(DeprecationWarning):
        require_service_scope(verifier, "x:y")


async def test_the_old_hook_does_not_warn_per_request():
    verifier = Verifier(
        build_allow_list([{"cn": "a.svc", "kind": "SERVICE", "source": "a", "capabilities": ["x:y"]}])
    )
    with pytest.warns(DeprecationWarning):
        hook = require_service_scope(verifier, "x:y")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        await hook(_Req("a.svc"), None, None, {})


def test_a_policy_mode_hook_needs_a_real_enforcer_at_decoration():
    _, verifier = _policy()
    with pytest.raises(TypeError):
        require_service_capability(verifier, "kyc:read", enforcer=object())  # type: ignore[arg-type]

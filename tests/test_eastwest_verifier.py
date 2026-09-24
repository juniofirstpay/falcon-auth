from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from falcon_auth import (
    KIND_CALLBACK,
    KIND_SERVICE,
    MissingClientCertError,
    MissingScopeError,
    Principal,
    SvcPlaneErrorCodes,
    UnknownCNError,
    Verifier,
    build_allow_list,
)
from falcon_auth.eastwest.verifier import peer_cn


# ─── helpers ─────────────────────────────────────────────────────────────────


def _make_cert_der(common_name: str) -> bytes:
    """Return a self-signed EC P-256 cert (DER-encoded) with the given CN.

    Only the Subject.CommonName is inspected by svcplane, so a self-signed
    cert is sufficient — chain validation is TLS's job (delegated to the
    handshake), which the unit tests bypass.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _scope_with(peer_cert_der: bytes | None) -> dict:
    scope: dict = {"type": "http"}
    if peer_cert_der is not None:
        scope["extensions"] = {"tls": {"peer_cert_der": peer_cert_der}}
    return scope


# ─── build_allow_list ────────────────────────────────────────────────────────


def test_build_allow_list_from_dicts():
    allow = build_allow_list(
        [
            {
                "cn": "gateway.svc",
                "kind": "SERVICE",
                "source": "gateway",
                "scopes": ["revocations.sessions:read"],
            },
            {
                "cn": "rail.svc",
                "kind": "CALLBACK",
                "source": "rail",
                "scopes": [],
            },
        ]
    )
    assert allow["gateway.svc"].kind == KIND_SERVICE
    assert allow["gateway.svc"].has_scope("revocations.sessions:read")
    assert allow["rail.svc"].kind == KIND_CALLBACK
    assert allow["rail.svc"].scopes == frozenset()


def test_build_allow_list_from_objects_with_attributes():
    class Row:
        def __init__(self, cn, kind, source, scopes):
            self.cn, self.kind, self.source, self.scopes = cn, kind, source, scopes

    allow = build_allow_list([Row("svc.a", "SERVICE", "a", ["x:y"])])
    assert allow["svc.a"] == Principal(
        cn="svc.a", kind="SERVICE", source="a", scopes=frozenset({"x:y"})
    )


def test_build_allow_list_rejects_unknown_kind():
    # Mistyped `kind` in settings should crash at boot rather than fail-open.
    with pytest.raises(ValueError, match="kind='REST'"):
        build_allow_list(
            [{"cn": "x", "kind": "REST", "source": "s", "scopes": []}]
        )


# ─── peer_cn ─────────────────────────────────────────────────────────────────


def test_peer_cn_returns_none_when_scope_lacks_tls_extension():
    assert peer_cn({"type": "http"}) is None
    assert peer_cn({"type": "http", "extensions": {}}) is None
    assert peer_cn({"type": "http", "extensions": {"tls": {}}}) is None


def test_peer_cn_returns_none_on_malformed_der():
    assert peer_cn(_scope_with(b"not a cert")) is None


def test_peer_cn_extracts_common_name_from_der():
    assert peer_cn(_scope_with(_make_cert_der("gateway.svc"))) == "gateway.svc"


def test_peer_cn_returns_none_when_cert_has_no_common_name():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "no-cn")]
    )
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
    der = cert.public_bytes(serialization.Encoding.DER)
    assert peer_cn(_scope_with(der)) is None


# ─── Verifier.authenticate ───────────────────────────────────────────────────


def test_authenticate_no_client_cert_raises_missing_client_cert_error():
    v = Verifier(allow={})
    with pytest.raises(MissingClientCertError) as ei:
        v.authenticate(_scope_with(None))
    # Default code for the fresh-verifier path.
    assert ei.value.code == 9000


def test_authenticate_unknown_cn_raises_unknown_cn_error():
    v = Verifier(allow={})
    with pytest.raises(UnknownCNError) as ei:
        v.authenticate(_scope_with(_make_cert_der("stranger.svc")))
    assert ei.value.code == 9001
    assert ei.value.cn == "stranger.svc"
    assert ei.value.extras == {"cn": "stranger.svc"}


def test_authenticate_known_cn_returns_principal():
    principal = Principal(
        cn="gateway.svc",
        kind="SERVICE",
        source="gateway",
        scopes=frozenset({"revocations.sessions:read"}),
    )
    v = Verifier(allow={"gateway.svc": principal})
    result = v.authenticate(_scope_with(_make_cert_der("gateway.svc")))
    assert result is principal


def test_authenticate_malformed_cert_der_is_treated_as_no_cert():
    # Corrupt DER → cryptography raises ValueError → peer_cn returns None →
    # authenticate raises MissingClientCertError. Only reachable if TLS is
    # bypassed (tests, or mis-injected scope); TLS itself rejects malformed
    # certs at the handshake.
    v = Verifier(allow={})
    with pytest.raises(MissingClientCertError):
        v.authenticate(_scope_with(b"not a cert"))


# ─── Verifier.require_scope ──────────────────────────────────────────────────


def test_require_scope_on_none_principal_raises():
    v = Verifier(allow={})
    with pytest.raises(MissingScopeError) as ei:
        v.require_scope(None, "any:scope")
    assert ei.value.code == 9002
    assert ei.value.scope == "any:scope"
    assert ei.value.extras == {"scope": "any:scope"}


def test_require_scope_missing_scope_raises():
    principal = Principal(
        cn="gateway.svc", kind="SERVICE", source="gateway",
        scopes=frozenset({"revocations.sessions:read"}),
    )
    v = Verifier(allow={"gateway.svc": principal})
    with pytest.raises(MissingScopeError) as ei:
        v.require_scope(principal, "invites:dispatch")
    assert ei.value.scope == "invites:dispatch"


def test_require_scope_granted_passes():
    principal = Principal(
        cn="gateway.svc", kind="SERVICE", source="gateway",
        scopes=frozenset({"revocations.sessions:read"}),
    )
    v = Verifier(allow={"gateway.svc": principal})
    # Does not raise → grant honored.
    v.require_scope(principal, "revocations.sessions:read")


# ─── SvcPlaneErrorCodes override ─────────────────────────────────────────────


def test_verifier_honors_consumer_code_overrides():
    # A repo whose 9xxx band is taken passes its own codes; Verifier threads
    # them into the raised exceptions.
    codes = SvcPlaneErrorCodes(missing_cert=5000, unknown_cn=5001, missing_scope=5002)
    v = Verifier(allow={}, codes=codes)

    with pytest.raises(MissingClientCertError) as ei:
        v.authenticate(_scope_with(None))
    assert ei.value.code == 5000

    with pytest.raises(UnknownCNError) as ei:
        v.authenticate(_scope_with(_make_cert_der("stranger.svc")))
    assert ei.value.code == 5001

    with pytest.raises(MissingScopeError) as ei:
        v.require_scope(None, "any:scope")
    assert ei.value.code == 5002


def test_verifier_codes_property_reads_configured_codes():
    codes = SvcPlaneErrorCodes(missing_cert=5000, unknown_cn=5001, missing_scope=5002)
    v = Verifier(allow={}, codes=codes)
    assert v.codes is codes


def test_a_duplicate_cn_in_the_allow_list_is_refused():
    """Issue #1 A13. Last-row-wins silently changed a peer's scopes -- the shape of a config
    merge going wrong, where two rows exist for one CN and only the second is enforced. A scope
    could be granted or lost by row order, with nothing to notice."""
    import pytest

    from falcon_auth.eastwest.verifier import build_allow_list

    with pytest.raises(ValueError, match="two entries for cn="):
        build_allow_list([
            {"cn": "peer.internal", "kind": "SERVICE", "source": "a", "scopes": ["x:read"]},
            {"cn": "peer.internal", "kind": "SERVICE", "source": "a", "scopes": ["x:write"]},
        ])

from __future__ import annotations

import ssl

# The split A15 made: everything with behaviour stays in `mtls` and needs no uvicorn; only the
# two concrete protocol subclasses moved, because a base class cannot be a deferred import.
from falcon_auth.eastwest.mtls import (
    _capture_peer_cert,
    _inject_tls_extension,
    build_uvicorn_ssl_kwargs,
)
from falcon_auth.eastwest.uvicorn_protocols import PeerCertH11Protocol


# ─── build_uvicorn_ssl_kwargs ────────────────────────────────────────────────


def test_empty_cert_returns_empty_kwargs():
    # regression check: cert_file="" → {} → uvicorn stays plaintext,
    # existing dev+tests unchanged (mirrors Go's ServerConfig("",…) → nil).
    assert build_uvicorn_ssl_kwargs("", "", "") == {}
    assert build_uvicorn_ssl_kwargs("", "/k", "/ca") == {}


def test_cert_only_yields_server_tls_no_client_verify():
    # TLS-terminated-upstream posture: server cert but no client CA → no
    # client-cert requirement (svcplane will fail-closed east-west routes).
    kw = build_uvicorn_ssl_kwargs("/c", "/k", "")
    assert kw["ssl_certfile"] == "/c"
    assert kw["ssl_keyfile"] == "/k"
    assert kw["ssl_version"] == ssl.PROTOCOL_TLS_SERVER
    assert "ssl_cert_reqs" not in kw
    assert "ssl_ca_certs" not in kw


def test_cert_plus_client_ca_enables_cert_optional():
    # Posture A mTLS: CERT_OPTIONAL is Python's VerifyClientCertIfGiven —
    # presented-but-unverifiable client cert fails the handshake; absence is
    # fine at TLS, svcplane fail-closes east-west routes.
    kw = build_uvicorn_ssl_kwargs("/c", "/k", "/ca")
    assert kw["ssl_certfile"] == "/c"
    assert kw["ssl_keyfile"] == "/k"
    assert kw["ssl_ca_certs"] == "/ca"
    assert kw["ssl_cert_reqs"] == ssl.CERT_OPTIONAL


def test_empty_key_file_normalised_to_none():
    # ssl_keyfile=None tells uvicorn "the key is bundled in the cert file".
    kw = build_uvicorn_ssl_kwargs("/c", "", "/ca")
    assert kw["ssl_keyfile"] is None


# ─── _capture_peer_cert ──────────────────────────────────────────────────────


class _Transport:
    def __init__(self, ssl_object):
        self._ssl_object = ssl_object

    def get_extra_info(self, name):
        return self._ssl_object if name == "ssl_object" else None


class _SSLObject:
    def __init__(self, der: bytes | None):
        self._der = der

    def getpeercert(self, binary_form: bool = False):
        assert binary_form is True
        return self._der


def test_capture_peer_cert_no_transport():
    assert _capture_peer_cert(None) is None


def test_capture_peer_cert_plain_transport_has_no_ssl_object():
    assert _capture_peer_cert(_Transport(ssl_object=None)) is None


def test_capture_peer_cert_ssl_but_no_client_cert():
    # CERT_OPTIONAL + client presents no cert → getpeercert returns None →
    # capture returns None → svcplane will raise MissingClientCertError.
    assert _capture_peer_cert(_Transport(_SSLObject(der=None))) is None


def test_capture_peer_cert_returns_der_bytes():
    der = b"\x30\x82"  # not a real DER, just a marker
    assert _capture_peer_cert(_Transport(_SSLObject(der=der))) == der


# ─── _inject_tls_extension ───────────────────────────────────────────────────


def test_inject_noop_when_no_peer_cert():
    scope: dict = {"type": "http"}
    _inject_tls_extension(scope, None)
    assert "extensions" not in scope


def test_inject_stamps_peer_cert_der_under_extensions_tls():
    scope: dict = {"type": "http"}
    _inject_tls_extension(scope, b"DER")
    assert scope["extensions"]["tls"] == {"peer_cert_der": b"DER"}


def test_inject_preserves_existing_extensions():
    scope: dict = {"type": "http", "extensions": {"other": {"x": 1}}}
    _inject_tls_extension(scope, b"DER")
    assert scope["extensions"]["other"] == {"x": 1}
    assert scope["extensions"]["tls"] == {"peer_cert_der": b"DER"}


# ─── protocol subclass: __setattr__ hook injects on every scope assignment ───


def test_h11_subclass_injects_tls_extension_on_scope_assignment():
    # Simulate what uvicorn does: assign a fresh scope dict to self.scope.
    # The subclass' __setattr__ hook must inject "extensions.tls" so the ASGI
    # task coroutine sees it before it runs.
    proto = PeerCertH11Protocol.__new__(PeerCertH11Protocol)
    # Manually stamp what connection_made would have captured.
    object.__setattr__(proto, "_peer_cert_der", b"DER")

    scope = {"type": "http", "headers": []}
    proto.scope = scope

    assert scope["extensions"]["tls"] == {"peer_cert_der": b"DER"}


def test_h11_subclass_noop_when_no_peer_cert():
    # No client cert presented (plaintext connection, or CERT_OPTIONAL +
    # absent cert) → no extension stamped → svcplane will raise MissingClientCertError.
    proto = PeerCertH11Protocol.__new__(PeerCertH11Protocol)
    object.__setattr__(proto, "_peer_cert_der", None)

    scope = {"type": "http", "headers": []}
    proto.scope = scope

    assert "extensions" not in scope


def test_h11_subclass_ignores_non_scope_attributes():
    # Sanity: __setattr__ only injects when the attribute being set is `scope`.
    proto = PeerCertH11Protocol.__new__(PeerCertH11Protocol)
    object.__setattr__(proto, "_peer_cert_der", b"DER")

    proto.something_else = {"type": "http"}
    assert "extensions" not in proto.something_else

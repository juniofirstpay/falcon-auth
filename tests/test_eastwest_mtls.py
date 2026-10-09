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


# ── A11: the context these kwargs produce survives a live certificate swap ────────────────


async def test_the_server_context_swaps_its_leaf_live_and_keeps_client_verification(tmp_path):
    """falcon-auth#1 A11. Rotation is reloaded by vault-agent-companion, which calls
    `load_cert_chain` on the live server context. This proves that handoff from falcon-auth's
    side, with no companion dependency: through a real handshake, the context uvicorn builds from
    `build_uvicorn_ssl_kwargs` serves the NEW leaf after `load_cert_chain`, keeps CERT_OPTIONAL,
    and the peer-cert capture still reads the caller."""
    import asyncio
    import datetime as dt
    import socket

    import falcon.asgi
    import uvicorn
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from falcon_auth.eastwest import peer_cn
    from falcon_auth.eastwest.uvicorn_protocols import PeerCertH11Protocol

    now = dt.datetime.now(dt.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("ca")).issuer_name(name("ca"))
          .public_key(ca_key.public_key()).serial_number(1)
          .not_valid_before(now - dt.timedelta(minutes=1))
          .not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(cn, serial, server):
        k = ec.generate_private_key(ec.SECP256R1())
        b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca.subject)
             .public_key(k.public_key()).serial_number(serial)
             .not_valid_before(now - dt.timedelta(minutes=1))
             .not_valid_after(now + dt.timedelta(days=1)))
        if server:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                                critical=False)
        return (b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
                + k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))

    server_leaf = tmp_path / "leaf.pem"       # one PEM, cert + key, as the sidecar renders it
    server_leaf.write_bytes(leaf("orders.internal", 1001, server=True))
    caller_leaf = tmp_path / "caller.pem"
    caller_leaf.write_bytes(leaf("payments.internal", 2001, server=False))

    class Who:
        async def on_get(self, req, resp):
            resp.media = {"peer_cn": peer_cn(req.scope)}

    app = falcon.asgi.App()
    app.add_route("/who", Who())
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, http=PeerCertH11Protocol, log_level="warning",
        lifespan="off",
        **build_uvicorn_ssl_kwargs(str(server_leaf), "", str(tmp_path / "ca.pem")),
    )
    config.load()                              # what the companion's attach() does
    server_ctx = config.ssl
    server = uvicorn.Server(config)
    serving = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)

    async def call():
        ctx = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))
        ctx.load_cert_chain(str(caller_leaf))
        r, w = await asyncio.open_connection("127.0.0.1", port, ssl=ctx,
                                             server_hostname="localhost")
        der = w.get_extra_info("ssl_object").getpeercert(True)
        w.write(b"GET /who HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        await w.drain()
        body = (await r.read()).split(b"\r\n\r\n", 1)[1]
        w.close()
        return x509.load_der_x509_certificate(der).serial_number, body

    try:
        assert await call() == (1001, b'{"peer_cn": "payments.internal"}')
        server_leaf.write_bytes(leaf("orders.internal", 1002, server=True))
        server_ctx.load_cert_chain(str(server_leaf))          # what the companion does on change
        assert await call() == (1002, b'{"peer_cn": "payments.internal"}')
        assert server_ctx.verify_mode == ssl.CERT_OPTIONAL
    finally:
        server.should_exit = True
        await serving

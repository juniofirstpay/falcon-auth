"""Tests for the tri-state authenticators, wired into the real middleware.

Issue #1 A4: the shipped adapters answered to a different contract than the middleware expects,
and nothing wired the two together. These do, because the failure is only visible end to end --
each half looks correct on its own.
"""

import datetime as dt

import falcon
import falcon.asgi
import falcon.testing
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from falcon_auth import planes
from falcon_auth.adapters.authenticators import jwt_authenticator, mtls_authenticator
from falcon_auth.adapters.middleware import PlaneAuthenticationMiddleware
from falcon_auth.adapters.routing import PlaneRegistry, mount
from falcon_auth.eastwest.verifier import Verifier, build_allow_list
from falcon_auth.errors import AuthzUnavailable, Unauthenticated
from falcon_auth.identity.jwks import InvalidToken


# ── stand-ins ─────────────────────────────────────────────────────────────────


class _User:
    def __init__(self, id=None, type="user", **claims):
        self.id, self.type, self.claims = id, type, claims


class _Verifier:
    """A JWKSVerifier stand-in: `good` verifies, `bad` is invalid, `boom` is a store fault."""

    def __init__(self):
        self.forwarded_claims = frozenset({"sid"})

    async def verify(self, token):
        if token == "bad":
            raise InvalidToken("InvalidSignatureError")
        if token == "boom":
            raise RuntimeError("jwks endpoint down")
        return {"sub": "user-1", "sid": "sess-1"}

    def principal_claims(self, claims):
        return {"sid": claims["sid"]}


def _cert_der(cn: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


PEER_DER = _cert_der("peer.internal")
STRANGER_DER = _cert_der("stranger.internal")

ALLOW = build_allow_list(
    [{"cn": "peer.internal", "kind": "SERVICE", "source": "peer", "scopes": ["x:read"]}]
)


class _NotFound(Exception):
    """The host's own not-found, which a wrong-plane 404 must be indistinguishable from."""


def _app(plane, *, cert_der=None):
    """A real app: real middleware, real verifiers, real tri-state adapters."""
    registry = PlaneRegistry()
    verifier = Verifier(ALLOW)
    middleware = PlaneAuthenticationMiddleware(
        registry,
        authenticators={
            planes.JWT: jwt_authenticator(_Verifier(), _User),
            planes.MTLS: mtls_authenticator(verifier),
        },
        not_found_error=_NotFound,
    )

    class _InjectCert:
        """Stands in for the uvicorn protocol subclass that injects the peer cert."""

        async def process_request(self, req, resp):
            if cert_der is not None:
                req.scope.setdefault("extensions", {})["tls"] = {"peer_cert_der": cert_der}

    async def render(req, resp, ex, params):
        resp.status = {
            _NotFound: falcon.HTTP_404,
            Unauthenticated: falcon.HTTP_401,
            AuthzUnavailable: falcon.HTTP_503,
        }.get(type(ex), falcon.HTTP_403)
        resp.media = {"error": type(ex).__name__}

    class Echo:
        async def on_get(self, req, resp):
            resp.media = {"ok": True}

    app = falcon.asgi.App(middleware=[_InjectCert(), middleware])
    for exc in (_NotFound, Unauthenticated, AuthzUnavailable, Exception):
        app.add_error_handler(exc, render)
    mount(registry, app, "/v1/thing", Echo(), plane=plane)
    return falcon.testing.TestClient(app)


# ── the A4 reproduction ───────────────────────────────────────────────────────


def test_a_forged_token_beside_a_valid_cert_is_401_not_404():
    """Issue #1 A4, the issue's own repro.

    The boolean adapter returns False for a forged token, which the middleware reads as "no
    credential present". C-038 step 2's 401 is skipped, the step-3 search finds the valid mTLS
    credential, and the caller is told 404 -- that the endpoint does not exist.

    Two things are wrong with that. The status is wrong (step 2 requires 401), and it is a worse
    answer: a forged token and a wrong-plane probe are different events, and the second one is
    flagged to the operator.
    """
    client = _app(planes.USER, cert_der=PEER_DER)
    r = client.simulate_get("/v1/thing", headers={"Authorization": "Bearer bad"})
    assert r.status_code == 401
    assert r.json["error"] == "Unauthenticated"


def test_the_boolean_collapse_is_what_produces_the_404():
    """The contrast, pinned. Without it the test above proves only that the code does what it
    does, not that it fixes anything.

    A boolean-style adapter returns falsy for a forged token, so the middleware reads "no
    credential present", skips step 2, and the step-3 search finds the valid certificate.

    Note the second harm, which the status code hides: the operator is flagged with a
    `plane_mismatch`. A forged token is reported as a wrong-plane probe -- a false security
    signal, pointing at the wrong incident.
    """

    def boolean_style(verifier, user_cls):
        async def attempt(req):
            header = req.get_header("Authorization")
            if not header:
                return None
            try:
                claims = await verifier.verify(header.split(None, 1)[1])
            except Exception:
                return None  # THE COLLAPSE: invalid reads as absent
            return user_cls(id=claims.get("sub"))

        return attempt

    registry = PlaneRegistry()
    flagged = []
    middleware = PlaneAuthenticationMiddleware(
        registry,
        authenticators={
            planes.JWT: boolean_style(_Verifier(), _User),
            planes.MTLS: mtls_authenticator(Verifier(ALLOW)),
        },
        not_found_error=_NotFound,
        on_plane_mismatch=lambda *a: flagged.append(a),
    )

    class _InjectCert:
        async def process_request(self, req, resp):
            req.scope.setdefault("extensions", {})["tls"] = {"peer_cert_der": PEER_DER}

    async def render(req, resp, ex, params):
        resp.status = falcon.HTTP_404 if isinstance(ex, _NotFound) else falcon.HTTP_401
        resp.media = {"error": type(ex).__name__}

    class Echo:
        async def on_get(self, req, resp):
            resp.media = {"ok": True}

    app = falcon.asgi.App(middleware=[_InjectCert(), middleware])
    for exc in (_NotFound, Exception):
        app.add_error_handler(exc, render)
    mount(registry, app, "/v1/thing", Echo(), plane=planes.USER)

    r = falcon.testing.TestClient(app).simulate_get(
        "/v1/thing", headers={"Authorization": "Bearer bad"}
    )
    assert r.status_code == 404, "the bug: a forged token told the caller the route is not there"
    assert flagged, "and the operator was flagged for a plane mismatch that did not happen"


# ── the JWT adapter's three states ────────────────────────────────────────────


def test_a_valid_token_passes():
    client = _app(planes.USER)
    assert client.simulate_get(
        "/v1/thing", headers={"Authorization": "Bearer good"}
    ).status_code == 200


def test_no_header_is_absent_not_invalid():
    client = _app(planes.USER)
    assert client.simulate_get("/v1/thing").status_code == 401


def test_another_scheme_reads_as_absent():
    """`Authorization: Basic ...` is a credential this method cannot parse -- not evidence that
    a token was forged."""
    client = _app(planes.USER)
    r = client.simulate_get("/v1/thing", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
    assert r.json["error"] == "Unauthenticated"


def test_a_store_fault_is_503_not_a_denial():
    """The distinction the boolean adapter collapses. During a JWKS outage, "your token is bad"
    reads as every user's credential going wrong at once; "we could not check" does not."""
    client = _app(planes.USER)
    r = client.simulate_get("/v1/thing", headers={"Authorization": "Bearer boom"})
    assert r.status_code == 503
    assert r.json["error"] == "AuthzUnavailable"


# ── the mTLS adapter's three states ───────────────────────────────────────────


def test_an_allow_listed_cert_passes_on_the_service_plane():
    client = _app(planes.SERVICE, cert_der=PEER_DER)
    assert client.simulate_get("/v1/thing").status_code == 200


def test_no_certificate_is_absent_not_invalid():
    """`Verifier.authenticate` RAISES here -- MissingClientCertError -- which the middleware
    would read as "present but invalid". A user-plane request carries no client certificate of
    its own and must not look like a broken service-plane credential."""
    client = _app(planes.SERVICE, cert_der=None)
    r = client.simulate_get("/v1/thing")
    assert r.status_code == 401, "step 5: nothing usable at all"


def test_an_unknown_cn_raises_rather_than_reading_as_a_wrong_plane_probe():
    """A real certificate this service does not recognise is present-and-invalid. On the
    wrong-plane search a raise ends the lookup at 401 rather than confirming the endpoint exists
    with a 404 -- step 4 needs a VALID credential for another plane, and this is not one."""
    client = _app(planes.USER, cert_der=STRANGER_DER)
    r = client.simulate_get("/v1/thing")
    assert r.status_code == 401


# ── the wrong-plane path still works with real adapters ───────────────────────


def test_a_valid_cert_on_a_user_route_is_still_404():
    """The behaviour the repro must not break: a genuinely valid credential for another plane
    is a wrong-plane probe, and gets the host's own not-found."""
    client = _app(planes.USER, cert_der=PEER_DER)
    r = client.simulate_get("/v1/thing")
    assert r.status_code == 404
    assert r.json["error"] == "_NotFound"


def test_a_valid_token_on_a_service_route_is_404():
    client = _app(planes.SERVICE)
    r = client.simulate_get("/v1/thing", headers={"Authorization": "Bearer good"})
    assert r.status_code == 404

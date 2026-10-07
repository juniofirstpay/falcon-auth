"""falcon-auth#1 A8: every error in C-001's shape, ``{code, message, extras?}``.

Each package exception names its platform register row; the handlers render it with the
register's message (C-048 §1), the caller-safe extras only, and the exception's own text as a
log-only trace (C-048 §2). Framework errors render the same way (C-001: "every" includes them).
"""
from __future__ import annotations

import re
import warnings

import falcon
import falcon.asgi
import falcon.testing
import pytest
from structlog.testing import capture_logs

from falcon_auth import PLAT_CODES, envelope, planes
from falcon_auth.adapters import (
    PlaneAuthenticationMiddleware,
    PlaneRegistry,
    mount,
    register_error_handlers,
    register_platform_error_handlers,
)
from falcon_auth.adapters.authenticators import CustomAuthenticator, JWTAuthenticator, Selector
from falcon_auth.assurance.operation import (
    OperationBodyMismatch,
    OperationChallengeMiss,
    OperationPurposeMismatch,
)
from falcon_auth.eastwest.errors import (
    MissingCapabilityError,
    MissingClientCertError,
    UnknownCNError,
)
from falcon_auth.errors import (
    AuthzUnavailable,
    CapabilityDenied,
    SessionMiss,
    StepUpRequired,
    TokenExpired,
    Unauthenticated,
)
from falcon_auth.identity.jwks import InvalidToken

C001_KEYS = {"code", "message", "extras"}
CODE = re.compile(r"^[A-Z]{4}[0-9]{4}$")


def _app(raise_this=None, **register_kwargs):
    class Raises:
        async def on_get(self, req, resp):
            raise raise_this

        async def on_post(self, req, resp):
            await req.get_media()

    app = falcon.asgi.App()
    register_platform_error_handlers(app, **register_kwargs)
    app.add_route("/x", Raises())
    return app


def _get(ex, **kw):
    return falcon.testing.TestClient(_app(ex, **kw)).simulate_get("/x")


def _assert_c001(r, status, code, extras=None):
    assert r.status_code == status
    assert set(r.json) <= C001_KEYS, f"extra root keys: {set(r.json) - C001_KEYS}"
    assert CODE.match(r.json["code"]) and r.json["code"] == code
    assert r.json["message"] == PLAT_CODES[code].message
    assert r.json.get("extras") == extras


# ─── the register copy ───────────────────────────────────────────────────────


def test_every_copied_row_is_well_formed():
    for code, row in PLAT_CODES.items():
        assert CODE.match(code) and row.code == code and row.message and 100 <= row.status < 600


def test_an_empty_extras_is_omitted():
    assert envelope("PLAT0101") == (401, {"code": "PLAT0101", "message": "Please sign in again."})


# ─── every package exception ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ex, status, code, extras",
    [
        (Unauthenticated("no token"), 401, "PLAT0101", None),
        (TokenExpired("exp passed"), 401, "PLAT0108", None),
        (CapabilityDenied("held nothing", capability="kyc:read"), 403, "PLAT0102",
         {"capability": "kyc:read"}),
        (SessionMiss("revoked"), 403, "PLAT0106", None),
        (StepUpRequired("not elevated", required=2, present=1), 401, "PLAT0109",
         {"required_session_trust_level": 2, "session_trust_level": 1}),
        (AuthzUnavailable("auth down"), 503, "PLAT0302", None),
        (MissingClientCertError(), 401, "PLAT0103", None),
        (UnknownCNError(cn="stranger.internal"), 403, "PLAT0104", None),
        (MissingCapabilityError("kyc:write"), 403, "PLAT0102", {"capability": "kyc:write"}),
    ],
    ids=lambda v: type(v).__name__ if isinstance(v, Exception) else None,
)
def test_each_exception_renders_its_platform_row(ex, status, code, extras):
    _assert_c001(_get(ex), status, code, extras)


def test_the_three_step_up_refusals_are_one_identical_answer():
    """C-030: every miss, replay or mismatch answers with one identical code -- and body."""
    bodies = {_get(cls("detail")).content
              for cls in (OperationChallengeMiss, OperationBodyMismatch, OperationPurposeMismatch)}
    assert len(bodies) == 1
    _assert_c001(_get(OperationBodyMismatch("x")), 401, "PLAT0109")


def test_a_503_carries_retry_after():
    """C-002."""
    assert _get(AuthzUnavailable("down"), retry_after=7).headers["Retry-After"] == "7"


def test_an_expired_jwt_is_plat0108_not_plat0101():
    """The client refreshes, rather than signing in again (RUL-072)."""

    class Expired:
        async def verify(self, token):
            raise InvalidToken("ExpiredSignatureError")

    class Forged:
        async def verify(self, token):
            raise InvalidToken("InvalidSignatureError")

    import asyncio

    class _Req:
        def get_header(self, name):
            return "Bearer t"

    with pytest.raises(TokenExpired):
        asyncio.run(JWTAuthenticator(Expired(), Selector("Authorization", "Bearer"))(_Req()))
    with pytest.raises(Unauthenticated) as e:
        asyncio.run(JWTAuthenticator(Forged(), Selector("Authorization", "Bearer"))(_Req()))
    assert not isinstance(e.value, TokenExpired)


# ─── C-048: copy from the register, detail to the log ────────────────────────


def test_the_operators_text_never_reaches_the_wire_and_is_logged():
    with capture_logs() as logs:
        r = _get(CapabilityDenied("SECRET internal detail 42", capability="kyc:read"))
    assert "SECRET" not in r.text
    line = next(e for e in logs if e["event"] == "error_response")
    assert "SECRET internal detail 42" in line["trace"]
    assert line["code"] == "PLAT0102" and line["path"] == "/x" and line["method"] == "GET"


def test_an_unknown_cn_is_logged_not_echoed():
    with capture_logs() as logs:
        r = _get(UnknownCNError(cn="stranger.internal"))
    assert "stranger" not in r.text
    assert "stranger.internal" in next(e for e in logs if e["event"] == "error_response")["trace"]


def test_a_host_register_overrides_the_copy():
    r = _get(Unauthenticated(), messages=lambda code: {"PLAT0101": "Sign in."}.get(code))
    assert r.json == {"code": "PLAT0101", "message": "Sign in."}


# ─── framework errors (C-001: "every" includes them) ─────────────────────────


def test_a_router_miss_is_plat0006():
    r = falcon.testing.TestClient(_app()).simulate_get("/nowhere")
    _assert_c001(r, 404, "PLAT0006")


def test_a_wrong_method_is_plat0007_and_keeps_allow():
    r = falcon.testing.TestClient(_app()).simulate_delete("/x")
    _assert_c001(r, 405, "PLAT0007")
    assert "GET" in r.headers["Allow"]


def test_malformed_media_is_plat0001():
    r = falcon.testing.TestClient(_app()).simulate_post(
        "/x", body=b"{not json", headers={"Content-Type": "application/json"})
    _assert_c001(r, 400, "PLAT0001")


def test_a_host_http_error_maps_by_status():
    _assert_c001(_get(falcon.HTTPConflict()), 409, "PLAT0010")


def test_an_unmapped_status_keeps_its_status_and_is_logged():
    with capture_logs() as logs:
        r = _get(falcon.HTTPError(falcon.HTTP_418))
    assert r.status_code == 418 and r.json["code"] == "PLAT0301"
    assert any(e["event"] == "http_error_unmapped" for e in logs)


def test_anything_unhandled_is_plat0301():
    with capture_logs():
        _assert_c001(_get(RuntimeError("boom")), 500, "PLAT0301")


def test_unhandled_can_be_left_to_the_host():
    r = _get(RuntimeError("boom"), unhandled=False)
    assert r.status_code == 500 and "code" not in (r.json or {})


# ─── the wrong-plane answer, end to end ──────────────────────────────────────


def test_the_wrong_plane_answer_is_byte_identical_to_a_router_miss():
    """RUL-158, through the real middleware and these handlers."""

    def fake(name, header, plane, method):
        async def attempt(req):
            return f"{name}-principal" if req.get_header(header) else None

        return CustomAuthenticator(attempt, plane=plane, method=method,
                                   selector=Selector(header))

    registry = PlaneRegistry()
    mw = PlaneAuthenticationMiddleware(registry, authenticators={
        "access_token": fake("access_token", "Authorization", planes.USER, planes.JWT),
        "mtls": fake("mtls", "X-Client-Cert", planes.SERVICE, planes.MTLS),
    })
    app = falcon.asgi.App(middleware=[mw])
    register_platform_error_handlers(app)

    class Orders:
        async def on_get(self, req, resp):
            resp.media = {}

    mount(registry, app, "/v1/orders", Orders(), plane=planes.USER)
    client = falcon.testing.TestClient(app)
    with capture_logs():
        wrong_plane = client.simulate_get("/v1/orders", headers={"X-Client-Cert": "payments"})
        router_miss = client.simulate_get("/v1/nowhere")
    assert wrong_plane.content == router_miss.content
    _assert_c001(wrong_plane, 404, "PLAT0006")


# ─── overriding and the old shape ────────────────────────────────────────────


def test_a_host_handler_registered_after_wins():
    """Falcon: one handler per class, the most specific class in the MRO."""
    app = _app(CapabilityDenied(capability="a:b"))

    async def mine(req, resp, ex, params):
        resp.status, resp.media = falcon.HTTP_403, {"code": "PRSN0042", "message": "nope"}

    app.add_error_handler(CapabilityDenied, mine)
    assert falcon.testing.TestClient(app).simulate_get("/x").json["code"] == "PRSN0042"


def test_the_pre_c001_registration_is_deprecated_and_unchanged():
    app = falcon.asgi.App()
    with pytest.warns(DeprecationWarning, match="register_platform_error_handlers"):
        register_error_handlers(app)

    class R:
        async def on_get(self, req, resp):
            raise MissingClientCertError()

    app.add_route("/x", R())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        body = falcon.testing.TestClient(app).simulate_get("/x").json
    assert body["code"] == 9000 and body["title"] == "MissingClientCertError"

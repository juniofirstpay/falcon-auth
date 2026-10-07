"""falcon-auth#1 A8: falcon-auth's own errors, in C-001's shape ``{code, message, extras?}``.

falcon-auth registers ONE handler, for its own error base, and renders each of its errors with the
register's message (C-048 §1), the caller-safe extras only, and the exception's own text as a
log-only trace (C-048 §2) -- the same JSON shape the host renders its own errors in. It registers
nothing else: the host's errors, framework ones and unhandled ones stay the host's.
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
    register_falcon_auth_error_handler,
    render_falcon_auth_error,
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

    app = falcon.asgi.App()
    register_falcon_auth_error_handler(app, **register_kwargs)
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
    line = next(e for e in logs if e["event"] == "falcon_auth_error")
    assert "SECRET internal detail 42" in line["trace"]
    assert line["code"] == "PLAT0102" and line["path"] == "/x" and line["method"] == "GET"


def test_an_unknown_cn_is_logged_not_echoed():
    with capture_logs() as logs:
        r = _get(UnknownCNError(cn="stranger.internal"))
    assert "stranger" not in r.text
    assert "stranger.internal" in next(e for e in logs if e["event"] == "falcon_auth_error")["trace"]


def test_a_host_register_overrides_the_copy():
    r = _get(Unauthenticated(), messages=lambda code: {"PLAT0101": "Sign in."}.get(code))
    assert r.json == {"code": "PLAT0101", "message": "Sign in."}


# ─── nothing but falcon-auth's own errors ────────────────────────────────────


def test_it_does_not_take_over_the_hosts_framework_errors():
    """A router miss is the host's to render: falcon-auth leaves Falcon's own default in place."""
    r = falcon.testing.TestClient(_app()).simulate_get("/nowhere")
    assert r.status_code == 404 and "code" not in (r.json or {})


def test_it_does_not_take_over_unhandled_exceptions():
    r = _get(RuntimeError("boom"))
    assert r.status_code == 500 and "code" not in (r.json or {})


def test_it_does_not_take_over_a_hosts_http_error():
    r = _get(falcon.HTTPConflict())
    assert r.status_code == 409 and "code" not in (r.json or {})


def test_a_host_with_one_handler_of_its_own_can_delegate():
    app = falcon.asgi.App()

    async def host_handler(req, resp, ex, params):
        if isinstance(ex, CapabilityDenied):
            render_falcon_auth_error(req, resp, ex)
        else:
            resp.status, resp.media = falcon.HTTP_400, {"code": "PRSN0001", "message": "Bad."}

    app.add_error_handler(Exception, host_handler)

    class R:
        async def on_get(self, req, resp):
            raise CapabilityDenied(capability="kyc:read")

    app.add_route("/x", R())
    with capture_logs():
        r = falcon.testing.TestClient(app).simulate_get("/x")
    _assert_c001(r, 403, "PLAT0102", {"capability": "kyc:read"})


# ─── the wrong-plane answer: the host's router miss, the same shape ──────────


def test_the_wrong_plane_answer_is_the_hosts_router_miss_byte_for_byte():
    """RUL-158. The middleware raises Falcon's HTTPRouteNotFound, so the HOST's router-miss
    handler renders it -- and falcon-auth's own errors come out in the same shape beside it."""

    def fake(name, header, plane, method):
        async def attempt(req):
            value = req.get_header(header)
            if value == "bad":
                raise Unauthenticated(f"invalid {name}")
            return f"{name}-principal" if value else None

        return CustomAuthenticator(attempt, plane=plane, method=method,
                                   selector=Selector(header))

    async def host_router_miss(req, resp, ex, params):     # the host's own C-001 serializer
        resp.status, resp.media = falcon.HTTP_404, {
            "code": "PLAT0006", "message": "The requested resource was not found."}

    registry = PlaneRegistry()
    mw = PlaneAuthenticationMiddleware(registry, authenticators={
        "access_token": fake("access_token", "Authorization", planes.USER, planes.JWT),
        "mtls": fake("mtls", "X-Client-Cert", planes.SERVICE, planes.MTLS),
    })
    app = falcon.asgi.App(middleware=[mw])
    register_falcon_auth_error_handler(app)
    app.add_error_handler(falcon.HTTPRouteNotFound, host_router_miss)

    class Orders:
        async def on_get(self, req, resp):
            resp.media = {}

    mount(registry, app, "/v1/orders", Orders(), plane=planes.USER)
    client = falcon.testing.TestClient(app)
    with capture_logs():
        wrong_plane = client.simulate_get("/v1/orders", headers={"X-Client-Cert": "payments"})
        router_miss = client.simulate_get("/v1/nowhere")
        forged = client.simulate_get("/v1/orders", headers={"Authorization": "bad"})
    assert wrong_plane.content == router_miss.content
    assert set(wrong_plane.json) == set(forged.json) == {"code", "message"}
    _assert_c001(forged, 401, "PLAT0101")


# ─── overriding and the old shape ────────────────────────────────────────────


def test_a_host_handler_registered_after_wins():
    """Falcon: one handler per class, the most specific class in the MRO."""
    app = _app(CapabilityDenied(capability="a:b"))

    async def mine(req, resp, ex, params):
        resp.status, resp.media = falcon.HTTP_403, {"code": "PRSN0042", "message": "nope"}

    app.add_error_handler(CapabilityDenied, mine)
    assert falcon.testing.TestClient(app).simulate_get("/x").json["code"] == "PRSN0042"


# ─── RUL-161: on by default; the old shape is an explicit, recorded exception ─


def _registered(**kw):
    app = falcon.asgi.App()
    register_error_handlers(app, **kw)

    class R:
        async def on_get(self, req, resp):
            raise req.context.raise_this

    async def set_raise(req, resp, resource, params):
        req.context.raise_this = _registered.ex

    app.add_route("/x", falcon.before(set_raise)(R)())
    return falcon.testing.TestClient(app)


@pytest.mark.parametrize(
    "ex, status, code, extras",
    [
        (MissingClientCertError(), 401, "PLAT0103", None),
        (UnknownCNError(cn="s.internal"), 403, "PLAT0104", None),
        (MissingCapabilityError("kyc:read"), 403, "PLAT0102", {"capability": "kyc:read"}),
        (CapabilityDenied(capability="a:b"), 403, "PLAT0102", {"capability": "a:b"}),
        (StepUpRequired(required=2), 401, "PLAT0109", {"required_session_trust_level": 2}),
    ],
    ids=lambda v: type(v).__name__ if isinstance(v, Exception) else None,
)
def test_the_call_hosts_already_make_now_renders_c001(ex, status, code, extras):
    """RUL-160/161: east-west included, by default, with no new call in the host."""
    _registered.ex = ex
    with warnings.catch_warnings():
        warnings.simplefilter("error")       # the default path warns about nothing
        with capture_logs():
            _assert_c001(_registered().simulate_get("/x"), status, code, extras)


def test_render_svcplane_error_registered_by_the_host_renders_c001():
    """persona registers this itself; it gets the new shape without a code change."""
    from falcon_auth.adapters import render_svcplane_error
    from falcon_auth.eastwest.errors import SvcPlaneError

    app = falcon.asgi.App()
    app.add_error_handler(SvcPlaneError, render_svcplane_error)

    class R:
        async def on_get(self, req, resp):
            raise MissingCapabilityError("kyc:write")

    app.add_route("/x", R())
    with capture_logs():
        _assert_c001(falcon.testing.TestClient(app).simulate_get("/x"), 403, "PLAT0102",
                     {"capability": "kyc:write"})


def test_numeric_code_overrides_are_deprecated():
    from falcon_auth import SvcPlaneErrorCodes, Verifier

    with pytest.warns(DeprecationWarning, match="RUL-161"):
        Verifier({}, codes=SvcPlaneErrorCodes(missing_cert=5000))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Verifier({})


def test_the_pre_c001_shape_is_an_explicit_recorded_exception():
    app = falcon.asgi.App()
    with pytest.warns(DeprecationWarning, match="C-001 exception"):
        register_error_handlers(app, legacy_shape=True)

    class R:
        async def on_get(self, req, resp):
            raise MissingClientCertError()

    app.add_route("/x", R())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        body = falcon.testing.TestClient(app).simulate_get("/x").json
    assert body["code"] == 9000 and body["title"] == "MissingClientCertError"

"""A CALLBACK source's HMAC (C-031; falcon-auth#1 A7).

One instance is one source. The signature is over the body's exact bytes, so the app runs inside
`RawBodyBuffer`. Missing or wrong answers `401 PLAT0111`, stale `401 PLAT0112` (registry/PLAT.md).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

import falcon
import falcon.asgi
import falcon.testing
import pytest

from falcon_auth import planes
from falcon_auth.adapters import (
    CallbackSource,
    CustomAuthenticator,
    HMACAuthenticator,
    PlaneAuthenticationMiddleware,
    PlaneRegistry,
    RawBodyBuffer,
    Selector,
    mount,
    register_error_handlers,
)
from falcon_auth.errors import AuthzUnavailable, CallbackSignatureInvalid, CallbackStale

SECRET = b"rail-secret"
BODY = b'{"order_ref":"ord_1","status":"SUCCESS","timestamp":1000}'


def sign(body: bytes = BODY, secret: bytes = SECRET, digest=hashlib.sha256) -> bytes:
    return hmac.new(secret, body, digest).digest()


class _Req:
    def __init__(self, headers=None, body: bytes | None = BODY):
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.scope = {} if body is None else {"falcon_auth.raw_body": body}

    def get_header(self, name):
        return self._headers.get(name.lower())


def _ts(req, body):
    return json.loads(body).get("timestamp")


# ─── the authenticator, alone ────────────────────────────────────────────────


async def test_a_correct_signature_is_the_source():
    auth = HMACAuthenticator(SECRET, source="rail")
    principal = await auth(_Req({"X-Webhook-Signature": sign().hex()}))
    assert principal == CallbackSource(source="rail", method="HMAC")
    assert (auth.planes, auth.method) == (frozenset({"CALLBACK"}), "HMAC")


async def test_hex_is_read_in_either_case():
    auth = HMACAuthenticator(SECRET, source="rail")
    assert await auth(_Req({"X-Webhook-Signature": sign().hex().upper()}))


async def test_no_signature_header_is_absent():
    assert await HMACAuthenticator(SECRET, source="rail")(_Req()) is None


@pytest.mark.parametrize(
    "signature",
    [
        sign(secret=b"other").hex(),          # another key
        sign(b"{}").hex(),                    # another body
        sign().hex()[:-2],                    # truncated
        "not-hex",                            # malformed
        base64.b64encode(sign()).decode(),    # the right digest, the wrong encoding
    ],
    ids=["wrong-key", "wrong-body", "truncated", "malformed", "wrong-encoding"],
)
async def test_a_wrong_signature_is_plat0111(signature):
    with pytest.raises(CallbackSignatureInvalid):
        await HMACAuthenticator(SECRET, source="rail")(_Req({"X-Webhook-Signature": signature}))


async def test_the_body_is_the_exact_bytes():
    """Re-serialising reorders keys and breaks the HMAC; the same object spelled differently
    is a different body."""
    respelled = json.dumps(json.loads(BODY), indent=1).encode()
    with pytest.raises(CallbackSignatureInvalid):
        await HMACAuthenticator(SECRET, source="rail")(
            _Req({"X-Webhook-Signature": sign().hex()}, body=respelled))


async def test_base64_with_a_prefix_and_another_header():
    auth = HMACAuthenticator(SECRET, source="psp", selector=Selector("X-Signature"),
                             prefix="sha512=", encoding="base64", digest="sha512")
    good = "sha512=" + base64.b64encode(sign(digest=hashlib.sha512)).decode()
    assert await auth(_Req({"X-Signature": good}))
    with pytest.raises(CallbackSignatureInvalid):  # prefix missing
        await auth(_Req({"X-Signature": good[len("sha512="):]}))


async def test_base64url_unpadded():
    auth = HMACAuthenticator(SECRET, source="psp", encoding="base64url")
    value = base64.urlsafe_b64encode(sign()).decode().rstrip("=")
    assert await auth(_Req({"X-Webhook-Signature": value}))


async def test_inside_the_window_passes_and_outside_is_plat0112():
    def auth(now):
        return HMACAuthenticator(SECRET, source="rail", timestamp_of=_ts, max_skew=300,
                                 clock=lambda: now)

    headers = {"X-Webhook-Signature": sign().hex()}
    assert await auth(1000 + 300)(_Req(headers))
    assert await auth(1000 - 300)(_Req(headers))
    for now in (1000 + 301, 1000 - 301):
        with pytest.raises(CallbackStale):
            await auth(now)(_Req(headers))


async def test_a_datetime_timestamp_and_a_missing_one():
    signed_at = datetime.fromtimestamp(1000, tz=timezone.utc)
    headers = {"X-Webhook-Signature": sign().hex()}
    fresh = HMACAuthenticator(SECRET, source="rail", timestamp_of=lambda r, b: signed_at,
                              clock=lambda: 1010)
    assert await fresh(_Req(headers))
    none = HMACAuthenticator(SECRET, source="rail", timestamp_of=lambda r, b: None)
    with pytest.raises(CallbackStale):
        await none(_Req(headers))


async def test_the_window_is_read_only_after_the_signature():
    """An unsigned timestamp is the caller's word; a forged callback is PLAT0111, never 0112."""
    auth = HMACAuthenticator(SECRET, source="rail", timestamp_of=_ts, clock=lambda: 10**9)
    with pytest.raises(CallbackSignatureInvalid):
        await auth(_Req({"X-Webhook-Signature": "00" * 32}))


async def test_the_secret_may_rotate_under_a_callable():
    current = [SECRET]
    auth = HMACAuthenticator(lambda: current[0], source="rail")
    assert await auth(_Req({"X-Webhook-Signature": sign().hex()}))
    current[0] = b"next"
    with pytest.raises(CallbackSignatureInvalid):
        await auth(_Req({"X-Webhook-Signature": sign().hex()}))
    assert await auth(_Req({"X-Webhook-Signature": sign(secret=b"next").hex()}))


async def test_a_callable_returning_no_secret_is_503_not_open():
    with pytest.raises(AuthzUnavailable):
        await HMACAuthenticator(lambda: b"", source="rail")(
            _Req({"X-Webhook-Signature": hmac.new(b"", BODY, "sha256").hexdigest()}))


async def test_without_the_raw_body_buffer_it_is_a_wiring_fault():
    with pytest.raises(RuntimeError, match="RawBodyBuffer"):
        await HMACAuthenticator(SECRET, source="rail")(
            _Req({"X-Webhook-Signature": sign().hex()}, body=None))


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"secret": b""}, "non-empty"),
        ({"secret": "text"}, "non-empty"),
        ({"source": ""}, "name"),
        ({"encoding": "base32"}, "encoding"),
        ({"digest": "nope"}, "nope"),
        ({"max_skew": 0}, "max_skew"),
    ],
)
def test_a_broken_configuration_refuses_at_startup(kwargs, match):
    args = {"secret": SECRET, "source": "rail", **kwargs}
    with pytest.raises(ValueError, match=match):
        HMACAuthenticator(args.pop("secret"), **args)


# ─── through the plane middleware, rendered ─────────────────────────────────


class Callback:
    async def on_post(self, req, resp):
        resp.media = {"source": req.context.auth_principal.source}


class Orders:
    async def on_get(self, req, resp):
        resp.media = {}


async def _user(req):
    token = Selector("Authorization", "Bearer").extract(req)
    return {"sub": "u1"} if token == "good" else None


def _client():
    registry = PlaneRegistry()
    mw = PlaneAuthenticationMiddleware(registry, authenticators={
        "rail_hmac": HMACAuthenticator(SECRET, source="rail", timestamp_of=_ts,
                                       clock=lambda: 1000),
        "access_token": CustomAuthenticator(_user, plane=planes.USER, method=planes.JWT,
                                            selector=Selector("Authorization", "Bearer")),
    })
    app = falcon.asgi.App(middleware=[mw])
    register_error_handlers(app)
    mount(registry, app, "/v1/callbacks/rail", Callback(), plane=planes.CALLBACK)
    mount(registry, app, "/v1/orders", Orders(), plane=planes.USER, actor_types={"CUSTOMER"})
    mw.verify()
    return falcon.testing.TestClient(RawBodyBuffer(app))


def _post(client, headers):
    return client.simulate_post("/v1/callbacks/rail", body=BODY, headers=headers)


def test_a_signed_callback_reaches_the_handler_as_its_source():
    r = _post(_client(), {"X-Webhook-Signature": sign().hex()})
    assert (r.status_code, r.json) == (200, {"source": "rail"})


@pytest.mark.parametrize(
    "headers",
    [{}, {"X-Webhook-Signature": "00" * 32}],
    ids=["missing", "wrong"],
)
def test_missing_or_wrong_is_one_answer_plat0111(headers):
    r = _post(_client(), headers)
    assert r.status_code == 401
    assert r.json == {"code": "PLAT0111", "message": "The request could not be authorised."}


def test_stale_is_plat0112():
    body = BODY.replace(b"1000", b"1")
    r = _client().simulate_post("/v1/callbacks/rail", body=body,
                                headers={"X-Webhook-Signature": sign(body).hex()})
    assert (r.status_code, r.json["code"]) == (401, "PLAT0112")


def test_a_valid_user_token_on_a_callback_route_is_the_router_miss():
    """C-060 §6: a valid credential for another plane is 404 PLAT0006, not the 401."""
    r = _post(_client(), {"Authorization": "Bearer good"})
    assert r.status_code == 404

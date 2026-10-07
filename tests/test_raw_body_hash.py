"""Issue #7 / #11 item 7: the step-up body binding hashes the raw bytes (C-058, `v28`).

`request_body_hash` = base64url, unpadded, SHA-256 over the exact bytes of the request body, hashed
by the consuming service as received, before any decode. C-058 superseded C-030's JCS clause.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import warnings

import falcon
import falcon.asgi
import falcon.testing
import pytest

from falcon_auth import raw_body_hash
from falcon_auth.adapters import RawBodyBuffer, raw_body
from falcon_auth.adapters.hooks import verify_operation_for
from falcon_auth.assurance.operation import OperationBodyMismatch, OperationVerification


# ─── the hash ────────────────────────────────────────────────────────────────


def test_the_empty_body_vector():
    """A fixed vector: SHA-256 of b"" in unpadded base64url."""
    assert raw_body_hash(b"") == "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"


def test_it_is_base64url_unpadded_sha256_of_the_exact_bytes():
    body = b'{"amount": 100,  "currency":"INR"}'
    expected = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
    assert raw_body_hash(body) == expected
    assert "=" not in expected


def test_no_canonicalization_two_spellings_of_one_object_differ():
    """The point of C-058: bytes, not meaning. Key order and whitespace count."""
    assert raw_body_hash(b'{"a":1,"b":2}') != raw_body_hash(b'{"b":2,"a":1}')
    assert raw_body_hash(b'{"a":1}') != raw_body_hash(b'{"a": 1}')


# ─── the buffer ──────────────────────────────────────────────────────────────


class Echo:
    """Reads the body the way a handler would, AND the raw bytes, to prove both survive."""

    async def on_post(self, req, resp):
        resp.media = {
            "media": await req.get_media(),
            "raw_hash": raw_body_hash(raw_body(req.scope) or b"-"),
        }


def _client(**kw):
    app = falcon.asgi.App()
    app.add_route("/x", Echo())
    return falcon.testing.TestClient(RawBodyBuffer(app, **kw))


def test_the_handler_still_gets_its_media_and_the_hash_is_over_the_sent_bytes():
    body = b'{"b": 2,   "a": 1}'
    r = _client().simulate_post("/x", body=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    assert r.json["media"] == {"a": 1, "b": 2}
    assert r.json["raw_hash"] == raw_body_hash(body)


def test_a_body_in_several_chunks_is_kept_whole():
    received = []

    async def app(scope, receive, send):
        message = await receive()
        received.append((message["body"], raw_body(scope)))
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    chunks = iter([
        {"type": "http.request", "body": b'{"a":', "more_body": True},
        {"type": "http.request", "body": b"1}", "more_body": False},
    ])

    async def receive():
        return next(chunks)

    async def send(message):
        pass

    asyncio.run(RawBodyBuffer(app)({"type": "http"}, receive, send))
    assert received == [(b'{"a":1}', b'{"a":1}')]


def test_a_body_over_the_limit_is_413_before_the_app_runs():
    r = _client(max_bytes=4).simulate_post("/x", body=b"0123456789")
    assert r.status_code == 413


def test_non_http_scopes_pass_through_untouched():
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    asyncio.run(RawBodyBuffer(app)({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]


def test_without_the_buffer_there_are_no_raw_bytes():
    """None, never b"" -- an unwired app must not read as an empty body."""
    assert raw_body({"type": "http"}) is None


# ─── verify_operation_for(bind_body=True) ────────────────────────────────────


class _Verifier:
    def __init__(self, bound_hash):
        self.bound_hash = bound_hash

    async def verify(self, session_ref, operation_id, *, user_ref):
        return OperationVerification.model_validate({
            "session_ref": session_ref, "user_ref": user_ref, "operation_id": operation_id,
            "purpose": "profile.update", "target_session_tier": 2,
            "request_body_hash": self.bound_hash, "consumed_at": "2026-10-07T10:00:00Z",
        })


def _stepup_client(verifier, *, wrap=True, **kwargs):
    class Resource:
        async def on_patch(self, req, resp):
            await verify_operation_for(
                req, verifier, lambda r: ("sess-1", "user-1"),
                expected_purpose="profile.update", **kwargs,
            )
            resp.media = {"ok": True, "body": await req.get_media()}

    async def mismatch(req, resp, ex, params):
        resp.status, resp.media = falcon.HTTP_409, {"error": "body_mismatch"}

    async def wiring(req, resp, ex, params):
        resp.status, resp.media = falcon.HTTP_500, {"error": type(ex).__name__, "detail": str(ex)}

    app = falcon.asgi.App()
    app.add_error_handler(OperationBodyMismatch, mismatch)
    app.add_error_handler(RuntimeError, wiring)
    app.add_error_handler(TypeError, wiring)
    app.add_route("/profile", Resource())
    return falcon.testing.TestClient(RawBodyBuffer(app) if wrap else app)


BODY = b'{"name":"x"}'
HEADERS = {"X-Operation-ID": "op-1", "Content-Type": "application/json"}


def test_the_bytes_the_client_hashed_pass_and_the_handler_still_reads_its_body():
    r = _stepup_client(_Verifier(raw_body_hash(BODY)), bind_body=True).simulate_patch(
        "/profile", body=BODY, headers=HEADERS)
    assert r.status_code == 200 and r.json == {"ok": True, "body": {"name": "x"}}


def test_the_same_object_in_other_bytes_is_a_mismatch():
    r = _stepup_client(_Verifier(raw_body_hash(BODY)), bind_body=True).simulate_patch(
        "/profile", body=b'{"name": "x"}', headers=HEADERS)
    assert r.status_code == 409


def test_binding_the_body_without_the_buffer_is_a_wiring_error_not_a_wrong_hash():
    client = _stepup_client(_Verifier(raw_body_hash(BODY)), wrap=False, bind_body=True)
    r = client.simulate_patch("/profile", body=BODY, headers=HEADERS)
    assert r.status_code == 500 and r.json["error"] == "RuntimeError"
    assert "RawBodyBuffer" in r.json["detail"]


def test_the_old_media_hasher_still_works_and_warns():
    client = _stepup_client(_Verifier("h"), body_hash=lambda media: "h")
    with pytest.warns(DeprecationWarning, match="C-058"):
        r = client.simulate_patch("/profile", body=BODY, headers=HEADERS)
    assert r.status_code == 200


def test_both_spellings_at_once_are_refused():
    client = _stepup_client(_Verifier("h"), bind_body=True, body_hash=lambda m: "h")
    r = client.simulate_patch("/profile", body=BODY, headers=HEADERS)
    assert r.json["error"] == "TypeError" and "not both" in r.json["detail"]


def test_an_unbound_purpose_needs_no_body():
    """A null bound hash means the purpose is not body-bound; nothing to compare."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        r = _stepup_client(_Verifier(None), bind_body=True).simulate_patch(
            "/profile", body=BODY, headers=HEADERS)
    assert r.status_code == 200

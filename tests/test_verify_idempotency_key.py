"""falcon-auth#45: the operation verify carries a fresh Idempotency-Key auth will accept.

Auth runs its idempotency hook on ``:verify`` before it reads anything else (ppi-backend-auth
``app/hooks/idempotency.py``): no key is ``400 PLAT0009``, a key outside
``^[A-Za-z0-9_-]{16,64}$`` is ``400 PLAT0001``. The fake below refuses the same way, so it
proves the key is present and well-formed. The positive control shows it really does refuse.
The key is fresh on every call and never reused, because a step-up can be spent only once: a
repeated verify must reach auth and get the consumed challenge (410), not a replayed 200.
"""
from __future__ import annotations

import re
from contextlib import asynccontextmanager

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from structlog.testing import capture_logs

from falcon_auth.assurance.operation import HttpOperationVerifier, OperationChallengeMiss
from falcon_auth.errors import AuthzMisconfigured

VERIFY = "/v1/svc/sessions/{session_ref}/operations/{operation_id}:verify"
_KEY = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
OK = {
    "session_ref": "sess-1", "user_ref": "user-1", "operation_id": "op-1",
    "purpose": "wallet.transfer", "target_session_tier": 2,
    "request_body_hash": None, "consumed_at": "2026-11-06T15:16:00Z",
}


@asynccontextmanager
async def auth():
    """A fake of auth's :verify: the idempotency hook's refusals, then a single-use challenge."""
    keys: list[str | None] = []
    consumed: set[str] = set()

    async def verify(request):
        key = request.headers.get("Idempotency-Key")
        keys.append(key)
        if not key:
            return web.json_response({"code": "PLAT0009", "message": "x"}, status=400)
        if not _KEY.match(key):
            return web.json_response({"code": "PLAT0001", "message": "x"}, status=400)
        op = request.match_info["o"]
        if op in consumed:
            return web.json_response({"code": "AUTH8501", "message": "x"}, status=410)
        consumed.add(op)
        return web.json_response(OK)

    app = web.Application()
    app.router.add_post("/v1/svc/sessions/{s}/operations/{o}:verify", verify)
    server = TestServer(app)
    await server.start_server()
    session = aiohttp.ClientSession(base_url=str(server.make_url("/")))
    session._retry_connection = False
    try:
        yield session, keys
    finally:
        await session.close()
        await server.close()


async def test_the_verify_carries_a_key_auth_accepts():
    async with auth() as (session, keys):
        verifier = HttpOperationVerifier(lambda: session, path_template=VERIFY)
        out = await verifier.verify("sess-1", "op-1", user_ref="user-1")
    assert out.operation_id == "op-1"
    assert len(keys) == 1 and _KEY.match(keys[0])


async def test_a_repeated_verify_meets_the_consumed_challenge_not_a_replay():
    async with auth() as (session, keys):
        verifier = HttpOperationVerifier(lambda: session, path_template=VERIFY)
        await verifier.verify("sess-1", "op-1", user_ref="user-1")
        with pytest.raises(OperationChallengeMiss):
            await verifier.verify("sess-1", "op-1", user_ref="user-1")
    assert keys[0] != keys[1], "a fresh key per call, never reused"


@pytest.mark.parametrize("headers, code", [({}, "PLAT0009"), ({"Idempotency-Key": "short"}, "PLAT0001")])
async def test_positive_control_the_fake_refuses_a_missing_or_bad_key(headers, code):
    async with auth() as (session, _):
        async with session.post(
            VERIFY.format(session_ref="sess-1", operation_id="op-1"),
            json={"user_ref": "user-1"}, headers=headers,
        ) as response:
            assert response.status == 400
            assert (await response.json())["code"] == code


@pytest.mark.parametrize("code", ["PLAT0009", "PLAT0001"])
async def test_auth_refusing_our_request_is_our_fault_not_a_bad_answer(code):
    """Optional ask 3: these two mean the CLIENT is wrong -- 500 PLAT0301, not 502 PLAT0304."""
    class _Resp:
        status = 400

        async def json(self):
            return {"code": code, "message": "x"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Session:
        def post(self, path, **kw):
            return _Resp()

    verifier = HttpOperationVerifier(lambda: _Session(), path_template=VERIFY)  # type: ignore[arg-type,return-value]
    with capture_logs(), pytest.raises(AuthzMisconfigured) as e:
        await verifier.verify("sess-1", "op-1", user_ref="user-1")
    assert e.value.plat_code == "PLAT0301"

"""falcon-auth#28 (2) / C-064: the package's own calls follow no redirect and make one attempt.

Against a real aiohttp server: auth's two endpoints answer a 3xx pointing at a decoy, and the
decoy counts what reaches it. Before, a plain session followed the redirect -- whatever the host's
own factory did, because aiohttp takes ``allow_redirects`` per request.
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from structlog.testing import capture_logs

from falcon_auth import outbound
from falcon_auth.assurance.operation import HttpOperationVerifier
from falcon_auth.errors import AuthzUnavailable
from falcon_auth.trustcontext import HttpTrustContextClient

FEED = {
    "session_ref": "sess-1", "user_ref": "user-1", "client_ref": "c", "device_ref": None,
    "session_state": 1, "device_trust_level": 3, "session_trust_level": 1,
    "trust_elevated_until": None, "grants": ["CUSTOMER_GRANT"], "actor_type": "CUSTOMER",
    "session_kind": "NORMAL", "delegations": [],
}
VERIFIED = {
    "session_ref": "sess-1", "user_ref": "user-1", "operation_id": "op-1",
    "purpose": "p", "target_session_tier": 2, "request_body_hash": None,
    "consumed_at": "2026-10-20T00:00:00Z",
}
TRUST = "/v1/internal/sessions/{session_ref}/trust-context"
VERIFY = "/v1/internal/sessions/{session_ref}/operations/{operation_id}:verify"


@asynccontextmanager
async def auth(status: int = 200):
    """Auth answering `status` -- a 3xx points at /decoy. `hits` counts every request."""
    hits: dict[str, int] = {}

    async def trust(request):
        hits["trust"] = hits.get("trust", 0) + 1
        if 300 <= status < 400:
            return web.Response(status=status, headers={"Location": "/decoy"})
        return web.json_response(FEED)

    async def verify(request):
        hits["verify"] = hits.get("verify", 0) + 1
        hits["body"] = json.loads(await request.read())
        if 300 <= status < 400:
            return web.Response(status=status, headers={"Location": "/decoy"})
        return web.json_response(VERIFIED)

    async def decoy(request):
        hits["decoy"] = hits.get("decoy", 0) + 1
        return web.json_response(FEED)

    app = web.Application()
    app.router.add_get("/v1/internal/sessions/{s}/trust-context", trust)
    app.router.add_post("/v1/internal/sessions/{s}/operations/{o}:verify", verify)
    app.router.add_route("*", "/decoy", decoy)
    server = TestServer(app)
    await server.start_server()
    try:
        yield server, hits
    finally:
        await server.close()


def _clients(session):
    return (
        HttpTrustContextClient(lambda: session, path_template=TRUST, api_version=None),
        HttpOperationVerifier(lambda: session, path_template=VERIFY, api_version=None),
    )


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_a_redirect_is_the_answer_never_a_second_request(status):
    async with auth(status) as (server, hits), aiohttp.ClientSession(
            base_url=str(server.make_url("/"))) as session:
        trust, verify = _clients(session)
        with capture_logs() as logs:
            with pytest.raises(AuthzUnavailable, match="redirect"):
                await trust.fetch("sess-1", user_ref="user-1")
            with pytest.raises(AuthzUnavailable, match="redirect"):
                await verify.verify("sess-1", "op-1", user_ref="user-1")
    assert hits.get("decoy", 0) == 0, "nothing reached the redirect's target"
    assert (hits["trust"], hits["verify"]) == (1, 1)
    refused = [e for e in logs if e["event"] == "outbound redirect not followed"]
    assert {e["location"] for e in refused} == {"/decoy"}, "Location goes to the log only"


async def test_the_calls_still_work():
    async with auth() as (server, hits), aiohttp.ClientSession(
            base_url=str(server.make_url("/"))) as session:
        trust, verify = _clients(session)
        assert (await trust.fetch("sess-1", user_ref="user-1")).user_ref == "user-1"
        assert (await verify.verify("sess-1", "op-1", user_ref="user-1")).operation_id == "op-1"
    assert hits["body"] == {"user_ref": "user-1"}


async def test_a_session_resending_on_a_dropped_connection_is_reported_once():
    async with auth() as (server, _), aiohttp.ClientSession(
            base_url=str(server.make_url("/"))) as session:
        trust, _v = _clients(session)
        with capture_logs() as logs:
            await trust.fetch("sess-1", user_ref="user-1")
            await trust.fetch("sess-1", user_ref="user-1")
        assert [e["event"] for e in logs].count("outbound_session_resends_on") == 1

        session._retry_connection = False  # what C-064 §3 asks of the host's factory
        outbound._reported.discard(id(session))
        with capture_logs() as logs:
            await trust.fetch("sess-1", user_ref="user-1")
        assert "outbound_session_resends_on" not in [e["event"] for e in logs]


async def test_a_hosts_own_strict_wrapper_is_called_in_its_own_shape():
    """Orders' StrictSession takes no allow_redirects and no json=: it enforces C-064 itself.
    The package must call it with only (url, params|data, headers)."""
    calls = []

    class _Resp:
        def __init__(self, body):
            self.status, self._body, self.headers = 200, body, {}

        async def json(self):
            return self._body

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class StrictSession:
        def get(self, url, *, params=None, headers=None):
            calls.append(("GET", url, params, headers))
            return _Resp(FEED)

        def post(self, url, *, data=None, headers=None):
            calls.append(("POST", url, json.loads(data), headers))
            return _Resp(VERIFIED)

    trust, verify = _clients(StrictSession())
    await trust.fetch("sess-1", user_ref="user-1")
    await verify.verify("sess-1", "op-1", user_ref="user-1")
    assert calls[0][:3] == ("GET", "/v1/internal/sessions/sess-1/trust-context",
                            {"user_ref": "user-1"})
    assert calls[1][2] == {"user_ref": "user-1"}
    assert calls[1][3]["Content-Type"] == "application/json"

"""falcon-auth#31 / C-066 §3-§4: when auth gives no usable answer, say WHAT happened.

    unavailable -- refused, connect timeout, 5xx    503 PLAT0302 + Retry-After
    timed out AFTER the request was sent            504 PLAT0303
    unusable -- 3xx, bad shape, unmapped status     502 PLAT0304
    auth refused THIS service (403)                 500 PLAT0301

Against a real aiohttp server, for both of the package's calls to auth.
"""
from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager

import aiohttp
import falcon
import falcon.asgi
import falcon.testing
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from structlog.testing import capture_logs

from falcon_auth import outbound
from falcon_auth.adapters import register_error_handlers
from falcon_auth.assurance.operation import HttpOperationVerifier
from falcon_auth.entitlement.resolver import AuthServiceResolver
from falcon_auth.errors import (
    AuthzMisconfigured,
    AuthzUnavailable,
    UpstreamBadResponse,
    UpstreamTimeout,
)
from falcon_auth.trustcontext import HttpTrustContextClient, TrustContextCache

FEED = {
    "session_ref": "sess-1", "user_ref": "user-1", "client_ref": "c", "device_ref": None,
    "session_state": 1, "device_trust_level": 3, "session_trust_level": 1,
    "trust_elevated_until": None, "grants": ["CUSTOMER_GRANT"], "actor_type": "CUSTOMER",
    "session_kind": "NORMAL", "delegations": [],
}
TRUST = "/v1/internal/sessions/{session_ref}/trust-context"
VERIFY = "/v1/internal/sessions/{session_ref}/operations/{operation_id}:verify"


def _answer(kind):
    async def handler(request):
        if kind == "slow":
            await asyncio.sleep(1)
        if kind == "garbage":
            return web.json_response({"nothing": "useful"})
        if kind == "not-json":
            return web.Response(text="<html>gateway</html>", content_type="text/html")
        if isinstance(kind, int):
            return web.json_response({"code": 1}, status=kind)
        return web.json_response(FEED)
    return handler


@asynccontextmanager
async def auth(kind, *, read_timeout=None):
    app = web.Application()
    app.router.add_get("/v1/internal/sessions/{s}/trust-context", _answer(kind))
    app.router.add_post("/v1/internal/sessions/{s}/operations/{o}:verify", _answer(kind))
    server = TestServer(app)
    await server.start_server()
    timeout = aiohttp.ClientTimeout(sock_read=read_timeout) if read_timeout else None
    session = aiohttp.ClientSession(base_url=str(server.make_url("/")), timeout=timeout)
    session._retry_connection = False
    try:
        yield (HttpTrustContextClient(lambda: session, path_template=TRUST),
               HttpOperationVerifier(lambda: session, path_template=VERIFY))
    finally:
        await session.close()
        await server.close()


async def _both(trust, verify, expected):
    with capture_logs():
        with pytest.raises(expected) as a:
            await trust.fetch("sess-1", user_ref="user-1")
        with pytest.raises(expected) as b:
            await verify.verify("sess-1", "op-1", user_ref="user-1")
    return a.value, b.value


@pytest.mark.parametrize("kind, expected, code", [
    (500, AuthzUnavailable, "PLAT0302"),
    (503, AuthzUnavailable, "PLAT0302"),
    (301, UpstreamBadResponse, "PLAT0304"),
    (307, UpstreamBadResponse, "PLAT0304"),
    (400, UpstreamBadResponse, "PLAT0304"),
    (422, UpstreamBadResponse, "PLAT0304"),
    ("garbage", UpstreamBadResponse, "PLAT0304"),
    ("not-json", UpstreamBadResponse, "PLAT0304"),
    (403, AuthzMisconfigured, "PLAT0301"),
])
async def test_each_kind_of_answer(kind, expected, code):
    async with auth(kind) as (trust, verify):
        a, b = await _both(trust, verify, expected)
    assert a.plat_code == b.plat_code == code


async def test_a_timeout_after_the_send_is_504():
    async with auth("slow", read_timeout=0.1) as (trust, verify):
        a, b = await _both(trust, verify, UpstreamTimeout)
    assert a.plat_code == "PLAT0303"


async def test_nobody_listening_is_503():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    session = aiohttp.ClientSession(base_url=f"http://127.0.0.1:{port}/")
    try:
        trust = HttpTrustContextClient(lambda: session, path_template=TRUST)
        with capture_logs(), pytest.raises(AuthzUnavailable) as e:
            await trust.fetch("sess-1", user_ref="user-1")
        assert type(e.value) is AuthzUnavailable and e.value.plat_code == "PLAT0302"
    finally:
        await session.close()


@pytest.mark.skipif(not hasattr(aiohttp, "ConnectionTimeoutError"), reason="aiohttp < 3.10")
def test_a_connect_timeout_is_503_nothing_was_sent():
    e = outbound.transport_failure(aiohttp.ConnectionTimeoutError(), call="x")
    assert type(e) is AuthzUnavailable


def test_an_unplaceable_timeout_reads_as_after_send():
    assert type(outbound.transport_failure(asyncio.TimeoutError(), call="x")) is UpstreamTimeout


# ─── rendered, and what C-017 still does with each ──────────────────────────


def test_the_wire():
    app = falcon.asgi.App()
    register_error_handlers(app)

    def raising(exc):
        class R:
            async def on_get(self, req, resp):
                raise exc
        return R()

    for path, exc in [("/a", AuthzUnavailable("x")), ("/b", UpstreamTimeout("x")),
                      ("/c", UpstreamBadResponse("x")), ("/d", AuthzMisconfigured("x"))]:
        app.add_route(path, raising(exc))
    client = falcon.testing.TestClient(app)
    with capture_logs():
        got = {p: client.simulate_get(p) for p in "/a /b /c /d".split()}
    assert {p: (r.status_code, r.json["code"]) for p, r in got.items()} == {
        "/a": (503, "PLAT0302"), "/b": (504, "PLAT0303"),
        "/c": (502, "PLAT0304"), "/d": (500, "PLAT0301")}
    assert got["/a"].headers.get("Retry-After") == "5"
    assert "Retry-After" not in got["/b"].headers


class _Mem:
    def __init__(self):
        self.store = {}

    async def get(self, k):
        return self.store.get(k)

    async def set(self, k, v, ttl):
        self.store[k] = v


class _User:
    id = "user-1"

    def get(self, key):
        return {"sid": "sess-1"}.get(key)


class _Auth:
    def __init__(self):
        self.next = None

    async def fetch(self, session_ref, *, user_ref):
        if self.next is not None:
            raise self.next
        from falcon_auth.trustcontext import TrustContext
        return TrustContext.model_validate(FEED)


@pytest.mark.parametrize("failure", [UpstreamTimeout("t"), UpstreamBadResponse("b")])
async def test_a_routine_operation_still_gets_the_last_good_copy(failure):
    """C-017, as the authority kept it: 504 and 502 are 'auth gave no usable answer'."""
    auth = _Auth()
    resolver = AuthServiceResolver(auth, TrustContextCache(_Mem()))
    await resolver.resolve(_User())
    auth.next = failure
    with capture_logs():
        assert (await resolver.resolve(_User())).user_ref == "user-1"
        with pytest.raises(type(failure)):
            await resolver.resolve(_User(), consequential=True)


async def test_a_misconfiguration_is_never_hidden_behind_the_copy():
    auth = _Auth()
    resolver = AuthServiceResolver(auth, TrustContextCache(_Mem()))
    await resolver.resolve(_User())
    auth.next = AuthzMisconfigured("403")
    with pytest.raises(AuthzMisconfigured):
        await resolver.resolve(_User())

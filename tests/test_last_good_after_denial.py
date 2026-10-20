"""falcon-auth#30: a session auth has DENIED is never served from the last-good copy.

The issue's sequence, replayed: t=0 fetch succeeds (copy written) -> t=10 auth denies (404/410,
or a non-ENABLED state) -> t=20 auth unreachable. Before the fix the t=0 copy was served at
t=20, on every worker sharing the cache, for up to the last-good TTL.
"""
from __future__ import annotations

import pytest
from structlog.testing import capture_logs

from falcon_auth.entitlement.resolver import AuthServiceResolver
from falcon_auth.errors import AuthzUnavailable, SessionMiss
from falcon_auth.trustcontext import (
    SESSION_STATE_ENABLED,
    SESSION_STATE_REVOKED,
    TrustContext,
    TrustContextCache,
)

CTX = {
    "session_ref": "sess-1",
    "user_ref": "user-1",
    "session_trust_level": 1,
    "device_trust_level": 3,
    "client_ref": "client-1",
    "device_ref": "device-1",
    "trust_elevated_until": None,
    "actor_type": "CUSTOMER",
    "session_kind": "NORMAL",
    "delegations": [],
    "grants": ["CUSTOMER_GRANT"],
}


class _Mem:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ttl):
        self.store[key] = value


class _Auth:
    """Answers whatever `next` is set to: a state, or an exception."""

    def __init__(self):
        self.next: object = SESSION_STATE_ENABLED

    async def fetch(self, session_ref, *, user_ref):
        if isinstance(self.next, Exception):
            raise self.next
        return TrustContext.model_validate({**CTX, "session_state": self.next})


class _User:
    id = "user-1"

    def get(self, key):
        return {"sid": "sess-1"}.get(key)


def _setup():
    auth, mem = _Auth(), _Mem()
    return auth, mem, AuthServiceResolver(auth, TrustContextCache(mem))


async def test_the_copy_serves_an_outage_while_the_session_is_live():
    """The degraded mode itself still works -- the fix must not remove it."""
    auth, _, resolver = _setup()
    await resolver.resolve(_User())
    auth.next = AuthzUnavailable("down")
    assert (await resolver.resolve(_User())).user_ref == "user-1"


@pytest.mark.parametrize("denial", [SessionMiss("410"), SESSION_STATE_REVOKED],
                         ids=["404-410", "200-revoked"])
async def test_after_a_denial_an_outage_fails_closed(denial):
    auth, _, resolver = _setup()
    await resolver.resolve(_User())                      # t=0: copy written

    auth.next = denial                                   # t=10: auth denies
    with pytest.raises(SessionMiss):
        await resolver.resolve(_User())

    auth.next = AuthzUnavailable("down")                 # t=20: auth unreachable
    with pytest.raises(AuthzUnavailable):
        await resolver.resolve(_User())


async def test_the_denial_reaches_every_worker_sharing_the_cache():
    """The copy lives in the SHARED cache, so one worker's denial must end it for all."""
    auth, mem, worker_a = _setup()
    worker_b = AuthServiceResolver(auth, TrustContextCache(mem))
    await worker_b.resolve(_User())
    auth.next = SessionMiss("410")
    with pytest.raises(SessionMiss):
        await worker_a.resolve(_User())
    auth.next = AuthzUnavailable("down")
    with pytest.raises(AuthzUnavailable):
        await worker_b.resolve(_User())


async def test_a_new_live_answer_writes_a_fresh_copy_over_the_tombstone():
    auth, _, resolver = _setup()
    auth.next = SessionMiss("410")
    with pytest.raises(SessionMiss):
        await resolver.resolve(_User())
    auth.next = SESSION_STATE_ENABLED
    await resolver.resolve(_User())
    auth.next = AuthzUnavailable("down")
    assert await resolver.resolve(_User())


async def test_a_cache_failure_never_masks_the_denial():
    class _Broken(_Mem):
        async def set(self, key, value, ttl):
            raise ConnectionError("redis down")

    auth = _Auth()
    auth.next = SessionMiss("410")
    resolver = AuthServiceResolver(auth, TrustContextCache(_Broken()))
    with capture_logs() as logs, pytest.raises(SessionMiss):
        await resolver.resolve(_User())
    assert any("last-good" in e["event"] for e in logs)


async def test_the_degraded_mode_warning_logs_no_session_ref():
    auth, _, resolver = _setup()
    await resolver.resolve(_User())
    auth.next = AuthzUnavailable("down")
    with capture_logs() as logs:
        await resolver.resolve(_User())
    (warning,) = [e for e in logs if "last-good" in e["event"]]
    assert "session_ref" not in warning
    assert "sess-1" not in str(warning.values())
    assert len(warning["session_ref_hash"]) == 16

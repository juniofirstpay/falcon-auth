"""falcon-auth#42 / C-079 §6: the routine trust-context cache, restored with a tunable TTL.

    routine read, copy younger than routine_ttl     served from cache, no call to auth
    routine read, copy at/after routine_ttl         fresh call
    consequential read                              always fresh, whatever the cache holds
    fresh=True (resolve or require)                 fresh call (C-079 §6: "may always pull fresh")
    max_age (#41's jti_staleness seam)              tightens the routine bound, never loosens it
    SessionMiss / non-ENABLED answer                destroys the copy; never served afterwards
    a 0.9.x entry (no fetch time)                   unknown age: never fresh, still last-good

Every test here runs against a real `AuthServiceResolver` over a shared dict cache and counts the
calls that reach auth -- the count IS the assertion that a read was or was not served from cache.
"""
from __future__ import annotations

import json
import math
from types import SimpleNamespace

import pytest
from structlog.testing import capture_logs

from falcon_auth.adapters.hooks import require
from falcon_auth.adapters.middleware import ACTOR_TYPES_ATTR
from falcon_auth.entitlement import build_enforcer
from falcon_auth.entitlement.grants import GrantRow
from falcon_auth.entitlement.resolver import AuthServiceResolver
from falcon_auth.errors import AuthzUnavailable, SessionMiss
from falcon_auth.trustcontext import (
    DEFAULT_ROUTINE_TTL,
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
T0 = 1_000_000.0


class _Mem:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ttl):
        self.store[key] = value


class _Auth:
    """Counts fetches; answers whatever `next` is: a session state, or an exception."""

    def __init__(self):
        self.calls = 0
        self.next: object = SESSION_STATE_ENABLED
        self.grants = ["CUSTOMER_GRANT"]

    async def fetch(self, session_ref, *, user_ref):
        self.calls += 1
        if isinstance(self.next, Exception):
            raise self.next
        return TrustContext.model_validate(
            {**CTX, "session_state": self.next, "grants": list(self.grants)})


class _User:
    id = "user-1"

    def get(self, key):
        return {"sid": "sess-1"}.get(key)


class _Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


def _setup(routine_ttl: float = DEFAULT_ROUTINE_TTL):
    auth, mem, clock = _Auth(), _Mem(), _Clock()
    cache = TrustContextCache(mem, routine_ttl=routine_ttl, clock=clock)
    return auth, mem, clock, AuthServiceResolver(auth, cache)


# ── 1. routine reads are served from cache within the TTL ─────────────────────


async def test_a_routine_read_within_the_ttl_does_not_call_auth():
    auth, _, clock, resolver = _setup(routine_ttl=60)
    await resolver.resolve(_User())
    assert auth.calls == 1
    clock.now += 59
    auth.grants = ["SOMETHING_NEWER"]                    # what a fresh read WOULD return
    principal = await resolver.resolve(_User())
    assert auth.calls == 1                               # served from cache ...
    assert principal.entitlements == ["CUSTOMER_GRANT"]  # ... and it shows


async def test_the_routine_copy_is_shared_across_workers():
    auth, mem, clock, worker_a = _setup()
    worker_b = AuthServiceResolver(auth, TrustContextCache(mem, clock=clock))
    await worker_a.resolve(_User())
    await worker_b.resolve(_User())
    assert auth.calls == 1


@pytest.mark.parametrize("elapsed", [60, 61, 899])
async def test_a_routine_read_at_or_past_the_ttl_reads_fresh(elapsed):
    auth, _, clock, resolver = _setup(routine_ttl=60)
    await resolver.resolve(_User())
    clock.now += elapsed
    auth.grants = ["SOMETHING_NEWER"]
    assert (await resolver.resolve(_User())).entitlements == ["SOMETHING_NEWER"]
    assert auth.calls == 2


async def test_a_fresh_read_restarts_the_window():
    auth, _, clock, resolver = _setup(routine_ttl=60)
    await resolver.resolve(_User())
    clock.now += 60
    await resolver.resolve(_User())                      # fresh, rewrites the copy
    clock.now += 30
    await resolver.resolve(_User())
    assert auth.calls == 2


async def test_routine_ttl_zero_turns_the_cache_off():
    auth, _, _, resolver = _setup(routine_ttl=0)
    for _ in range(3):
        await resolver.resolve(_User())
    assert auth.calls == 3


@pytest.mark.parametrize("bad", [-1, math.inf, math.nan])
def test_a_nonsense_routine_ttl_is_refused(bad):
    with pytest.raises(ValueError, match="routine_ttl"):
        TrustContextCache(_Mem(), routine_ttl=bad)


async def test_a_cached_elevation_that_has_lapsed_is_projected_away():
    """A cached copy is projected, exactly like the last-good copy always was."""
    auth, mem, clock, resolver = _setup()
    cache = TrustContextCache(mem, clock=clock)
    await cache.write(TrustContext.model_validate({
        **CTX, "session_state": 1, "session_trust_level": 2,
        "trust_elevated_until": "2000-01-01T00:00:00.000Z",
    }))
    principal = await resolver.resolve(_User())
    assert auth.calls == 0
    assert principal.session_trust_level == 1


async def test_a_cache_that_fails_on_read_is_a_miss_not_a_refusal():
    class _Broken(_Mem):
        async def get(self, key):
            raise ConnectionError("redis down")

    auth = _Auth()
    resolver = AuthServiceResolver(auth, TrustContextCache(_Broken()))
    with capture_logs() as logs:
        assert (await resolver.resolve(_User())).user_ref == "user-1"
    assert auth.calls == 1
    assert any("cache read failed" in e["event"] for e in logs)


# ── 2. consequential reads stay fresh ─────────────────────────────────────────


async def test_a_consequential_read_never_uses_the_routine_copy():
    auth, _, clock, resolver = _setup(routine_ttl=600)
    await resolver.resolve(_User())
    clock.now += 1
    auth.grants = ["SOMETHING_NEWER"]
    principal = await resolver.resolve(_User(), consequential=True)
    assert auth.calls == 2
    assert principal.entitlements == ["SOMETHING_NEWER"]


async def test_a_consequential_read_refreshes_the_copy_for_routine_reads():
    auth, _, clock, resolver = _setup()
    await resolver.resolve(_User(), consequential=True)
    clock.now += 1
    await resolver.resolve(_User())
    assert auth.calls == 1


# ── 3. a consumer may force fresh (C-079 §6) ──────────────────────────────────


async def test_resolve_fresh_bypasses_the_routine_copy():
    auth, _, clock, resolver = _setup()
    await resolver.resolve(_User())
    clock.now += 1
    auth.grants = ["SOMETHING_NEWER"]
    assert (await resolver.resolve(_User(), fresh=True)).entitlements == ["SOMETHING_NEWER"]
    assert auth.calls == 2


async def test_fresh_keeps_the_routine_outage_fallback():
    """`fresh` selects the read, not the class: a routine op still degrades to last-good."""
    auth, _, clock, resolver = _setup()
    await resolver.resolve(_User())
    auth.next = AuthzUnavailable("down")
    with capture_logs():
        assert (await resolver.resolve(_User(), fresh=True)).user_ref == "user-1"
    assert auth.calls == 2


REGISTRY = {"orders:read": "ORDER_READ"}
EXPANSION = {"CUSTOMER_GRANT": ["ORDER_READ"]}
GRANTS = {"CUSTOMER_GRANT": GrantRow("CUSTOMER", "self"), "ONBOARDING_GRANT": GrantRow("CUSTOMER", "self")}


def _request():
    ctx = SimpleNamespace(user=_User())
    setattr(ctx, ACTOR_TYPES_ATTR, {"CUSTOMER"})
    req = SimpleNamespace(context=ctx, uri_template="/v1/orders", get_header=lambda name: None)
    resp = SimpleNamespace(append_header=lambda *a: None)
    return req, resp


@pytest.mark.parametrize("fresh, calls", [(False, 1), (True, 2)])
async def test_require_fresh_reaches_auth_on_a_routine_route(fresh, calls):
    auth, _, clock, resolver = _setup()
    enforcer = build_enforcer(REGISTRY, expansion=EXPANSION, grants=GRANTS)
    hook = require(enforcer, resolver, "orders:read", fresh=fresh)
    await resolver.resolve(_User())                      # warm the copy
    clock.now += 1
    req, resp = _request()
    await hook(req, resp, None, {})
    assert req.context.principal.opened_by == "CUSTOMER_GRANT"
    assert auth.calls == calls


async def test_require_without_fresh_still_works_with_a_resolver_that_predates_it():
    """A host's own resolver written against 0.9.x takes no `fresh=`: only routes asking for it
    pass it, so nothing else breaks on upgrade."""
    class _Old:
        async def resolve(self, user, *, consequential=False):
            return await resolver.resolve(user, consequential=consequential)

    _, _, _, resolver = _setup()
    enforcer = build_enforcer(REGISTRY, expansion=EXPANSION, grants=GRANTS)
    req, resp = _request()
    await require(enforcer, _Old(), "orders:read")(req, resp, None, {})
    assert req.context.principal.opened_by == "CUSTOMER_GRANT"


# ── 4. the seam: _context's age, and max_age ──────────────────────────────────


async def test_context_reports_zero_for_a_fresh_fetch_and_the_real_age_of_a_copy():
    auth, _, clock, resolver = _setup()
    _, age = await resolver._context("sess-1", "user-1", consequential=False)
    assert age == 0.0
    clock.now += 42
    _, age = await resolver._context("sess-1", "user-1", consequential=False)
    assert age == 42
    assert auth.calls == 1


@pytest.mark.parametrize("max_age, calls", [(None, 1), (300, 1), (60, 2), (30, 2), (0, 2)])
async def test_max_age_tightens_the_routine_bound_and_never_loosens_it(max_age, calls):
    """#41 passes `max_age=jti_staleness` (60 s): a routine TTL above it must not weaken the
    current-jti check (issue #42 row 4). Copy age 60, routine_ttl 120."""
    auth, _, clock, resolver = _setup(routine_ttl=120)
    await resolver.resolve(_User())
    clock.now += 60
    _, age = await resolver._context("sess-1", "user-1", consequential=False, max_age=max_age)
    assert auth.calls == calls
    assert age == (60 if calls == 1 else 0.0)


async def test_max_age_does_not_bound_the_last_good_copy_and_its_age_is_reported():
    auth, _, clock, resolver = _setup()
    await resolver.resolve(_User())
    clock.now += 500
    auth.next = AuthzUnavailable("down")
    with capture_logs() as logs:
        context, age = await resolver._context(
            "sess-1", "user-1", consequential=False, max_age=60)
    assert context.user_ref == "user-1"
    assert age == 500
    (warning,) = [e for e in logs if "last-good" in e["event"]]
    assert warning["age_s"] == 500


# ── 5. a denied session is served from no cache ───────────────────────────────


@pytest.mark.parametrize("denial", [SessionMiss("410"), SESSION_STATE_REVOKED],
                         ids=["404-410", "200-revoked"])
async def test_a_denial_destroys_the_routine_copy(denial):
    auth, _, clock, resolver = _setup(routine_ttl=600)
    await resolver.resolve(_User())                      # copy written
    auth.next = denial
    with pytest.raises(SessionMiss):                     # a fresh read sees the denial
        await resolver.resolve(_User(), consequential=True)

    clock.now += 1                                       # well inside routine_ttl
    auth.next = AuthzUnavailable("down")                 # and auth now unreachable
    with pytest.raises(AuthzUnavailable):                # NOT the routine copy, NOT last-good
        await resolver.resolve(_User())
    assert auth.calls == 3                               # the routine read had to ask


async def test_a_denial_on_one_worker_ends_the_routine_copy_on_another():
    auth, mem, clock, worker_a = _setup()
    worker_b = AuthServiceResolver(auth, TrustContextCache(mem, clock=clock))
    await worker_b.resolve(_User())
    auth.next = SessionMiss("410")
    with pytest.raises(SessionMiss):
        await worker_a.resolve(_User(), fresh=True)
    with pytest.raises(SessionMiss):
        await worker_b.resolve(_User())                  # asked auth: no copy left to serve


# ── 6. a 0.9.x entry is never fresh ───────────────────────────────────────────


async def test_an_entry_written_by_0_9_has_unknown_age_and_is_never_fresh():
    auth, mem, _, resolver = _setup(routine_ttl=600)
    old = TrustContext.model_validate({**CTX, "session_state": 1})
    mem.store["lastgood:sess-1"] = old.model_dump_json()       # 0.9.x's format: no fetch time
    await resolver.resolve(_User())
    assert auth.calls == 1


async def test_an_entry_written_by_0_9_is_still_a_last_good_copy_of_unknown_age():
    auth, mem, _, resolver = _setup()
    old = TrustContext.model_validate({**CTX, "session_state": 1})
    mem.store["lastgood:sess-1"] = old.model_dump_json()
    auth.next = AuthzUnavailable("down")
    with capture_logs():
        context, age = await resolver._context("sess-1", "user-1", consequential=False)
    assert context.user_ref == "user-1"
    assert age == math.inf


async def test_an_entry_stamped_in_the_future_is_not_fresh():
    auth, mem, clock, resolver = _setup()
    await TrustContextCache(mem, clock=lambda: clock.now + 3600).write(
        TrustContext.model_validate({**CTX, "session_state": 1}))
    await resolver.resolve(_User())
    assert auth.calls == 1


async def test_a_new_entry_still_parses_as_a_0_9_context():
    """Rolling deploy: a 0.9.x worker reads `TrustContext.model_validate_json(raw)` off the same
    key. The stamp rides inside the context's JSON, so that still parses and the old worker keeps
    its outage fallback."""
    _, mem, _, resolver = _setup()
    await resolver.resolve(_User())
    raw = mem.store["lastgood:sess-1"]
    assert "falcon_auth_fetched_at" in json.loads(raw)
    assert TrustContext.model_validate_json(raw).grants == ["CUSTOMER_GRANT"]

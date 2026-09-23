"""Tests for the shared trust-context client, model and cache.

Both parts depend on this module -- assurance reads the trust fields, entitlement reads
the grants -- so its contract is asserted here once rather than twice.

Infra-free: the cache runs over a dict, and the client is exercised through a stub.
"""

from datetime import UTC, datetime, timedelta

import pydantic
import pytest

from falcon_auth.trustcontext import (
    DEFAULT_GRANTS_TTL,
    DEFAULT_LAST_GOOD_TTL,
    DEFAULT_TRUST_TTL,
    SESSION_TRUST_AUTHENTICATED,
    SESSION_TRUST_ELEVATED,
    NullCache,
    TrustContext,
    TrustContextCache,
)

BASE = {
    "session_ref": "sess-1",
    "user_ref": "user-1",
    "session_state": 1,
    "device_trust_level": 3,
    "session_trust_level": SESSION_TRUST_AUTHENTICATED,
}


def _ctx(**overrides):
    return TrustContext.model_validate({**BASE, "grants": ["RETAIL_USER"], **overrides})


class _MemCache:
    """A dict standing in for redis. `keys` is what the field-split assertions read."""

    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def set(self, key: str, value: str, ttl: int) -> None:
        self.store[key] = value


# ── the model ─────────────────────────────────────────────────────────────────


def test_grants_is_required():
    """Auth emits no grants today, and that must fail loudly rather than quietly.

    Optional-and-absent would resolve every caller to "holds nothing" and 403 -- a total
    outage wearing the costume of a permissions problem. A parse error says what is wrong.
    """
    with pytest.raises(pydantic.ValidationError) as e:
        TrustContext.model_validate(BASE)
    assert e.value.errors()[0]["loc"] == ("grants",)


def test_grants_is_a_list_because_grants_compose_as_a_union():
    ctx = _ctx(grants=["RETAIL_USER", "SUPPORT_AGENT"])
    assert ctx.grants == ["RETAIL_USER", "SUPPORT_AGENT"]


def test_the_field_is_not_called_entitlements():
    """What auth emits is a coarse grant, never this service's entitlement (C-038/RUL-074).

    A service taking layer-3 output from the identity provider is the collapse C-033 §4
    forbids, so the old name must not quietly keep working.
    """
    assert "grants" in TrustContext.model_fields
    assert "entitlements" not in TrustContext.model_fields


def test_unknown_fields_are_tolerated():
    """`extra="allow"`, so auth adding the proposed `grant_epoch` breaks nothing."""
    ctx = _ctx(grant_epoch=7)
    assert ctx.grant_epoch == 7


# ── the projection ────────────────────────────────────────────────────────────


def test_a_lapsed_elevation_window_reads_as_authenticated():
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    ctx = _ctx(session_trust_level=SESSION_TRUST_ELEVATED, trust_elevated_until=past)
    projected = ctx.project()
    assert projected.session_trust_level == SESSION_TRUST_AUTHENTICATED
    assert projected.trust_elevated_until is None


def test_a_live_elevation_window_is_left_alone():
    future = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
    ctx = _ctx(session_trust_level=SESSION_TRUST_ELEVATED, trust_elevated_until=future)
    assert ctx.project().session_trust_level == SESSION_TRUST_ELEVATED


def test_an_unparseable_window_is_treated_as_expired():
    """The safe direction is to under-report trust, never to project an unbounded elevation."""
    ctx = _ctx(session_trust_level=SESSION_TRUST_ELEVATED, trust_elevated_until="not-a-date")
    assert ctx.project().session_trust_level == SESSION_TRUST_AUTHENTICATED


def test_projection_does_not_touch_an_unelevated_session():
    ctx = _ctx(session_trust_level=SESSION_TRUST_AUTHENTICATED)
    assert ctx.project() is ctx


# ── the cache: by field, not by response ──────────────────────────────────────


async def test_write_splits_the_response_into_three_keys():
    mem = _MemCache()
    cache = TrustContextCache(mem)
    await cache.write(_ctx())
    assert sorted(mem.store) == ["grants:sess-1", "lastgood:sess-1", "trust:sess-1"]


async def test_round_trip_preserves_both_halves():
    cache = TrustContextCache(_MemCache())
    await cache.write(_ctx(session_trust_level=SESSION_TRUST_ELEVATED))
    back = await cache.read("sess-1")
    assert back is not None
    assert back.grants == ["RETAIL_USER"]
    assert back.session_trust_level == SESSION_TRUST_ELEVATED


async def test_an_expired_trust_half_forces_a_refetch_even_when_grants_are_warm():
    """The whole point of the split.

    Cached as one payload under one TTL, a session demoted 90 seconds ago would still read
    as trusted because its grants were still warm.
    """
    mem = _MemCache()
    cache = TrustContextCache(mem)
    await cache.write(_ctx())
    del mem.store["trust:sess-1"]
    assert await cache.read("sess-1") is None
    assert "grants:sess-1" in mem.store, "the grants half is still warm; only trust expired"


async def test_an_expired_grants_half_also_forces_a_refetch():
    mem = _MemCache()
    cache = TrustContextCache(mem)
    await cache.write(_ctx())
    del mem.store["grants:sess-1"]
    assert await cache.read("sess-1") is None


async def test_the_two_halves_carry_different_ttls():
    """Grants are the slowest-moving of the three levels; trust demotes on a timer and on
    device state. One TTL over both is what silently serves a stale trust level."""
    assert DEFAULT_GRANTS_TTL > DEFAULT_TRUST_TTL
    assert DEFAULT_LAST_GOOD_TTL > DEFAULT_GRANTS_TTL


async def test_last_good_is_readable_when_the_live_halves_are_gone():
    mem = _MemCache()
    cache = TrustContextCache(mem)
    await cache.write(_ctx())
    del mem.store["trust:sess-1"]
    del mem.store["grants:sess-1"]
    assert await cache.read("sess-1") is None
    last_good = await cache.read_last_good("sess-1")
    assert last_good is not None and last_good.grants == ["RETAIL_USER"]


async def test_a_corrupt_entry_is_a_miss_not_a_crash():
    mem = _MemCache()
    cache = TrustContextCache(mem)
    await cache.write(_ctx())
    mem.store["grants:sess-1"] = "{not json"
    assert await cache.read("sess-1") is None
    mem.store["lastgood:sess-1"] = "{not json"
    assert await cache.read_last_good("sess-1") is None


async def test_null_cache_always_misses():
    cache = TrustContextCache(NullCache())
    await cache.write(_ctx())
    assert await cache.read("sess-1") is None
    assert await cache.read_last_good("sess-1") is None

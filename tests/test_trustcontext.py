"""Tests for the shared trust-context client, model and cache.

Both parts depend on this module -- assurance reads the trust fields, entitlement reads
the grants -- so its contract is asserted here once rather than twice.

Infra-free: the cache runs over a dict, and the client is exercised through a stub.
"""

from datetime import UTC, datetime, timedelta

import pydantic
import pytest

from falcon_auth.trustcontext import (
    DEFAULT_LAST_GOOD_TTL,
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


# ── the degradation store: not a read-through cache ───────────────────────────


async def test_only_the_last_good_copy_is_written():
    """C-038/RUL-072: assurance is live. The `grants:` and `trust:` halves are gone -- a cached
    trust level is a window a demoted device keeps transacting inside, which is the exact hazard
    the rule names. What remains is the degradation copy, read only when auth is unreachable."""
    mem = _MemCache()
    cache = TrustContextCache(mem)
    await cache.write(_ctx())
    assert sorted(mem.store) == ["lastgood:sess-1"]


async def test_there_is_no_read_path():
    """Asserted rather than left implicit. A context cannot be assembled without its trust half,
    and the trust half is never stored -- so a `read` would have to either serve stale assurance
    or always miss, and neither is worth the shape of a working cache."""
    cache = TrustContextCache(_MemCache())
    assert not hasattr(cache, "read")


async def test_last_good_survives_a_round_trip():
    cache = TrustContextCache(_MemCache())
    await cache.write(_ctx(session_trust_level=SESSION_TRUST_ELEVATED))
    back = await cache.read_last_good("sess-1")
    assert back is not None
    assert back.grants == ["RETAIL_USER"]
    assert back.session_trust_level == SESSION_TRUST_ELEVATED


async def test_a_corrupt_entry_is_a_miss_not_a_crash():
    mem = _MemCache()
    cache = TrustContextCache(mem)
    await cache.write(_ctx())
    mem.store["lastgood:sess-1"] = "{not json"
    assert await cache.read_last_good("sess-1") is None


async def test_null_cache_always_misses():
    cache = TrustContextCache(NullCache())
    await cache.write(_ctx())
    assert await cache.read_last_good("sess-1") is None


async def test_the_last_good_ttl_is_the_only_one_left():
    """There is no grants TTL and no trust TTL to compare it against any more."""
    import falcon_auth.trustcontext as tc

    assert tc.DEFAULT_LAST_GOOD_TTL == 900
    assert not hasattr(tc, "DEFAULT_TRUST_TTL")
    assert not hasattr(tc, "DEFAULT_GRANTS_TTL")


# ── nothing deployment-specific is hardcoded ──────────────────────────────────


def test_the_trust_context_path_is_required():
    """Where auth is mounted, and under which API version, is a deployment fact.

    A default here would be a guess baked into a library, wrong for the first consumer
    that mounts auth elsewhere -- and C-039 moves the version into the first path
    segment, so the path is exactly where that variation lands.
    """
    from falcon_auth.trustcontext import HttpTrustContextClient

    with pytest.raises(TypeError):
        HttpTrustContextClient(lambda: None)  # type: ignore[call-arg,arg-type]


def test_the_cache_key_prefix_is_required():
    """A shared redis is shared: a default namespace collides two services' entries
    the first time both use it."""
    from falcon_auth.trustcontext import RedisCache

    with pytest.raises(TypeError):
        RedisCache(object())  # type: ignore[call-arg]


async def test_the_client_sends_the_api_version_auth_requires():
    """C-039 drops `X-API-Version` -- the version is the first path segment -- but AUTH HAS NOT
    ADOPTED IT. `validate_api_version` gates every endpoint across 15 route modules and answers
    400/E1004 when the header is missing or unknown.

    An earlier version of this test asserted the client sends NO version header, citing C-039.
    That was convention-correct and reality-wrong: the package could not talk to auth at all,
    because every read would 400 and surface as AuthzUnavailable.
    """
    from falcon_auth.trustcontext import HttpTrustContextClient

    seen: dict = {}

    class _Resp:
        status = 200

        async def json(self):
            return {**BASE, "grants": ["RETAIL_USER"]}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Session:
        def get(self, path, **kw):
            seen.update(kw)
            seen["path"] = path
            return _Resp()

    client = HttpTrustContextClient(
        lambda: _Session(),  # type: ignore[arg-type,return-value]
        path_template="/internal/sessions/{session_ref}/trust-context",
        api_version="1",
    )
    await client.fetch("sess-1", user_ref="user-1")
    assert seen["headers"] == {"X-API-Version": "1"}


async def test_none_means_send_no_version_header():
    """A legitimate value, for an auth that has adopted C-039. It is REQUIRED rather than
    defaulted because both plausible defaults are wrong somewhere and neither fails loudly."""
    from falcon_auth.trustcontext import HttpTrustContextClient

    seen: dict = {}

    class _Resp:
        status = 200

        async def json(self):
            return {**BASE, "grants": ["RETAIL_USER"]}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Session:
        def get(self, path, **kw):
            seen.update(kw)
            return _Resp()

    client = HttpTrustContextClient(
        lambda: _Session(),  # type: ignore[arg-type,return-value]
        path_template="/v1/internal/sessions/{session_ref}/trust-context",
        api_version=None,
    )
    await client.fetch("sess-1", user_ref="user-1")
    assert seen["headers"] == {}


async def test_the_api_version_is_required_with_no_default():
    from falcon_auth.trustcontext import HttpTrustContextClient

    with pytest.raises(TypeError):
        HttpTrustContextClient(  # type: ignore[call-arg]
            lambda: None,  # type: ignore[arg-type,return-value]
            path_template="/x/{session_ref}",
        )

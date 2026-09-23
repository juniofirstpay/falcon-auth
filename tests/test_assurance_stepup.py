"""Tests for the step-up gate.

Infra-free: a stub `TrustContextClient` returns canned contexts and counts its calls, which
is how the no-caching assertion is made.
"""

from datetime import UTC, datetime, timedelta

import pytest

from falcon_auth.assurance.stepup import check_session_elevated
from falcon_auth.errors import AuthzUnavailable, SessionMiss, StepUpRequired
from falcon_auth.trustcontext import (
    SESSION_TRUST_AUTHENTICATED,
    SESSION_TRUST_ELEVATED,
    TrustContext,
)

BASE = {
    "session_ref": "sess-1",
    "user_ref": "user-1",
    "session_state": 1,
    "device_trust_level": 3,
    "grants": ["RETAIL_USER"],
}


def _ctx(**overrides) -> TrustContext:
    return TrustContext.model_validate(
        {**BASE, "session_trust_level": SESSION_TRUST_AUTHENTICATED, **overrides}
    )


class _Client:
    """Stub trust source. `calls` is what the freshness assertions read."""

    def __init__(self, context=None, raises=None):
        self._context = context
        self._raises = raises
        self.calls = 0
        self.seen: list[tuple[str, str]] = []

    async def fetch(self, session_ref: str, *, user_ref: str) -> TrustContext:
        self.calls += 1
        self.seen.append((session_ref, user_ref))
        if self._raises is not None:
            raise self._raises
        return self._context


def _elevated(minutes: int = 10) -> TrustContext:
    until = (datetime.now(UTC) + timedelta(minutes=minutes)).isoformat()
    return _ctx(session_trust_level=SESSION_TRUST_ELEVATED, trust_elevated_until=until)


# ── the gate ──────────────────────────────────────────────────────────────────


async def test_an_elevated_session_passes():
    client = _Client(_elevated())
    ctx = await check_session_elevated(client, "sess-1", "user-1")
    assert ctx.session_trust_level == SESSION_TRUST_ELEVATED


async def test_an_authenticated_session_is_refused():
    client = _Client(_ctx())
    with pytest.raises(StepUpRequired):
        await check_session_elevated(client, "sess-1", "user-1")


async def test_the_refusal_says_what_was_required_and_what_was_present():
    """The client needs to know which challenge to raise, not merely that it was refused."""
    client = _Client(_ctx())
    with pytest.raises(StepUpRequired) as e:
        await check_session_elevated(client, "sess-1", "user-1")
    assert e.value.required == SESSION_TRUST_ELEVATED
    assert e.value.present == SESSION_TRUST_AUTHENTICATED
    assert e.value.extras == {
        "required_session_trust_level": SESSION_TRUST_ELEVATED,
        "session_trust_level": SESSION_TRUST_AUTHENTICATED,
    }


async def test_the_lookup_is_keyed_by_session_with_the_user_as_a_guard():
    """Trust is per-session, never per-user: one person holds several sessions at different
    tiers, so there is no per-user answer to ask for."""
    client = _Client(_elevated())
    await check_session_elevated(client, "sess-1", "user-1")
    assert client.seen == [("sess-1", "user-1")]


# ── the window ────────────────────────────────────────────────────────────────


async def test_a_lapsed_elevation_window_is_refused():
    """Projected on read, so the gate fails closed on expiry without anything having swept."""
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    client = _Client(_ctx(session_trust_level=SESSION_TRUST_ELEVATED, trust_elevated_until=past))
    with pytest.raises(StepUpRequired) as e:
        await check_session_elevated(client, "sess-1", "user-1")
    assert e.value.present == SESSION_TRUST_AUTHENTICATED, "the lapsed window projected down"


async def test_an_unbounded_elevation_is_not_honoured():
    """An elevated session whose window cannot be parsed is refused, not trusted.

    The safe direction is to under-report trust; honouring it would extend an elevation
    nobody can bound.
    """
    client = _Client(
        _ctx(session_trust_level=SESSION_TRUST_ELEVATED, trust_elevated_until="not-a-date")
    )
    with pytest.raises(StepUpRequired):
        await check_session_elevated(client, "sess-1", "user-1")


# ── freshness ─────────────────────────────────────────────────────────────────


async def test_every_check_reads_fresh():
    """Assurance is live (C-038). A cached elevation is what breaks the feature: the user
    completes a challenge, retries, and a stale level refuses them again."""
    client = _Client(_elevated())
    for _ in range(3):
        await check_session_elevated(client, "sess-1", "user-1")
    assert client.calls == 3


async def test_a_session_that_elevates_between_calls_is_seen_immediately():
    """The case the no-cache rule exists for: the challenge is completed mid-flight."""

    class _Elevating(_Client):
        async def fetch(self, session_ref: str, *, user_ref: str) -> TrustContext:
            self.calls += 1
            return _ctx() if self.calls == 1 else _elevated()

    client = _Elevating()
    with pytest.raises(StepUpRequired):
        await check_session_elevated(client, "sess-1", "user-1")
    ctx = await check_session_elevated(client, "sess-1", "user-1")
    assert ctx.session_trust_level == SESSION_TRUST_ELEVATED


# ── the failure modes stay apart ──────────────────────────────────────────────


async def test_an_unreachable_trust_source_is_not_a_step_up_prompt():
    """Telling a user to step up when auth is unreachable sends them to complete a challenge
    that cannot help, and charges an infrastructure fault to them."""
    client = _Client(raises=AuthzUnavailable("trust source unreachable"))
    with pytest.raises(AuthzUnavailable):
        await check_session_elevated(client, "sess-1", "user-1")


async def test_a_dead_session_is_not_a_step_up_prompt():
    """A session that is gone cannot be elevated -- the caller re-authenticates instead."""
    client = _Client(raises=SessionMiss("session is not live"))
    with pytest.raises(SessionMiss):
        await check_session_elevated(client, "sess-1", "user-1")


def test_step_up_required_is_not_a_capability_denial():
    """C-033 keeps the five checks answering separately. A host mapping CapabilityDenied
    alone would render "you do not have access", which is wrong here: the caller may hold
    every entitlement the route asks for."""
    from falcon_auth.errors import CapabilityDenied

    assert not issubclass(StepUpRequired, CapabilityDenied)
    assert issubclass(SessionMiss, CapabilityDenied), "SessionMiss deliberately still is"


# ── the Falcon gate ───────────────────────────────────────────────────────────


class _Req:
    def __init__(self, refs):
        self.context = type("Ctx", (), {})()
        self._refs = refs


async def test_the_hook_gates_a_route():
    from falcon_auth.adapters.hooks import require_elevated

    client = _Client(_elevated())
    hook = require_elevated(client, lambda req: ("sess-1", "user-1"))
    await hook(_Req(None), None, None, {})
    assert client.calls == 1


async def test_the_hook_refuses_an_unelevated_session():
    from falcon_auth.adapters.hooks import require_elevated

    client = _Client(_ctx())
    hook = require_elevated(client, lambda req: ("sess-1", "user-1"))
    with pytest.raises(StepUpRequired):
        await hook(_Req(None), None, None, {})


async def test_the_hook_absorbs_stray_decorator_kwargs():
    """`falcon.before` forwards every extra keyword to the hook, including the `is_async=True`
    callers still pass. A strict signature would raise TypeError -- a 500 on a gated route."""
    from falcon_auth.adapters.hooks import require_elevated

    client = _Client(_elevated())
    hook = require_elevated(client, lambda req: ("sess-1", "user-1"))
    await hook(_Req(None), None, None, {}, is_async=True)
    assert client.calls == 1

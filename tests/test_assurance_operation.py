"""Tests for per-operation step-up.

Two of these pin behaviours of Falcon itself rather than of this package -- hook ordering, and
what reading the body in a hook does to the handler. Both are load-bearing for the design and
both are the opposite of what a reader would assume, so they are asserted rather than trusted.
"""

import falcon
import falcon.asgi
import falcon.testing
import pytest

from falcon_auth.assurance.operation import (
    OperationBodyMismatch,
    OperationChallengeMiss,
    OperationVerification,
    verify_operation,
)
from falcon_auth.adapters.hooks import require_operation_step_up
from falcon_auth.errors import AuthzUnavailable, StepUpRequired, Unauthenticated
from falcon_auth.trustcontext import SESSION_TRUST_AUTHENTICATED, SESSION_TRUST_ELEVATED


def _verification(**over):
    return OperationVerification.model_validate({
        "session_ref": "sess-1",
        "user_ref": "user-1",
        "operation_id": "op-1",
        "purpose": "profile.update",
        "target_session_tier": SESSION_TRUST_ELEVATED,
        "request_body_hash": None,
        **over,
    })


class _Verifier:
    """Records calls, so "was the challenge spent?" is answerable."""

    def __init__(self, result=None, raises=None):
        self._result = result if result is not None else _verification()
        self._raises = raises
        self.calls = []

    async def verify(self, session_ref, operation_id, *, user_ref):
        self.calls.append((session_ref, operation_id, user_ref))
        if self._raises is not None:
            raise self._raises
        return self._result


# ── the core ──────────────────────────────────────────────────────────────────


async def test_a_passed_challenge_for_this_operation_authorizes_it():
    v = _Verifier()
    out = await verify_operation(v, "sess-1", "op-1", user_ref="user-1")
    assert out.operation_id == "op-1"
    assert v.calls == [("sess-1", "op-1", "user-1")]


async def test_an_unspendable_challenge_is_not_a_retry():
    """Unknown, unpassed, expired and consumed are one uniform answer, so challenge state does
    not leak. The client's recovery is a NEW operation id, not a retry of this one."""
    v = _Verifier(raises=OperationChallengeMiss("gone"))
    with pytest.raises(OperationChallengeMiss):
        await verify_operation(v, "sess-1", "op-1", user_ref="user-1")


async def test_a_weaker_challenge_cannot_be_spent_on_a_stronger_route():
    """A real, passed challenge raised under a weaker policy. StepUpRequired rather than a miss:
    the session is fine and a challenge really is what is needed, just a stronger one."""
    v = _Verifier(_verification(target_session_tier=SESSION_TRUST_AUTHENTICATED))
    with pytest.raises(StepUpRequired) as excinfo:
        await verify_operation(v, "sess-1", "op-1", user_ref="user-1")
    assert excinfo.value.required == SESSION_TRUST_ELEVATED
    assert excinfo.value.present == SESSION_TRUST_AUTHENTICATED


async def test_an_infrastructure_failure_is_not_a_user_denial():
    v = _Verifier(raises=AuthzUnavailable("down"))
    with pytest.raises(AuthzUnavailable):
        await verify_operation(v, "sess-1", "op-1", user_ref="user-1")


# ── body binding ──────────────────────────────────────────────────────────────


async def test_a_matching_body_passes():
    v = _Verifier(_verification(request_body_hash="abc"))
    out = await verify_operation(v, "sess-1", "op-1", user_ref="user-1", body_hash="abc")
    assert out.request_body_hash == "abc"


async def test_a_different_body_is_a_different_act():
    """The check that stops a step-up raised to move 500 being spent on a body that moves
    50000. Same operation id, different act."""
    v = _Verifier(_verification(request_body_hash="for-500"))
    with pytest.raises(OperationBodyMismatch):
        await verify_operation(v, "sess-1", "op-1", user_ref="user-1", body_hash="for-50000")


async def test_a_bound_challenge_with_no_computed_hash_is_refused():
    """The asymmetry worth being strict about. Treating "we have no hash" as "no check needed"
    would let a service opt out of body binding by forgetting to pass one -- which is exactly
    how a body-bound challenge stops being body-bound."""
    v = _Verifier(_verification(request_body_hash="abc"))
    with pytest.raises(OperationBodyMismatch, match="no body hash was computed"):
        await verify_operation(v, "sess-1", "op-1", user_ref="user-1", body_hash=None)


async def test_an_unbound_challenge_needs_no_comparison():
    """`request_body_hash: null` means the purpose is not body-bound. Nothing to compare."""
    v = _Verifier(_verification(request_body_hash=None))
    assert await verify_operation(v, "sess-1", "op-1", user_ref="user-1", body_hash="anything")


# ── the Falcon hook ───────────────────────────────────────────────────────────


def _app(verifier, *, body_hash=None, extra_hook=None):
    refs = lambda req: ("sess-1", "user-1")  # noqa: E731
    gate = require_operation_step_up(verifier, refs, body_hash=body_hash)

    async def render(req, resp, ex, params):
        resp.status = falcon.HTTP_403
        resp.media = {"error": type(ex).__name__}

    if extra_hook is not None:
        class Resource:
            @falcon.before(extra_hook)
            @falcon.before(gate)
            async def on_patch(self, req, resp):
                resp.media = {"body": await req.get_media()}
    else:
        class Resource:
            @falcon.before(gate)
            async def on_patch(self, req, resp):
                resp.media = {"body": await req.get_media()}

    app = falcon.asgi.App()
    for exc in (OperationChallengeMiss, OperationBodyMismatch, StepUpRequired, Unauthenticated,
                AuthzUnavailable):
        app.add_error_handler(exc, render)
    app.add_route("/profile", Resource())
    return falcon.testing.TestClient(app)


def test_the_hook_spends_the_challenge_and_lets_the_write_through():
    v = _Verifier()
    r = _app(v).simulate_patch("/profile", json={"name": "x"},
                               headers={"X-Operation-Id": "op-1"})
    assert r.status_code == 200
    assert v.calls == [("sess-1", "op-1", "user-1")]


def test_a_mutation_with_no_operation_id_is_refused():
    """A write needing per-operation step-up and carrying no operation id cannot be authorized
    at all -- and the challenge is not spent finding that out."""
    v = _Verifier()
    r = _app(v).simulate_patch("/profile", json={"name": "x"})
    assert r.status_code == 403
    assert r.json["error"] == "Unauthenticated"
    assert v.calls == [], "nothing was spent"


def test_the_handler_still_sees_its_body_after_the_hook_hashed_it():
    """THE constraint on this design. A hook that calls stream.read() leaves the handler an
    empty body and get_media() then 400s with "Could not parse an empty JSON body". get_media()
    caches the DESERIALIZED media, so hook and handler share one object.

    Measured on Falcon 4.2. If this ever fails, per-operation step-up cannot be a before hook.
    """
    seen = {}

    def hasher(media):
        seen["hook_saw"] = media
        return "h"

    v = _Verifier(_verification(request_body_hash="h"))
    r = _app(v, body_hash=hasher).simulate_patch(
        "/profile", json={"amount": 500}, headers={"X-Operation-Id": "op-1"}
    )
    assert r.status_code == 200
    assert seen["hook_saw"] == {"amount": 500}
    assert r.json["body"] == {"amount": 500}, "the handler's body survived the hook"


def test_a_body_mismatch_refuses_before_the_handler_runs():
    v = _Verifier(_verification(request_body_hash="for-500"))
    r = _app(v, body_hash=lambda m: "for-50000").simulate_patch(
        "/profile", json={"amount": 50000}, headers={"X-Operation-Id": "op-1"}
    )
    assert r.status_code == 403
    assert r.json["error"] == "OperationBodyMismatch"


# ── the ordering the idempotency key depends on ───────────────────────────────


def test_falcon_runs_stacked_hooks_outermost_first():
    """Load-bearing, and the reverse of what Python's decorator semantics suggest: the
    innermost decorator WRAPS first but EXECUTES last.

    The idempotency lookup must run before the step-up verify. A retry whose first response was
    lost has to return the cached response WITHOUT reaching the gate -- the challenge was
    consumed on the first attempt, so verifying again answers OperationChallengeMiss and fails
    the exact retry X-Operation-Id exists to make safe.
    """
    order = []

    async def idempotency(req, resp, resource, params, *_a, **_kw):
        order.append("idempotency")

    v = _Verifier()

    class RecordingVerifier(_Verifier):
        async def verify(self, *a, **kw):
            order.append("step-up")
            return await super().verify(*a, **kw)

    client = _app(RecordingVerifier(), extra_hook=idempotency)
    client.simulate_patch("/profile", json={}, headers={"X-Operation-Id": "op-1"})

    assert order == ["idempotency", "step-up"], (
        "the idempotency lookup must run first, or an idempotent retry burns into a consumed "
        "challenge"
    )

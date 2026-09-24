"""Tests for per-operation step-up.

The Falcon-level tests drive the shape orders' create API actually uses: the idempotency
reservation is taken INLINE in the responder, and only a RESERVED outcome may spend a
challenge. The replay and in-progress branches must return without touching it -- which is why
there is no `before` hook for this, and why a test asserts there isn't one.
"""

import falcon
import falcon.asgi
import falcon.testing
import pytest

from falcon_auth.assurance.operation import (
    OperationBodyMismatch,
    OperationChallengeMiss,
    OperationPurposeMismatch,
    OperationVerification,
    verify_operation,
)
from falcon_auth.adapters.hooks import verify_operation_for
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
        "consumed_at": "2026-08-07T10:22:45Z",
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
    out = await verify_operation(v, "sess-1", "op-1", user_ref="user-1", expected_purpose="profile.update")
    assert out.operation_id == "op-1"
    assert v.calls == [("sess-1", "op-1", "user-1")]


async def test_an_unspendable_challenge_is_not_a_retry():
    """Unknown, unpassed, expired and consumed are one uniform answer, so challenge state does
    not leak. The client's recovery is a NEW operation id, not a retry of this one."""
    v = _Verifier(raises=OperationChallengeMiss("gone"))
    with pytest.raises(OperationChallengeMiss):
        await verify_operation(v, "sess-1", "op-1", user_ref="user-1", expected_purpose="profile.update")


async def test_a_challenge_for_another_purpose_cannot_be_spent_here():
    """Cross-purpose replay, and the only place it can be caught. A challenge passed for
    `mpin_reset` must not authorize a wallet transfer just because both are operation-scoped --
    and auth cannot check it, because the operation id is unique only within a session and auth
    does not know which route is redeeming it."""
    v = _Verifier(_verification(purpose="mpin_reset"))
    with pytest.raises(OperationPurposeMismatch):
        await verify_operation(
            v, "sess-1", "op-1", user_ref="user-1", expected_purpose="wallet.transfer"
        )


async def test_the_challenge_is_spent_even_when_the_purpose_is_wrong():
    """Worth being explicit about. Auth consumed it -- it was valid for ITS purpose -- so the
    user must re-challenge. That is the cost of catching this downstream."""
    v = _Verifier(_verification(purpose="mpin_reset"))
    with pytest.raises(OperationPurposeMismatch):
        await verify_operation(
            v, "sess-1", "op-1", user_ref="user-1", expected_purpose="wallet.transfer"
        )
    assert v.calls == [("sess-1", "op-1", "user-1")], "auth was called; the challenge is gone"


async def test_there_is_no_tier_gate_on_this_path():
    """AUTH-ADR-112: an operation-scoped step-up does NOT raise the session's ambient tier --
    `challenge:authenticate` answers 204 and writes no trust state. Gating on
    target_session_tier would assert session-trust semantics this path does not have, so a
    challenge whose recorded tier is AUTHENTICATED still verifies."""
    v = _Verifier(_verification(target_session_tier=SESSION_TRUST_AUTHENTICATED))
    out = await verify_operation(
        v, "sess-1", "op-1", user_ref="user-1", expected_purpose="profile.update"
    )
    assert out.target_session_tier == SESSION_TRUST_AUTHENTICATED


async def test_an_infrastructure_failure_is_not_a_user_denial():
    v = _Verifier(raises=AuthzUnavailable("down"))
    with pytest.raises(AuthzUnavailable):
        await verify_operation(v, "sess-1", "op-1", user_ref="user-1", expected_purpose="profile.update")


# ── body binding ──────────────────────────────────────────────────────────────


async def test_a_matching_body_passes():
    v = _Verifier(_verification(request_body_hash="abc"))
    out = await verify_operation(v, "sess-1", "op-1", user_ref="user-1", expected_purpose="profile.update", body_hash="abc")
    assert out.request_body_hash == "abc"


async def test_a_different_body_is_a_different_act():
    """The check that stops a step-up raised to move 500 being spent on a body that moves
    50000. Same operation id, different act."""
    v = _Verifier(_verification(request_body_hash="for-500"))
    with pytest.raises(OperationBodyMismatch):
        await verify_operation(v, "sess-1", "op-1", user_ref="user-1", expected_purpose="profile.update", body_hash="for-50000")


async def test_a_bound_challenge_with_no_computed_hash_is_refused():
    """The asymmetry worth being strict about. Treating "we have no hash" as "no check needed"
    would let a service opt out of body binding by forgetting to pass one -- which is exactly
    how a body-bound challenge stops being body-bound."""
    v = _Verifier(_verification(request_body_hash="abc"))
    with pytest.raises(OperationBodyMismatch, match="no body hash was computed"):
        await verify_operation(v, "sess-1", "op-1", user_ref="user-1", expected_purpose="profile.update", body_hash=None)


async def test_an_unbound_challenge_needs_no_comparison():
    """`request_body_hash: null` means the purpose is not body-bound. Nothing to compare."""
    v = _Verifier(_verification(request_body_hash=None))
    assert await verify_operation(v, "sess-1", "op-1", user_ref="user-1", expected_purpose="profile.update", body_hash="anything")


# ── the inline form, and the reservation it must follow ──────────────────────
#
# There is no `before` hook for this, deliberately. X-Operation-ID is also the idempotency key,
# and in this estate the reservation is taken INLINE in the responder -- after every hook has
# run. A hook would consume the challenge on every replay, before `reserve` was called, turning
# the replay path into "challenge already consumed". These tests drive the real shape.


class _Reservation:
    RESERVED = "reserved"
    REPLAY = "replay"
    IN_PROGRESS = "in_progress"


def _app(verifier, *, outcome=_Reservation.RESERVED, body_hash=None, stored=None):
    refs = lambda req: ("sess-1", "user-1")  # noqa: E731

    async def render(req, resp, ex, params):
        resp.status = falcon.HTTP_403
        resp.media = {"error": type(ex).__name__}

    class Resource:
        async def on_patch(self, req, resp):
            # exactly orders' shape: reserve first, and only RESERVED may spend a challenge
            if outcome is _Reservation.REPLAY:
                resp.status = falcon.HTTP_200
                resp.set_header("Idempotency-Replayed", "true")
                resp.media = stored or {"replayed": True}
                return
            if outcome is _Reservation.IN_PROGRESS:
                resp.status = falcon.HTTP_202
                return

            await verify_operation_for(
                req, verifier, refs, expected_purpose="profile.update", body_hash=body_hash
            )
            resp.media = {"body": await req.get_media()}

    app = falcon.asgi.App()
    for exc in (OperationChallengeMiss, OperationBodyMismatch, StepUpRequired, Unauthenticated,
                AuthzUnavailable):
        app.add_error_handler(exc, render)
    app.add_route("/profile", Resource())
    return falcon.testing.TestClient(app)


def test_a_genuine_first_execution_spends_the_challenge():
    v = _Verifier()
    r = _app(v).simulate_patch("/profile", json={"name": "x"},
                               headers={"X-Operation-ID": "op-1"})
    assert r.status_code == 200
    assert v.calls == [("sess-1", "op-1", "user-1")]


def test_a_replay_returns_the_stored_response_without_spending_anything():
    """THE case a before-hook could not serve. The challenge was consumed on the first attempt;
    verifying again would answer OperationChallengeMiss and fail the exact retry the operation
    id exists to make safe."""
    v = _Verifier()
    r = _app(v, outcome=_Reservation.REPLAY, stored={"order_id": 7}).simulate_patch(
        "/profile", json={"name": "x"}, headers={"X-Operation-ID": "op-1"}
    )
    assert r.status_code == 200
    assert r.json == {"order_id": 7}
    assert v.calls == [], "a replay must not reach the challenge"


def test_an_in_progress_reservation_does_not_spend_anything_either():
    v = _Verifier()
    r = _app(v, outcome=_Reservation.IN_PROGRESS).simulate_patch(
        "/profile", json={}, headers={"X-Operation-ID": "op-1"}
    )
    assert r.status_code == 202
    assert v.calls == []


def test_a_mutation_with_no_operation_id_is_refused():
    """And nothing is spent finding that out."""
    v = _Verifier()
    r = _app(v).simulate_patch("/profile", json={"name": "x"})
    assert r.status_code == 403
    assert r.json["error"] == "Unauthenticated"
    assert v.calls == []


def test_the_handler_still_sees_its_body_after_the_helper_hashed_it():
    """A hook reading `stream.read()` leaves the handler b'' and get_media() then 400s with
    "Could not parse an empty JSON body". get_media() caches the DESERIALIZED media, so both
    sides share one object. Measured on Falcon 4.2."""
    seen = {}

    def hasher(media):
        seen["hasher_saw"] = media
        return "h"

    v = _Verifier(_verification(request_body_hash="h"))
    r = _app(v, body_hash=hasher).simulate_patch(
        "/profile", json={"amount": 500}, headers={"X-Operation-ID": "op-1"}
    )
    assert r.status_code == 200
    assert seen["hasher_saw"] == {"amount": 500}
    assert r.json["body"] == {"amount": 500}, "the handler's body survived"


def test_a_body_mismatch_refuses_before_the_write():
    v = _Verifier(_verification(request_body_hash="for-500"))
    r = _app(v, body_hash=lambda m: "for-50000").simulate_patch(
        "/profile", json={"amount": 50000}, headers={"X-Operation-ID": "op-1"}
    )
    assert r.status_code == 403
    assert r.json["error"] == "OperationBodyMismatch"


def test_the_header_is_spelled_as_the_estate_spells_it():
    from falcon_auth.adapters.hooks import DEFAULT_OPERATION_HEADER

    assert DEFAULT_OPERATION_HEADER == "X-Operation-ID"


def test_there_is_no_before_hook_for_this():
    """Asserted, because a hook is the obvious thing to reach for and it is wrong here -- it
    would run before the inline reservation and spend a challenge on every replay."""
    from falcon_auth.adapters import hooks

    assert not hasattr(hooks, "require_operation_step_up")

"""Step-up: is this session authenticated strongly enough, right now.

Assurance is layer 2 of C-033's five checks -- distinct from identity (who is this) and from
entitlement (what class of thing may they do). A caller can hold every entitlement a route
asks for and still be refused here, because the question is not *what* they may do but *how
recently and how strongly* they proved who they are.

Framework-agnostic: :func:`check_session_elevated` takes two reference strings and returns
or raises. The Falcon gate that drives it lives in :mod:`falcon_auth.adapters.hooks`, because
extracting those references from a request is a consumer convention -- it depends on where
that service's authenticator chose to put the session claim.

**The read is always fresh.** No cache, and that is a correctness decision rather than a
performance one:

- C-038 rules it outright -- "assurance is live", and "no blanket TTL over the whole
  response: a demoted device must not keep transacting for the length of a cache window".
- A cached elevation is exactly what breaks the feature. The user completes a challenge,
  retries, and a stale `session_trust_level` refuses them again -- which reads as step-up
  being broken rather than as a cache being warm. Elevation is the one value that changes
  *because of a user action*, so caching it fights the user.
- The volume argument does not apply. Step-up gates sit on the few routes that demand
  elevation, and those are the routes where correctness is worth a round trip.

**Two tiers, and no third.** Auth's own log settles it: "you cannot be authenticated and
below baseline -- the thing that looked like 'low session trust' was device-untrusted
mislabelled." So the gate takes no tier argument: its *presence* is the requirement, and
"authenticated is enough" is expressed by not applying it.

**Two failure modes, kept apart.** `StepUpRequired` means the session is live but not
elevated -- the client raises a challenge and retries. `AuthzUnavailable` means the lookup
itself failed. Answering "go and step up" when the real problem is that auth is unreachable
sends the user to complete a challenge that cannot help, and charges an infrastructure fault
to them. `SessionMiss` is a third outcome and is left to propagate unchanged: a dead session
cannot be elevated, it has to be re-established.

This covers **general elevation** only -- the session-wide, window-bounded tier. It is one of
two step-up mechanisms and they are not interchangeable: a mutation must never be gated on an
elevation window, because a window authorizes a period rather than an act, and one step-up
would then authorize every write until it expires. Per-operation step-up is a separate,
consumed, body-bound challenge and is not implemented here.
"""

from __future__ import annotations

from ..errors import SessionMiss, StepUpRequired
from ..trustcontext import (
    SESSION_STATE_ENABLED,
    SESSION_TRUST_ELEVATED,
    TrustContext,
    TrustContextClient,
)

__all__ = ("check_session_elevated",)


async def check_session_elevated(
    client: TrustContextClient, session_ref: str, user_ref: str
) -> TrustContext:
    """Return the session's trust context if it is ELEVATED; raise otherwise.

    :param client: the trust-context client. Pass the plain client, ``not`` a cache-backed
        one -- see the module docstring on why assurance is read live.
    :param session_ref: the session to ask about. Trust is per-session, never per-user: one
        person holds several concurrent sessions at different tiers, so there is no per-user
        answer to ask for.
    :param user_ref: auth's ownership guard. A subject that does not own ``session_ref`` gets
        a 404 from auth, which surfaces here as ``SessionMiss``.

    :raises StepUpRequired: the session is live and authenticated, but not elevated.
    :raises SessionMiss: the session is dead, unknown, or not owned by this subject. It
        cannot be elevated -- the caller re-authenticates rather than raising a challenge.
    :raises AuthzUnavailable: the lookup itself failed. Deliberately distinct from
        ``StepUpRequired``: a challenge cannot fix an unreachable trust source.

    Returns the context rather than ``None`` so a caller that also wants the elevation window
    -- to tell the client how long it has, say -- does not pay for a second fetch.
    """
    context = await client.fetch(session_ref, user_ref=user_ref)

    # Auth answers 200 for a REVOKED session -- revoke sets `state`, and the trust-context read
    # filters on `is_active` only. Without this, a logged-out session could pass a step-up gate
    # on a still-elevated trust level.
    if context.session_state != SESSION_STATE_ENABLED:
        raise SessionMiss("session is not enabled", session_state=context.session_state)

    # Project even though a fresh read arrives projected by auth. It is free, and the
    # direction it can be wrong in is the safe one: if auth ever returned an elevated
    # session whose window had passed, honouring it would extend an elevation nobody
    # granted. Defence in depth on a gate, not a substitute for auth doing it.
    context = context.project()

    if context.session_trust_level != SESSION_TRUST_ELEVATED:
        raise StepUpRequired(
            "this action requires a more recent authentication",
            required=SESSION_TRUST_ELEVATED,
            present=context.session_trust_level,
        )

    return context

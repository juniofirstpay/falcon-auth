"""Part 3 — assurance: how strongly, and how recently, did they authenticate.

Read from auth's service plane, never from the token — a signed snapshot of mutable state is
authority that cannot be withdrawn until it expires.

Two tiers, and there will not be a third: `AUTHENTICATED` and `ELEVATED`. A step-up gate's
*presence* is the requirement; "authenticated is enough" is expressed by omitting it.

**Assurance is live.** C-038 forbids a blanket TTL over the trust-context response: a demoted
device must not keep transacting for the length of a cache window. Entitlements cache well;
this does not.

Two failure modes stay distinct. `StepUpRequired` means the session is live but not elevated
(the consumer answers 403). `TrustContextUnavailable` means the lookup itself failed (503).
Collapsing them sends a user to complete a challenge that cannot help, and charges an
infrastructure fault to them.

The trust tiers and the client live in the package root (`trustcontext`), because
`entitlement` reads the same response for a different field. This part contributes the
policy, not a second lookup.
"""

from __future__ import annotations

from .stepup import check_session_elevated

__all__ = ("check_session_elevated",)

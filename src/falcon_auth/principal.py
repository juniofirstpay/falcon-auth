"""The resolved user-plane caller: who they are, what they hold, and how strongly they
authenticated.

One object carries all three because they arrive together from one trust-context lookup, and
because separating them would let a route read entitlements while forgetting assurance -- the
collapse C-033's five-check split exists to prevent. What a route may *do* with each stays
separate: entitlements gate the capability (layer 3), and the trust fields are layer 2, read
by the step-up gate.

Deliberately frozen. A hook resolves this once per request and puts it on the request context;
a handler reads it. Nothing downstream should be able to grant itself an entitlement by
assignment.

NOT the east-west principal. `eastwest.Principal` is a cert-bound service identity --
`cn`, `kind`, `source`, `scopes` -- and shares no field with this one. Both being called
"Principal" in one process is what made them look like one model to be merged; they are two
different things that happen to share a name, and folding them into a single class would make
it entirely nullable on whichever plane you were not on. Whether they get a common base, a
Protocol, or stay separate is A4's question, and it is open.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .trustcontext import SESSION_TRUST_ELEVATED

__all__ = ("Principal",)


@dataclass(frozen=True)
class Principal:
    """The caller's authorization context for one request.

    `user_ref` is the subject in the *identity provider's* terms. A service that keeps its own
    subject aggregate resolves this to a local id (layer 1); one that stores the ref it is
    given uses it directly.

    The trust fields are `None` for a principal with no session -- an api-key service account
    -- which is why any assurance rule must treat `None` as "unknown", never as
    "untrusted-but-present".
    """

    user_ref: str
    entitlements: list[str] = field(default_factory=list)
    session_ref: str | None = None
    session_trust_level: int | None = None
    device_trust_level: int | None = None
    trust_elevated_until: str | None = None

    def holds(self, entitlement: str) -> bool:
        return entitlement in self.entitlements

    @property
    def is_elevated(self) -> bool:
        """Whether the session is currently ELEVATED.

        Reads a value that has already been expiry-projected -- by auth on a fresh read, by
        `TrustContext.project` on a cached one -- so this never needs a clock of its own.

        An elevated *window* authorizes sensitive reads only. A mutation needs a
        per-operation challenge, and no amount of elevation substitutes for one: a window
        authorizes a period rather than an act, so one step-up would otherwise authorize
        every write until it expired.
        """
        return self.session_trust_level == SESSION_TRUST_ELEVATED

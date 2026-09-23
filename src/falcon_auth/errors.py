"""The failures this package raises — deliberately NOT HTTP errors.

This package cannot depend on a host service's error catalog: orders renders `{code, label, title,
description, extras}` (`app/error/errors.py`), a peer may render RFC 7807, and neither shape belongs
in a reusable gate. So the package raises its own small hierarchy and the host maps it once, at
`register_error_handlers`, into whatever it already puts on the wire.

This lives at the package root rather than inside `entitlement/` because `trustcontext` raises
two of them, and `SessionMiss` subclasses `CapabilityDenied` -- a relationship the docstring
below explains and which cannot be split across modules without breaking it.

Naming, recorded rather than fixed: `AuthzError` and `AuthzUnavailable` were named when this
was an authorization-only library. They are now raised by a package that also authenticates,
and `AuthzUnavailable` in particular is a trust-context lookup failure rather than anything
specific to authorization. Renaming them is a deliberate later change -- it is a public API
break for two services, and doing it inside a port would make the port unauditable.

The mapping a host is expected to apply, from the contract's §11.2 denial table:

    Unauthenticated   -> 401   no token, or the authn hook never ran
    CapabilityDenied  -> 403   authenticated, lacks the entitlement. Do not retry.
    SessionMiss       -> 403   the session is dead/unknown -- still a DENY, see below
    StepUpRequired    -> 403   entitled, but the session is not elevated. Retry AFTER a challenge.
    AuthzUnavailable  -> 503   authorization state could not be established. Retry with backoff.

**`SessionMiss` is a denial, not an outage, and the distinction is load-bearing.** §5: *"a dead or
unknown session is a deny, not an error. An unreachable auth service is an error."* Reporting a
logged-out session as `503` tells the client to retry a request that will never succeed; reporting a
genuine outage as `403` tells it to give up on one that would. It subclasses `CapabilityDenied` so a
host that does not care gets the right status for free, and one that does can still tell them apart.

**A `403` from the auth service is `AuthzUnavailable`, never a denial.** It means *our* client
certificate lacks the `trust:read` scope -- a deployment fault. Surfacing it as a user denial would
turn a misconfigured rollout into "every user suddenly lacks permissions", which is the wrong page to
be woken up to.
"""
from typing import Any

__all__ = (
    "AuthzError",
    "AuthzUnavailable",
    "CapabilityDenied",
    "SessionMiss",
    "StepUpRequired",
    "Unauthenticated",
)


class AuthzError(Exception):
    """Base of every failure this package raises. Hosts may map this alone as a catch-all 403."""

    def __init__(self, description: str | None = None, **extras: Any) -> None:
        self.description = description or self.__class__.__doc__ or self.__class__.__name__
        self.extras = extras
        super().__init__(self.description)


class Unauthenticated(AuthzError):
    """No verified principal on the request."""


class CapabilityDenied(AuthzError):
    """The principal does not hold an entitlement granting this capability."""

    def __init__(
        self, description: str | None = None, *, capability: str | None = None, **extras: Any
    ) -> None:
        self.capability = capability
        if capability is not None:
            extras.setdefault("capability", capability)
        super().__init__(description, **extras)


class SessionMiss(CapabilityDenied):
    """The session is dead, unknown, or not owned by the asserted subject."""


class AuthzUnavailable(AuthzError):
    """Authorization state could not be established -- the trust source is unreachable or misconfigured."""


class StepUpRequired(AuthzError):
    """The session is live and authenticated, but not elevated to the tier this route needs.

    Deliberately NOT a subclass of `CapabilityDenied`, and the contrast with `SessionMiss`
    is the point. A host that maps `CapabilityDenied` alone renders "you do not have access
    to this" -- which is wrong here and actively unhelpful: the caller may hold every
    entitlement the route asks for, and the only thing missing is a recent enough proof of
    who they are. C-033 keeps the five checks answering separately for exactly this reason,
    with assurance answering "a challenge, not a denial".

    So a host must map this one explicitly. That is the cost, and it buys a response that
    tells the client what to do next rather than that it may not.

    `required` and `present` travel on the error so the response body can carry them: the
    client needs to know which challenge to raise, not merely that it was refused.
    """

    def __init__(
        self,
        description: str | None = None,
        *,
        required: int,
        present: int | None = None,
        **extras: Any,
    ) -> None:
        self.required = required
        self.present = present
        extras.setdefault("required_session_trust_level", required)
        if present is not None:
            extras.setdefault("session_trust_level", present)
        super().__init__(description, **extras)

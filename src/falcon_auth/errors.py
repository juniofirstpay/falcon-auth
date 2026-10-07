"""The failures this package raises — deliberately NOT HTTP errors.

Every condition here is a COMMON one, with a platform register row (C-008, C-043), so each class
names its row (`plat_code`, :mod:`falcon_auth.wire`) and
`falcon_auth.adapters.errors.register_platform_error_handlers` renders them in C-001's shape --
`{code, message, extras?}` -- with the register's copy and the exception's own text as a log-only
trace (C-048). A host that keeps its own handlers maps them by the table below.

This lives at the package root rather than inside `entitlement/` because `trustcontext` raises
two of them, and `SessionMiss` subclasses `CapabilityDenied` -- a relationship the docstring
below explains and which cannot be split across modules without breaking it.

Naming, recorded rather than fixed: `AuthzError` and `AuthzUnavailable` were named when this
was an authorization-only library. They are now raised by a package that also authenticates,
and `AuthzUnavailable` in particular is a trust-context lookup failure rather than anything
specific to authorization. Renaming them is a deliberate later change -- it is a public API
break for two services, and doing it inside a port would make the port unauditable.

The mapping a host is expected to apply -- statuses and codes from the platform register
(`registry/PLAT.md`):

    Unauthenticated   -> 401 PLAT0101   no token, or the authn hook never ran
    CapabilityDenied  -> 403 PLAT0102   authenticated, lacks the capability. Do not retry. Both
                                        planes since C-055 (`PLAT0105` retired)
    SessionMiss       -> 403 PLAT0106   the session is dead/unknown -- still a DENY, see below
    StepUpRequired    -> 401 PLAT0109   entitled, but the session is not elevated. Retry AFTER a
                                        challenge (RUL-086; RFC 9470's status)
    AuthzUnavailable  -> 503            authorization state could not be established. Retry with
                                        backoff

and, from the plane middleware, a wrong-plane credential -> 404 PLAT0006, the router miss
(RUL-158) -- raised as Falcon's own `HTTPRouteNotFound`, so the host's router-miss handler renders it.

**`SessionMiss` is a denial, not an outage, and the distinction is load-bearing.** §5: *"a dead or
unknown session is a deny, not an error. An unreachable auth service is an error."* Reporting a
logged-out session as `503` tells the client to retry a request that will never succeed; reporting a
genuine outage as `403` tells it to give up on one that would. It subclasses `CapabilityDenied` so a
host that does not care gets the right status for free, and one that does can still tell them apart.

**`StepUpRequired` is `401 PLAT0109`** (issue #1 A16, settled). An earlier version of this
docstring said the code did not exist and argued for 403. It exists: allocated 2026-09-24 by
RUL-086, at 401, matching RFC 9470's step-up challenge. The concern behind the 403 argument still
applies to clients: many treat a bare 401 as "refresh the token and retry", which can never resolve
here because the token is valid and what is missing is a FACTOR. So a client must branch on the
CODE, not the status -- `PLAT0109` means "raise a challenge", `PLAT0101` means "sign in". This class
deliberately does not subclass `CapabilityDenied`, so a host maps it explicitly, and `required` /
`present` ride in `extras` for the client to branch on.

**A `403` from the auth service is `AuthzUnavailable`, never a denial.** It means *our* client
certificate lacks the `trust:read` scope -- a deployment fault. Surfacing it as a user denial would
turn a misconfigured rollout into "every user suddenly lacks permissions", which is the wrong page to
be woken up to.
"""
from typing import Any, ClassVar

from .wire import PlatformError

__all__ = (
    "AuthzError",
    "AuthzUnavailable",
    "CapabilityDenied",
    "SessionMiss",
    "StepUpRequired",
    "TokenExpired",
    "Unauthenticated",
)


class AuthzError(PlatformError):
    """Base of the user-plane and assurance failures this package raises.

    Each subclass names its platform register row (:attr:`plat_code`, C-008), so
    :func:`falcon_auth.adapters.errors.register_platform_error_handlers` renders every one of them
    in C-001's shape. ``description`` is the operator's text: the log-only ``trace`` (C-048 §2),
    never the customer ``message``.
    """

    plat_code: ClassVar[str] = "PLAT0301"

    def __init__(self, description: str | None = None, **extras: Any) -> None:
        self.description = description or self.__class__.__doc__ or self.__class__.__name__
        self.extras = extras
        super().__init__(self.description)

    def trace(self) -> str:
        return self.description


class Unauthenticated(AuthzError):
    """No verified principal on the request."""

    plat_code: ClassVar[str] = "PLAT0101"


class TokenExpired(Unauthenticated):
    """The token is well-formed and signed, but past ``exp``.

    Its own row because the client's recovery differs: ``PLAT0108`` means **refresh** the token
    and retry; ``PLAT0101`` means sign in again (RUL-072: resource services verify locally, so
    they are the ones who can tell). A subclass, so a host catching ``Unauthenticated`` still
    catches it.
    """

    plat_code: ClassVar[str] = "PLAT0108"


class CapabilityDenied(AuthzError):
    """The principal does not hold an entitlement granting this capability."""

    plat_code: ClassVar[str] = "PLAT0102"

    def __init__(
        self, description: str | None = None, *, capability: str | None = None, **extras: Any
    ) -> None:
        self.capability = capability
        if capability is not None:
            extras.setdefault("capability", capability)
        super().__init__(description, **extras)

    def wire_extras(self) -> dict[str, Any]:
        # C-055: the missing capability rides `extras.capability`, on both planes.
        return {"capability": self.capability} if self.capability is not None else {}


class SessionMiss(CapabilityDenied):
    """The session is dead, unknown, or not owned by the asserted subject."""

    plat_code: ClassVar[str] = "PLAT0106"

    def wire_extras(self) -> dict[str, Any]:
        # A dead session is not about a capability; naming one would mislead the client.
        return {}


class AuthzUnavailable(AuthzError):
    """Authorization state could not be established -- the trust source is unreachable or misconfigured."""

    plat_code: ClassVar[str] = "PLAT0302"


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

    plat_code: ClassVar[str] = "PLAT0109"

    def wire_extras(self) -> dict[str, Any]:
        # Which challenge to raise -- the client needs it, and it reveals nothing it lacks.
        return {
            k: self.extras[k]
            for k in ("required_session_trust_level", "session_trust_level")
            if k in self.extras
        }

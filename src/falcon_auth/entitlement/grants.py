"""Which grants count for this request: C-052's actor type and C-053's grant kinds.

The platform register (`registry/GRANTS.md`, rules 6) gives every grant ONE actor type and ONE
**kind**, and the kind decides whose records the grant reaches (C-053 §1):

    self      the holder's own records                  CUSTOMER_GRANT
    subject   ONE named customer's, via a delegation     DELEGATED_CUSTOMER_GRANT, impersonation
    unbound   what the service's assignment and          AGENT_GRANT, ADMIN_GRANT
              confines allow (layers 4-5, C-054)

:func:`select` turns a resolved principal, the route's declared actor types and the request's
``Subject-Ref`` into the list of grants the capability check may use. ⛔ Kinds never mix in one
decision (C-053 §3, §6): that is what stops a customer's own write grant from reaching an account
they merely have a read delegation on.

Pure -- no framework. :func:`falcon_auth.adapters.hooks.require` calls it and maps its refusals.

READINGS this follows (ruled or put to the platform):

    customer-admitting route   Subject-Ref absent ⇒ `self` grants; present ⇒ the caller's LIVE
                               `subject` delegations FOR THAT SUBJECT (C-053 §3)
    OPERATOR-only route        `unbound` grants count; a Subject-Ref is refused (RUL-177)
    operator on a customer     served only as a SHADOW session (C-053 §9); a NORMAL operator
    route                      session is not admitted there
    shadow session             must send Subject-Ref equal to its one delegation's subject (H2)
    a delegation's time bound  `valid_until: null` is no bound -- allowed only where the grant's
                               register row says the bound is OPTIONAL. On a REQUIRED one (or a
                               row that declares none) the delegation counts as none: H4's
                               404 PLAT0008, ⛔ never perpetual, ⛔ never a session-wide 503
                               (RUL-193 D1-D3); an expired one likewise (RUL-180 reading 4)
    every subject refusal      one answer, 404 PLAT0008, byte-identical (H2, H4, RUL-162/177)
    grant vs actor type        a feed grant (or delegation) outside the session's actor type, or
                               one the register does not list, is a configuration mismatch:
                               refused, 503 (C-052 §7)
"""
from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

import structlog

from ..errors import ActorTypeNotAdmitted, AuthzUnavailable, SubjectNotReachable

logger = structlog.get_logger("falcon_auth.entitlement")

__all__ = (
    "CUSTOMER_GRANT",
    "GrantKind",
    "GrantRegister",
    "GrantRow",
    "ONBOARDING_GRANT",
    "Selection",
    "TimeBound",
    "normalise_grants",
    "select",
)

#: The two grants RUL-187 names. Platform register names, ⛔ immutable once allocated (rule 2).
#: A user who signed up holds ONBOARDING_GRANT, swapped for CUSTOMER_GRANT on onboarding.
ONBOARDING_GRANT = "ONBOARDING_GRANT"
CUSTOMER_GRANT = "CUSTOMER_GRANT"

GrantKind = Literal["self", "subject", "unbound"]
_KINDS = frozenset({"self", "subject", "unbound"})
#: `registry/GRANTS.md`'s *time bound* column (RUL-193 D2): whether a delegation of a SUBJECT
#: grant must carry a `valid_until`.
TimeBound = Literal["optional", "required"]
_TIME_BOUNDS = frozenset({"optional", "required"})
#: The actor types a grant can belong to. Grants ride the USER-plane feed, so SERVICE and SYSTEM
#: never hold one.
_GRANT_ACTORS = frozenset({"CUSTOMER", "OPERATOR"})


@dataclass(frozen=True)
class GrantRow:
    """One row of `registry/GRANTS.md`: the grant's actor type and kind (rule 6), and for a
    subject grant its time bound (RUL-193 D2)."""

    actor_type: str
    kind: GrantKind
    #: For an OPERATOR grant, the kind of operator (``AGENT`` · ``ADMIN`` · ``EXTERNAL``).
    actor_kind: str | None = None
    #: Subject grants only: ``"optional"`` -- a ``null`` ``valid_until`` is no bound -- or
    #: ``"required"``. Left ``None`` on a subject grant it reads as REQUIRED: a ``null`` is then
    #: never perpetual. Copy the register's column so an optional grant is honoured.
    time_bound: TimeBound | None = None

    def __post_init__(self) -> None:
        if self.actor_type not in _GRANT_ACTORS:
            raise ValueError(f"a grant's actor type is CUSTOMER or OPERATOR, not {self.actor_type!r}")
        if self.kind not in _KINDS:
            raise ValueError(f"a grant's kind is one of {sorted(_KINDS)}, not {self.kind!r}")
        if self.time_bound is not None:
            if self.time_bound not in _TIME_BOUNDS:
                raise ValueError(
                    f"a time bound is one of {sorted(_TIME_BOUNDS)}, not {self.time_bound!r}"
                )
            if self.kind != "subject":
                raise ValueError(
                    "only a subject grant has a time bound (registry/GRANTS.md, RUL-193 D2)"
                )

    @property
    def unbounded_allowed(self) -> bool:
        """Whether a delegation of this grant may carry ``valid_until: null`` (RUL-193 D2)."""
        return self.time_bound == "optional"


#: ``grant name -> its row``, as the host copies it from `registry/GRANTS.md`.
GrantRegister = Mapping[str, GrantRow]


def normalise_grants(grants: Mapping[str, Any]) -> dict[str, GrantRow]:
    """Accept ``GrantRow`` values, or ``(actor_type, kind[, actor_kind[, time_bound]])``."""
    out: dict[str, GrantRow] = {}
    for name, row in grants.items():
        out[name] = row if isinstance(row, GrantRow) else GrantRow(*row)
    return out


@dataclass(frozen=True)
class Selection:
    """What the capability check may use, and what the service needs to finish the decision."""

    #: The grants to evaluate, in order -- first match wins (RUL-076).
    grants: list[str]
    #: The subject the request acts on (C-053 H3, H6, H7), or ``None`` for the caller's own.
    subject_ref: str | None = None
    #: ``grant -> delegation ref``, for the audit line (H7) when a subject grant opens the route.
    delegation_for: dict[str, str] = field(default_factory=dict)


def select(
    principal: Any,
    *,
    admitted: Collection[str],
    subject_header: str | None,
    grants: GrantRegister,
    now: datetime | None = None,
) -> Selection:
    """The grants that may open this route for this request. See the module docstring.

    :raises ActorTypeNotAdmitted: the caller's actor type, or session kind, is not admitted here.
        The adapter answers as a router miss (``404 PLAT0006``, RUL-158).
    :raises SubjectNotReachable: any refusal about subjects -- one identical answer.
    :raises AuthzUnavailable: a grant outside the session's actor type, or not in the register.
    """
    actor = principal.actor_type
    admitted = frozenset(admitted)
    if actor not in admitted:
        raise ActorTypeNotAdmitted(f"actor type {actor!r} is not admitted here ({sorted(admitted)})")

    held = list(principal.entitlements)
    for name in held:
        _row_for(name, actor, grants)

    if admitted == {"OPERATOR"}:
        if subject_header is not None:
            raise SubjectNotReachable("a Subject-Ref on an OPERATOR-only route (RUL-177)")
        return Selection(grants=[g for g in held if grants[g].kind == "unbound"])

    # A route admitting CUSTOMER. An operator is served here only as a shadow session (§9).
    shadow = principal.session_kind == "SHADOW"
    if actor == "OPERATOR" and not shadow:
        raise ActorTypeNotAdmitted("an operator on a customer route must be in a SHADOW session")
    if shadow and subject_header != principal.delegations[0].subject_ref:
        raise SubjectNotReachable("a shadow session's Subject-Ref is missing or not its subject (H2)")

    if subject_header is None:
        return Selection(grants=[g for g in held if grants[g].kind == "self"])

    usable: list[str] = []
    delegation_for: dict[str, str] = {}
    for d in principal.delegations:
        if d.subject_ref != subject_header:
            continue
        row = _row_for(d.grant, actor, grants)
        if row.kind != "subject":
            raise AuthzUnavailable(f"delegation {d.ref} carries {d.grant!r}, which is not a subject grant")
        if d.valid_until is None and not row.unbounded_allowed:
            # RUL-193 D3: a defect in the feed, scoped to THIS delegation -- it counts as none.
            logger.warning("delegation_unbounded_on_required_grant", ref=d.ref, grant=d.grant)
            continue
        if not d.live(now):
            continue
        if d.grant not in delegation_for:
            usable.append(d.grant)
            delegation_for[d.grant] = d.ref
    if not usable:
        # Unknown subject, or one without a live delegation: the same answer (H4).
        raise SubjectNotReachable("no live delegation for this Subject-Ref (H4)")
    return Selection(grants=usable, subject_ref=subject_header, delegation_for=delegation_for)


def _row_for(name: str, actor: str, grants: GrantRegister) -> GrantRow:
    row = grants.get(name)
    if row is None:
        raise AuthzUnavailable(f"the feed carries grant {name!r}, which the register does not list")
    if row.actor_type != actor:
        raise AuthzUnavailable(
            f"grant {name!r} belongs to {row.actor_type}, but this session is {actor} (C-052 §7)"
        )
    return row

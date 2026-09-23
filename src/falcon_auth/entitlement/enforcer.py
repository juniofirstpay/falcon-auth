"""The capability gate: does any entitlement the caller holds open this route?

Casbin is used here as an exact-match lookup and nothing more. The model has no role hierarchy, no
wildcards, no attribute expressions -- two string comparisons. That is deliberate: a policy engine
decides *may this principal invoke this capability*, and must never absorb *is this transition
legal* or *is there enough money* (§8), which are answerable only against live state under a lock.

The one non-obvious choice is that casbin's `sub` is the **entitlement**, not the user. So no user
identifier ever enters the policy engine, and the policy is a pure function of the registry -- which
is what lets it be built once at import and shared across every request without a lock.

    registry:  {"orders:read": "ORDER_READ"}     capability -> the entitlement that grants it
    policy:    ("ORDER_READ", "orders:read")     entitlement -> the capability it opens

Note the inversion between the two: the registry is written capability-first because that is how a
route reads ("this door needs..."), and the policy is stored entitlement-first because that is how
the question is asked ("does this key open...").
"""
import casbin
from casbin.model import Model

from collections.abc import Mapping

from ..principal import Principal

__all__ = ("CapabilityEnforcer", "MODEL_TEXT", "Registry", "build_enforcer", "normalise_registry")

#: What a service authors. The value is an ANY-OF list of entitlements (RUL-073): the caller
#: passes if it holds ANY of them. A bare string is accepted and read as a one-element list,
#: so a registry written before the list form keeps working unchanged.
#:
#: The two directions this expresses, and why they are not the same thing:
#:
#:    one entitlement over many capabilities   several rows naming the same entitlement
#:                                             -- grouping, already in use: 12 entitlements
#:                                             govern 2-4 capabilities each
#:    many entitlements over one capability    ONE row listing them, any-of -- alternatives
#:
#: Alternatives are listed EXPLICITLY: no wildcards, no prefix matching, no role transitivity
#: on this axis, so "who can reach this route" is answerable from one row. ADR-210 still
#: governs the judgement -- if one alternative's blast radius differs from another's, it
#: belongs to a DIFFERENT capability, not the same row.
Registry = Mapping[str, str | list[str]]

# The platform's Casbin model, from registry/AUTHZ-MODEL.md section 2, VERBATIM.
#
# Casbin is a mandated stack element (RUL-074) -- the platform's first library mandate -- and this
# text is a platform artifact, never re-authored per service. If each service could write its own
# matcher, "one two-layer policy" would be a suggestion. Copied rather than imported because the
# artifact lives in another repository; it is short, and a divergence is visible in review.
#
#   r.sub / p.sub   a GRANT on the request side, an ENTITLEMENT on the policy side -- the
#                   g() wrapper is what bridges them. Never a user, session or role.
#   r.obj / p.obj   the capability a route demands. Never a URL, table or object id.
#   g row           grant -> entitlement (the expansion)
#   p row           entitlement -> capability (the gate)
#
# No user identifier enters the engine, so the policy stays a pure function of the registry --
# built once at import and shared across requests without a lock.
MODEL_TEXT = """
[request_definition]
r = sub, obj
[policy_definition]
p = sub, obj
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj
"""


class CapabilityEnforcer:
    """Wraps casbin so callers ask one question and the first-match-wins loop lives in one place."""

    def __init__(self, enforcer: casbin.Enforcer, registry: Registry) -> None:
        self._enforcer = enforcer
        self._registry = normalise_registry(registry)

    @property
    def registry(self) -> dict[str, list[str]]:
        """The capability -> entitlements map this enforcer was built from.

        Always the NORMALISED form -- every value a list, whatever the author wrote -- so a
        caller reading it back never has to branch on the two shapes. A copy; do not mutate.
        """
        return {cap: list(ents) for cap, ents in self._registry.items()}

    def knows(self, capability: str) -> bool:
        """Whether `capability` has a policy row at all.

        An unknown capability is denied by `allows` regardless -- no policy can match it -- but a
        route asking for one it never registered is a wiring bug, not a user denial, and a host's
        startup check should be able to say so.
        """
        return capability in self._registry

    def opened_by(self, subjects: list[str], capability: str) -> str | None:
        """The FIRST subject that opens `capability`, or ``None`` if none does.

        RUL-076: evaluation is per subject, first match wins. The verdict is the same one
        ``any()`` gave -- the difference is that a boolean cannot tell C-032's audit line WHICH
        grant was responsible, and "who opened this route" is exactly what an audit trail is for
        when a principal holds several.

        Order is the caller's. Grants compose as a union and the model has no deny effect, so no
        ordering can change the verdict -- only which of several equally sufficient subjects is
        recorded. The first is chosen because it is the one the caller listed first, which is a
        reason a reader can reconstruct.
        """
        for subject in subjects:
            if self._enforcer.enforce(subject, capability):
                return subject
        return None

    def allows(self, subjects: list[str], capability: str) -> bool:
        """True iff any held subject opens `capability`. Empty holdings deny.

        A subject is a GRANT after C-038 -- casbin walks `g(grant, entitlement)` then matches
        `p(entitlement, capability)` in one call. An ENTITLEMENT still works unchanged, because
        the default role manager counts ``name1 == name2`` as a link, which is what makes the
        two-layer adoption non-breaking.
        """
        return self.opened_by(subjects, capability) is not None

    def allows_principal(self, principal: Principal, capability: str) -> bool:
        return self.allows(principal.entitlements, capability)

    def principal_opened_by(self, principal: Principal, capability: str) -> str | None:
        """:meth:`opened_by` for a principal -- the audit-line form."""
        return self.opened_by(principal.entitlements, capability)


def normalise_registry(registry: Registry) -> dict[str, list[str]]:
    """Read every value as an any-of list, and refuse a row that grants nothing.

    A capability mapped to nothing -- an empty string, an empty list, or a list of blanks -- would
    deny every caller forever while LOOKING configured. It fails at import rather than at 3am,
    for the same reason absence must never mean "ungated".
    """
    out: dict[str, list[str]] = {}
    blank: list[str] = []
    for capability, value in registry.items():
        entitlements = [value] if isinstance(value, str) else list(value)
        kept = [e.strip() for e in entitlements if isinstance(e, str) and e.strip()]
        if not kept:
            blank.append(capability)
            continue
        out[capability] = kept
    if blank:
        raise ValueError(
            f"capabilities mapped to an empty entitlement: {', '.join(sorted(blank))}"
        )
    return out


def build_enforcer(
    registry: Registry,
    *,
    expansion: Mapping[str, list[str]] | None = None,
) -> CapabilityEnforcer:
    """Build the gate from a service's capability registry. In-memory: no adapter, no policy file.

    ⛔ No policy adapter, deliberately (RUL-075): a change to who may reach a route is a DEPLOY,
    reviewable in a diff, never a row someone edits in a datastore while the service is running.

    :param registry: capability -> the entitlements that open it, any-of (RUL-073). Each
        entitlement becomes its own `p` row, so any-of falls out of the policy effect --
        ``some(where (p.eft == allow))`` -- rather than needing a second mechanism.

    :param expansion: ``grant -> the entitlements it expands to``, written as `g` rows in the
        SAME policy set. This is C-038's first layer, and it replaces the hand-written `_expand`
        callable the ported resolver carried -- "no longer hand-written code" (RUL-075).

        ``None`` means no `g` rows, which is the correct state today: auth emits no grants at
        all, and the platform grant register is deliberately empty. With no rows, every
        ``enforce(x, capability)`` still resolves through the default role manager's
        ``name1 == name2`` link, so the gate answers exactly as it did before this layer existed.
    """
    normalised = normalise_registry(registry)

    model: Model = casbin.Enforcer.new_model(text=MODEL_TEXT)
    enforcer = casbin.Enforcer(model)
    for capability, entitlements in normalised.items():
        for entitlement in entitlements:
            enforcer.add_policy(entitlement, capability)
    for grant, entitlements in (expansion or {}).items():
        for entitlement in entitlements:
            enforcer.add_grouping_policy(grant, entitlement)
    return CapabilityEnforcer(enforcer, normalised)


# ---------------------------------------------------------------------------------------------
# C-038 CONFORMANCE, OWED (Phase C) -- recorded here so the gap is visible at the code, not only
# in a register. This module is a faithful port of what runs in two services today; the
# convention that reshapes it was ratified after it was written.
#
#   Flatness lint          `g` is transitive in casbin to maxHierarchyLevel and cannot express
#                          flatness itself, so a build-time lint must reject any name appearing
#                          on both sides of a row
#
#   Grant register         every `g` row's grant must be listed in registry/GRANTS.md, and an
#                          unregistered grant must REFUSE BOOT -- never resolve to "holds
#                          nothing" and continue
#
# Adoption is non-breaking: `Enforce(entitlement, capability)` keeps answering identically once
# `g` rows exist, because casbin's default role manager counts `name1 == name2` as a link. So
# the two layers can land before auth emits a single grant.
# ---------------------------------------------------------------------------------------------

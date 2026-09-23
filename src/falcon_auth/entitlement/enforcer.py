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

from ..principal import Principal

__all__ = ("CapabilityEnforcer", "MODEL_TEXT", "build_enforcer")

# `sub` = a held entitlement · `obj` = the capability a route requires. Allow iff a policy pairs them
# exactly. Nothing else is expressible, and nothing else should be.
MODEL_TEXT = """
[request_definition]
r = sub, obj
[policy_definition]
p = sub, obj
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj
"""


class CapabilityEnforcer:
    """Wraps casbin so callers ask one question and the first-match-wins loop lives in one place."""

    def __init__(self, enforcer: casbin.Enforcer, registry: dict[str, str]) -> None:
        self._enforcer = enforcer
        self._registry = dict(registry)

    @property
    def registry(self) -> dict[str, str]:
        """The capability -> entitlement map this enforcer was built from (a copy; do not mutate)."""
        return dict(self._registry)

    def knows(self, capability: str) -> bool:
        """Whether `capability` has a policy row at all.

        An unknown capability is denied by `allows` regardless -- no policy can match it -- but a
        route asking for one it never registered is a wiring bug, not a user denial, and a host's
        startup check should be able to say so.
        """
        return capability in self._registry

    def allows(self, entitlements: list[str], capability: str) -> bool:
        """True iff any held entitlement has a policy granting `capability`. Empty holdings deny."""
        return any(self._enforcer.enforce(entitlement, capability) for entitlement in entitlements)

    def allows_principal(self, principal: Principal, capability: str) -> bool:
        return self.allows(principal.entitlements, capability)


def build_enforcer(registry: dict[str, str]) -> CapabilityEnforcer:
    """Build the gate from a service's §9.1 registry. In-memory policy: no adapter, no policy file.

    Raises on a capability mapped to an empty entitlement. That row would deny every caller forever
    while *looking* configured, so it fails at import rather than at 3am -- the same reason §9.1 says
    absence must never mean ungated.
    """
    blank = sorted(cap for cap, ent in registry.items() if not ent or not ent.strip())
    if blank:
        raise ValueError(f"capabilities mapped to an empty entitlement: {', '.join(blank)}")

    model: Model = casbin.Enforcer.new_model(text=MODEL_TEXT)
    enforcer = casbin.Enforcer(model)
    for capability, entitlement in registry.items():
        enforcer.add_policy(entitlement, capability)
    return CapabilityEnforcer(enforcer, registry)


# ---------------------------------------------------------------------------------------------
# C-038 CONFORMANCE, OWED (Phase C) -- recorded here so the gap is visible at the code, not only
# in a register. This module is a faithful port of what runs in two services today; the
# convention that reshapes it was ratified after it was written.
#
#   MODEL_TEXT             must come from the platform artifact (registry/AUTHZ-MODEL.md §2),
#                          never be re-authored per service. The target adds a
#                          [role_definition] and wraps r.sub: `m = g(r.sub, p.sub) && ...`
#
#   Registry              `dict[str, str]` must become `dict[str, list[str]]`, read ANY-OF
#                          (RUL-073): a capability opened by TXN_READ *or* SUPPORT_READ is one
#                          row listing both, never two capabilities
#
#   The `g` layer          the grant -> entitlement expansion currently lives outside this file
#                          as a hand-written `_expand` callable. C-038 puts it in the SAME
#                          policy set as `g, <grant>, <entitlement>` rows -- "no longer
#                          hand-written code"
#
#   Flatness lint          `g` is transitive in casbin to maxHierarchyLevel and cannot express
#                          flatness itself, so a build-time lint must reject any name appearing
#                          on both sides of a row
#
#   Grant register         every `g` row's grant must be listed in registry/GRANTS.md, and an
#                          unregistered grant must REFUSE BOOT -- never resolve to "holds
#                          nothing" and continue
#
#   Per-grant evaluation   `allows` short-circuits over entitlements, which is right as far as
#                          it goes. C-038 (RUL-076) requires evaluating PER GRANT, first match
#                          wins -- both verdicts agree, but only the loop records WHICH grant
#                          opened the route, which C-032's audit line needs
#
# Adoption is non-breaking: `Enforce(entitlement, capability)` keeps answering identically once
# `g` rows exist, because casbin's default role manager counts `name1 == name2` as a link. So
# the two layers can land before auth emits a single grant.
# ---------------------------------------------------------------------------------------------

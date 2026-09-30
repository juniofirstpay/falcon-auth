"""Build-time checks on the policy: exactly two hops, and every grant registered.

Both are startup failures, and both exist because the engine cannot enforce them itself.

WHY FLATNESS CANNOT BE LEFT TO CASBIN. `g` is transitive to `maxHierarchyLevel`. Given
``g, A, B`` and ``g, B, C``, casbin resolves A to C's capabilities and raises no objection --
reproduced in `tests/test_entitlement.py::test_casbin_chains_a_third_hop_silently`. So "exactly
two hops" is a property the policy CAN violate and the engine will never report. RUL-075 makes
it a build-time lint for exactly that reason, and is explicit that it is never a rule left to
readers.

What a third hop costs: the two layers stop meaning what their names say. A grant that reaches
another grant's entitlements makes "which routes does this grant open" unanswerable without
walking a graph -- and the answer changes when a row is added somewhere else entirely, which is
the property the flat model exists to prevent.

WHY AN UNREGISTERED GRANT MUST REFUSE BOOT. A grant is allocated by the authority and is
immutable once allocated (GRANTS.md rules 1-2). A service naming one that is not in the register
has either invented authority's vocabulary or is holding a row against a name that was retired.
Both resolve to "this principal holds nothing" at runtime, which reads as a permissions problem
and is really a deployment fault. C-038 rules it refuses boot -- never resolved to nothing and
allowed to continue.

THE REGISTER IS PASSED IN, NOT READ. `registry/GRANTS.md` lives in the platform-conventions
repository, and this package reads no files and no configuration. The host supplies the names it
has, the same way it supplies every other fact about its deployment.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping

from .enforcer import Registry, normalise_registry

__all__ = (
    "FlatnessError",
    "PolicyError",
    "UnregisteredGrant",
    "check_flatness",
    "check_grants_registered",
    "check_peers",
    "check_register_disjoint",
    "verify_policy",
)


class PolicyError(ValueError):
    """The policy is arranged in a way the engine would run but the convention forbids."""


class FlatnessError(PolicyError):
    """A name sits on both sides of the expansion, so the policy is more than two hops deep."""


class UnregisteredGrant(PolicyError):
    """A `g` row names a grant the platform register does not list."""


def check_flatness(expansion: Mapping[str, list[str]], registry: Registry | None = None) -> None:
    """Refuse an expansion that is not exactly two hops.

    Three shapes are rejected, and they are three ways of saying one thing -- a name must be a
    grant or an entitlement, never both:

        g, A, A          a self-link. Harmless to evaluate and meaningless to read, and it
                         hides the question of which layer A belongs to
        g, A, B + g, B, C   B is a target and a source, so A chains to C
        A is a grant AND an entitlement in the capability registry
                         GRANTS.md rule 4: a name appears either in the register or in a
                         service's entitlement vocabulary, never both

    :param registry: the capability registry, so the third check can run. Optional because the
        first two are worth having on their own, but a caller with a registry should pass it --
        :func:`verify_policy` always does.
    """
    sources = set(expansion)
    targets = {entitlement for row in expansion.values() for entitlement in row}

    self_links = sorted(g for g in expansion if g in expansion[g])
    if self_links:
        raise FlatnessError(
            f"these grants expand to themselves: {', '.join(self_links)}. A name is a grant or "
            f"an entitlement, never both"
        )

    both = sorted(sources & targets)
    if both:
        raise FlatnessError(
            f"these names are on BOTH sides of the expansion: {', '.join(both)}. casbin would "
            f"chain them to a third hop without objecting -- `g` is transitive and cannot "
            f"express flatness itself. Exactly two hops: grant -> entitlement -> capability"
        )

    if registry is not None:
        entitlements = {
            e for row in normalise_registry(registry).values() for e in row
        }
        collisions = sorted(sources & entitlements)
        if collisions:
            raise FlatnessError(
                f"these names are used as a grant AND as an entitlement in the capability "
                f"registry: {', '.join(collisions)}. GRANTS.md rule 4 -- a name appears in the "
                f"platform register or in this service's vocabulary, never both, because that "
                f"is what keeps the two layers distinguishable"
            )


def check_grants_registered(
    expansion: Mapping[str, list[str]], register: Collection[str]
) -> None:
    """Refuse a `g` row naming a grant the platform register does not list.

    :param register: the grant names from `registry/GRANTS.md`. **Empty is a legitimate value
        today** -- the register is deliberately empty because nothing grants yet -- and it is
        consistent: with no registered grants, an expansion must also be empty, and this raises
        if it is not. That is the correct outcome, not an edge case to wave through.
    """
    unknown = sorted(set(expansion) - set(register))
    if unknown:
        raise UnregisteredGrant(
            f"these grants are not in the platform register: {', '.join(unknown)}. A grant is "
            f"allocated by the authority and immutable once allocated, so an unlisted name is "
            f"either invented here or retired there. Refusing boot -- it is never resolved to "
            f"'holds nothing' and allowed to continue, because that reads as a permissions "
            f"problem and is really a deployment fault"
        )


def check_register_disjoint(registry: Registry, register: Collection[str]) -> None:
    """Refuse a grant name that is also one of this service's entitlements.

    GRANTS.md rule 4 again, but over the REGISTER rather than the expansion -- and that
    distinction is the whole bug this closes.

    :func:`check_flatness` compares the expansion's KEYS against the entitlement vocabulary. With
    an empty expansion that set is empty, so the collision can never be found -- and an empty
    expansion is the state every service is in today, because nothing grants yet. Meanwhile
    casbin's default role manager links ``name1 == name2``, so a grant spelled exactly like an
    entitlement opens that entitlement's routes with **no `g` row at all**:

        verify_policy({"payments:read": "PAYMENT_READ"}, None, grant_register=["PAYMENT_READ"])
        enforcer.allows(["PAYMENT_READ"], "payments:read")   -> True

    That is the layer-3 collapse C-033 forbids: a coarse, estate-wide grant reaching a service's
    routes directly, without passing through the expansion that is supposed to mediate it. The
    check therefore runs over every registered grant, whether or not the expansion mentions it.
    """
    entitlements = {e for row in normalise_registry(registry).values() for e in row}
    collisions = sorted(set(register) & entitlements)
    if collisions:
        raise FlatnessError(
            f"these names are in the platform grant register AND in this service's entitlement "
            f"vocabulary: {', '.join(collisions)}. casbin links name1 == name2, so each of them "
            f"opens its own routes with no `g` row -- a grant reaching layer 3 directly. "
            f"GRANTS.md rule 4: a name is a grant or an entitlement, never both"
        )


def check_peers(
    peers: Mapping[str, list[str]],
    registry: Registry,
    expansion: Mapping[str, list[str]] | None = None,
    grant_register: Collection[str] = (),
) -> None:
    """Refuse service-plane peer rows that break the two-hop shape (C-056, proposed).

    A peer takes the grant's position -- ``g, <peer>, <entitlement>`` -- in the SAME policy, so
    every hazard the grant rows have, the peer rows have too, plus one of their own:

        a peer named like a grant           casbin cannot tell them apart; whichever the name
                                            belongs to, the other's rows answer for it
        a peer named like an entitlement    ``name1 == name2``: the peer opens that
                                            entitlement's routes with no ``g`` row (#1 A2)
        a peer row targeting a grant or     a third hop, which casbin chains silently
        another peer
        a peer row naming an entitlement    the peer holds nothing by it -- a typo that reads
        that opens no capability            as a permissions problem at 3am. This is #8's
                                            typo class on the HOLDING side; the route side is
                                            checked when the hook is decorated

    Grants are named by the platform register and entitlements by the service, so the names do
    not collide by format -- but they are all plain strings to casbin, so it is proved rather
    than assumed. All four sets are known at boot, which makes the proof cheap.
    """
    expansion = expansion or {}
    names = set(peers)
    grants = set(expansion) | set(grant_register)
    entitlements = {e for row in normalise_registry(registry).values() for e in row}
    entitlements |= {e for row in expansion.values() for e in row}

    as_grant = sorted(names & grants)
    if as_grant:
        raise FlatnessError(
            f"these names are both a service-plane peer and a grant: {', '.join(as_grant)}. They "
            f"share one policy, and casbin cannot tell which rows a name belongs to"
        )
    as_entitlement = sorted(names & entitlements)
    if as_entitlement:
        raise FlatnessError(
            f"these peer names are also entitlements: {', '.join(as_entitlement)}. casbin links "
            f"name1 == name2, so each would open that entitlement's routes with no `g` row"
        )
    targets = {e for row in peers.values() for e in row}
    third_hop = sorted(targets & (names | grants))
    if third_hop:
        raise FlatnessError(
            f"these peer rows point at a peer or a grant: {', '.join(third_hop)}. casbin would "
            f"chain a third hop without objecting. Exactly two: peer -> entitlement -> capability"
        )
    opening = {e for row in normalise_registry(registry).values() for e in row}
    dead = sorted(
        f"{peer} -> {e}" for peer, row in peers.items() for e in row if e not in opening
    )
    if dead:
        raise FlatnessError(
            f"these peer rows name an entitlement that opens no capability: {', '.join(dead)}. "
            f"The peer holds nothing by them -- almost always a typo, and one that would surface "
            f"as a 403 on a caller rather than at boot"
        )


def verify_policy(
    registry: Registry,
    expansion: Mapping[str, list[str]] | None = None,
    *,
    grant_register: Collection[str] | None = None,
    peers: Mapping[str, list[str]] | None = None,
) -> None:
    """Run every build-time check. Call once at startup, before serving.

    :param grant_register: the names in `registry/GRANTS.md`. ``None`` SKIPS both register
        checks -- a deliberate escape hatch for a host that has no copy of the register to hand,
        not a default anyone should settle for. Passing an empty collection is the stricter and
        more honest position today: it asserts that an expansion must also be empty, which is
        exactly true while nothing grants.
    :param peers: the service-plane peer rows passed to ``build_enforcer(peers=...)``. Checked by
        :func:`check_peers` whenever given -- against the register too, when one is passed.
    """
    expansion = expansion or {}
    check_flatness(expansion, registry)
    if grant_register is not None:
        check_grants_registered(expansion, grant_register)
        # Over the REGISTER, not the expansion -- see the function. This is the check that an
        # empty expansion used to skip entirely.
        check_register_disjoint(registry, grant_register)
    if peers:
        check_peers(peers, registry, expansion, grant_register or ())

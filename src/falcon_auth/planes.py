"""The plane vocabulary: who is calling, and therefore how they prove it.

A **plane** is the kind of caller an endpoint is mounted for. C-038 fixes four of them and
pins each to an authentication method drawn from a **closed set**:

    USER        JWT bearer                  identity from the token's claims
    SERVICE     mTLS                        identity from the peer CN
    CALLBACK    HMAC or one-shot token      identity from the signature, or a token we minted
    PUBLIC      none                        no identity

The enclosure is always mTLS -- every in-VPC hop is mutually authenticated -- so the method in
that table is not "the only TLS"; it is what *authorizes* the request on top of a transport that
is already mutual. SERVICE is the plane where the two coincide, which is why its identity is the
enclosure context itself rather than anything in the request body or headers.

WHY THIS MODULE EXISTS. The vocabulary was previously defined twice, in two packages, with
different spellings, and the package this one replaces had no name for USER or PUBLIC at all --
only the two kinds that arrive by certificate. A plane spelled two ways is a plane that can be
compared unequal to itself, and the comparison that matters here decides whether a request is
answered or refused.

WHY THESE ARE CODE AND NOT CONFIGURATION. C-037 puts deployment values in settings; this is not
one. "Which method authenticates the service plane" is policy, and a settings key for it is one
edit away from a deployment where mTLS is not required. Constants, reviewed in a pull request --
or nothing.
"""
from collections.abc import Mapping
from typing import Literal

__all__ = (
    "CALLBACK",
    "EAST_WEST_KINDS",
    "EastWestKind",
    "HMAC",
    "JWT",
    "METHODS_BY_PLANE",
    "MTLS",
    "Method",
    "ONE_SHOT_TOKEN",
    "PLANES",
    "PLANE_BY_METHOD",
    "PUBLIC",
    "Plane",
    "SERVICE",
    "USER",
    "methods_for",
    "plane_for",
)


# ── planes ────────────────────────────────────────────────────────────────────────────────

#: The four planes. A ``Literal`` rather than an ``Enum`` on purpose: these strings are written
#: by hand in consumers' allow-list config (``kind: SERVICE``), so the value a reader types and
#: the value the code compares must be the same object with no unwrapping step between them.
#: It also gives mypy exhaustiveness on a ``match`` over planes, which an ``Enum`` of ``str``
#: does not do as cleanly.
Plane = Literal["USER", "SERVICE", "CALLBACK", "PUBLIC"]

USER: Plane = "USER"
SERVICE: Plane = "SERVICE"
CALLBACK: Plane = "CALLBACK"
PUBLIC: Plane = "PUBLIC"

#: Every plane, for a startup check that a route's declared plane is one of them. A route
#: mounted on a misspelled plane must fail at boot: it would otherwise match no rule in the
#: middleware's map and, depending on how that map is read, be ungated.
PLANES: frozenset[Plane] = frozenset({USER, SERVICE, CALLBACK, PUBLIC})


# ── methods ───────────────────────────────────────────────────────────────────────────────

#: The closed set of authentication methods. Closed is the whole point: an api-key is not here,
#: and that absence is load-bearing rather than an oversight.
Method = Literal["JWT", "MTLS", "HMAC", "ONE_SHOT_TOKEN"]

JWT: Method = "JWT"
MTLS: Method = "MTLS"
HMAC: Method = "HMAC"
#: Spelled out rather than ``TOKEN`` so it can never be read as the JWT bearer. It is a
#: single-use credential this service minted, verified and consumed (C-030).
ONE_SHOT_TOKEN: Method = "ONE_SHOT_TOKEN"


# ── the map ───────────────────────────────────────────────────────────────────────────────

#: ``plane -> the methods that authenticate on it``.
#:
#: USER and SERVICE are PINNED to exactly one method each -- that is what "one authentication
#: method per plane" means and the set is not permitted to grow. CALLBACK is the one plane that
#: carries two, because a callback source proves itself either by signing the body or by
#: presenting a token we handed it, and the estate has both kinds of counterparty.
#:
#: This does NOT loosen C-031 ("one verification method per callback source"). The plane permits
#: two; each individual source is pinned to one of them at its own registration. The plane-level
#: set is the union of what any source may use, never a choice offered per request -- a request
#: that may prove itself two ways is a request an attacker may prove one way.
#:
#: PUBLIC maps to an EMPTY set rather than to ``None``. Empty says "no method authenticates
#: here", which is a fact about the plane; ``None`` would say "unknown", and every call site
#: would have to branch on it -- with the fail-open branch being the short one.
METHODS_BY_PLANE: Mapping[Plane, frozenset[Method]] = {
    USER: frozenset({JWT}),
    SERVICE: frozenset({MTLS}),
    CALLBACK: frozenset({HMAC, ONE_SHOT_TOKEN}),
    PUBLIC: frozenset(),
}

#: ``method -> the single plane it authenticates on``, derived from the map above.
#:
#: This inverse is what makes C-038's step 4 computable: a caller presenting a VALID credential
#: that belongs to a different plane gets a 404 -- body identical to a genuine not-found -- and
#: the mismatch is logged and flagged. To answer "a different plane" the code must be able to
#: name the plane a credential belongs to, and that is only a question with an answer while each
#: method sits under exactly one plane.
#:
#: So the construction below is not a convenience; it is an assertion. If a method were ever
#: listed under two planes, this module would refuse to import rather than let the 404 rule
#: silently become "whichever plane was iterated last".
def _invert(by_plane: Mapping[Plane, frozenset[Method]]) -> Mapping[Method, Plane]:
    inverse: dict[Method, Plane] = {}
    for plane, methods in by_plane.items():
        for method in methods:
            if method in inverse:
                raise ValueError(
                    f"method {method!r} is listed under two planes "
                    f"({inverse[method]!r} and {plane!r}); the plane of a credential must be "
                    f"unambiguous or C-038's wrong-plane 404 has no defined answer"
                )
            inverse[method] = plane
    return inverse


PLANE_BY_METHOD: Mapping[Method, Plane] = _invert(METHODS_BY_PLANE)


# ── lookups ───────────────────────────────────────────────────────────────────────────────


def methods_for(plane: Plane) -> frozenset[Method]:
    """The methods that authenticate on ``plane``.

    Raises on an unknown plane rather than returning an empty set. The two are opposite facts --
    "nothing authenticates here" is PUBLIC, a deliberate declaration, while an unknown plane is
    a wiring bug -- and collapsing them would make a typo'd plane name behave exactly like the
    one plane that needs no credential.
    """
    try:
        return METHODS_BY_PLANE[plane]
    except KeyError:
        raise ValueError(f"unknown plane {plane!r}; expected one of {sorted(PLANES)}") from None


def plane_for(method: Method) -> Plane:
    """The plane ``method`` authenticates on. See :data:`PLANE_BY_METHOD`."""
    try:
        return PLANE_BY_METHOD[method]
    except KeyError:
        raise ValueError(
            f"unknown authentication method {method!r}; expected one of "
            f"{sorted(PLANE_BY_METHOD)}"
        ) from None


# ── the east-west subset ──────────────────────────────────────────────────────────────────

#: The planes whose identity arrives on the certificate, and so the only ``kind`` values an
#: east-west allow-list entry may carry.
#:
#: Narrowed HERE rather than spelled again in :mod:`falcon_auth.eastwest.verifier`, so the
#: allow-list's accepted values and the plane vocabulary cannot drift apart. The values are
#: unchanged from that module's original ``KIND_SERVICE`` / ``KIND_CALLBACK``, which is why
#: adopting this module rewrites no consumer's config.
EastWestKind = Literal["SERVICE", "CALLBACK"]

#: The runtime companion to :data:`EastWestKind`, for validating config rows at boot.
EAST_WEST_KINDS: frozenset[Plane] = frozenset({SERVICE, CALLBACK})

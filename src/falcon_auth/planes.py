"""The plane vocabulary: which credential an endpoint is mounted for, and how it is checked.

C-060 (platform-conventions ``v30``) fixes **five planes**, each holding a closed set of
authentication methods **named by how they are checked**; a route declares **exactly one**:

    USER        JWT                                       the token's claims
    CLIENT      DPOP_PROOF · REFERENCE_TOKEN · ONE_SHOT_TOKEN
                                                          a registered client before any user
                                                          session exists -- ⛔ the identity
                                                          provider's ONLY
    SERVICE     MTLS                                      the peer CN
    CALLBACK    HMAC · ONE_SHOT_TOKEN                     the signature, or a token we minted
    PUBLIC      none                                      no caller principal (C-060 §5)

The enclosure is always mTLS -- every in-VPC hop is mutually authenticated -- so the method in
that table is not "the only TLS"; it is what *authorizes* the request on top of a transport that
is already mutual. SERVICE is the plane where the two coincide, which is why its identity is the
enclosure context itself rather than anything in the request body or headers.

**This package serves resource services** (RUL-157: a pinned artifact for the Python stack, the
identity provider carved out -- it enforces through its own mechanism, C-061 §2). So CLIENT is
named here, because the vocabulary is the platform's, but a resource service may not mount it:
see :data:`RESOURCE_SERVICE_PLANES`.

WHY THESE ARE CODE AND NOT CONFIGURATION. C-037 puts deployment values in settings; this is not
one. "Which method authenticates the service plane" is policy, and a settings key for it is one
edit away from a deployment where mTLS is not required. Constants, reviewed in a pull request --
or nothing.
"""
from collections.abc import Mapping
from typing import Literal

__all__ = (
    "CALLBACK",
    "CLIENT",
    "DPOP_PROOF",
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
    "REFERENCE_TOKEN",
    "RESOURCE_SERVICE_PLANES",
    "SEARCHABLE_METHODS",
    "SERVICE",
    "USER",
    "methods_for",
    "plane_for",
)


# ── planes ────────────────────────────────────────────────────────────────────────────────

#: The five planes. A ``Literal`` rather than an ``Enum`` on purpose: these strings are written
#: by hand in consumers' allow-list config (``kind: SERVICE``), so the value a reader types and
#: the value the code compares must be the same object with no unwrapping step between them.
Plane = Literal["USER", "CLIENT", "SERVICE", "CALLBACK", "PUBLIC"]

USER: Plane = "USER"
#: Pre-user: a registered client, or an auth-issued link, authenticates before any session
#: exists (C-060 §2). Its routes declare no actor type -- the actor type is born with a session.
CLIENT: Plane = "CLIENT"
SERVICE: Plane = "SERVICE"
CALLBACK: Plane = "CALLBACK"
PUBLIC: Plane = "PUBLIC"

#: Every plane, for a startup check that a route's declared plane is one of them. A route
#: mounted on a misspelled plane must fail at boot: it would otherwise match no rule in the
#: middleware's map and, depending on how that map is read, be ungated.
PLANES: frozenset[Plane] = frozenset({USER, CLIENT, SERVICE, CALLBACK, PUBLIC})

#: The planes a **resource service** may mount. CLIENT is ⛔ the identity provider's only
#: (C-060 §2), and the identity provider does not use this package (RUL-157), so the registry
#: refuses a CLIENT route outright rather than leaving it to a profile.
RESOURCE_SERVICE_PLANES: frozenset[Plane] = PLANES - {CLIENT}


# ── methods ───────────────────────────────────────────────────────────────────────────────

#: The closed set of authentication methods, **named by how they are checked** (C-060 §3) --
#: not "bearer" (how a token is used) or "opaque" (what it looks like). An api-key is not here,
#: and that absence is load-bearing rather than an oversight.
Method = Literal["JWT", "MTLS", "HMAC", "ONE_SHOT_TOKEN", "REFERENCE_TOKEN", "DPOP_PROOF"]

JWT: Method = "JWT"
MTLS: Method = "MTLS"
HMAC: Method = "HMAC"
#: Spelled out rather than ``TOKEN`` so it can never be read as the JWT bearer. A single-use
#: credential this service minted, verified and consumed (C-030).
ONE_SHOT_TOKEN: Method = "ONE_SHOT_TOKEN"
#: Opaque, looked up, reusable until it expires. CLIENT only.
REFERENCE_TOKEN: Method = "REFERENCE_TOKEN"
#: A DPoP proof by a registered client key, as the whole credential. CLIENT only. Named so the
#: vocabulary is whole; this package builds no authenticator for it (the identity provider's).
DPOP_PROOF: Method = "DPOP_PROOF"


# ── the map ───────────────────────────────────────────────────────────────────────────────

#: ``plane -> the methods that authenticate on it``, exactly as C-060 §3 rules.
#:
#: A plane holds a SET; a **route declares exactly one** of it (C-060 §3, C-031's reason at route
#: grain: a request that may prove itself two ways is a request an attacker may prove one way).
#: CALLBACK's two methods therefore mean "a source is pinned to one or the other", never "either
#: per request".
#:
#: PUBLIC maps to an EMPTY set rather than to ``None``. Empty says "no method authenticates
#: here", which is a fact about the plane; ``None`` would say "unknown", and every call site
#: would have to branch on it -- with the fail-open branch being the short one.
METHODS_BY_PLANE: Mapping[Plane, frozenset[Method]] = {
    USER: frozenset({JWT}),
    CLIENT: frozenset({DPOP_PROOF, REFERENCE_TOKEN, ONE_SHOT_TOKEN}),
    SERVICE: frozenset({MTLS}),
    CALLBACK: frozenset({HMAC, ONE_SHOT_TOKEN}),
    PUBLIC: frozenset(),
}

#: The methods the **wrong-plane search** may verify (C-060 §6, refining C-038 step 4): only
#: credentials **verifiable without I/O** -- the TLS peer identity, and a JWT's signature, expiry
#: and audience. A credential that needs a lookup to validate (a reference token, a client-key
#: proof, a one-shot token) is treated as ABSENT there, so a probe carrying junk cannot turn the
#: 404 rule into database load.
SEARCHABLE_METHODS: frozenset[Method] = frozenset({JWT, MTLS})


#: ``method -> the plane it authenticates on``, for a **resource service**.
#:
#: The original shape of ``PlaneAuthenticationMiddleware(authenticators={Method: callable})``
#: places each authenticator by this map. Over all five planes it is not a function --
#: ONE_SHOT_TOKEN sits under CLIENT and CALLBACK -- but CLIENT is not a resource service's, so
#: over :data:`RESOURCE_SERVICE_PLANES` each method has one plane, and the construction below
#: asserts it: if that ever stopped holding, this module would refuse to import rather than
#: place a credential on whichever plane was iterated last.
def _invert(by_plane: Mapping[Plane, frozenset[Method]]) -> Mapping[Method, Plane]:
    inverse: dict[Method, Plane] = {}
    for plane, methods in by_plane.items():
        for method in methods:
            if method in inverse:
                raise ValueError(
                    f"method {method!r} is listed under two planes "
                    f"({inverse[method]!r} and {plane!r}); the plane of a credential must be "
                    f"unambiguous to place it"
                )
            inverse[method] = plane
    return inverse


PLANE_BY_METHOD: Mapping[Method, Plane] = _invert(
    {p: m for p, m in METHODS_BY_PLANE.items() if p in RESOURCE_SERVICE_PLANES}
)


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
    """The resource-service plane ``method`` authenticates on. See :data:`PLANE_BY_METHOD`."""
    try:
        return PLANE_BY_METHOD[method]
    except KeyError:
        raise ValueError(
            f"{method!r} authenticates on no resource-service plane; expected one of "
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

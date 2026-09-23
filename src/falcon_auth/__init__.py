"""falcon-auth — every post-transport trust decision a Falcon service makes.

Four parts, one question: **may this caller do this?**

    eastwest/      is this peer service who its certificate says, and does it hold this scope
    identity/      who is this user
    assurance/     how strongly, and how recently, did they authenticate
    entitlement/   what class of thing may this principal do

Three modules sit above the parts because they are the shared vocabulary the package exists
to unify — none of them ever moves inside a part:

    planes.py          the four planes, the registry, and the mount that records them
    principal.py       one principal model, both planes
    trustcontext.py    ONE call to auth, read by both assurance and entitlement

**The boundary this package keeps.** The east-west, identity and assurance parts may
*establish* who a caller is and how strongly. They may never *decide* permission — only
`entitlement/` decides. A guard test asserts the import direction, because packaging is no
longer holding that line.

**Out of scope, permanently.** Ownership ("is this *their* object") and domain ("does the
object's state permit it") stay with the owning service: only it holds the data, and any answer
computed elsewhere is stale by the time it is used.

**Framework-agnostic cores.** Nothing outside `adapters/` imports Falcon. Every core is driven
by plain values — a token string, two reference strings, a raw ASGI scope — so each is
exercisable without a web framework.

**No transport, no configuration.** The package performs no HTTP of its own and reads no
settings. A consumer injects its own session getter and passes every value as an argument.
"""

from __future__ import annotations

__version__ = "0.1.0"

# The public API is re-exported here as each part lands; the submodule tree is an
# implementation detail, except `adapters`, which consumers import directly for the
# Falcon integration.
#
# Landed: eastwest (A1) · identity (A2) · trustcontext + errors (A4a) · assurance (B1)
#         · principal + entitlement (A3) · planes (A4).
# The plane vocabulary. The bare constants (USER, SERVICE, CALLBACK, PUBLIC) are NOT
# re-exported at top level: `from falcon_auth import SERVICE` reads ambiguously at a call site
# and collides with names a consumer is likely to have of its own. Import the module and say
# `planes.SERVICE`, which says which vocabulary the value belongs to.
from . import planes
from .planes import (
    EAST_WEST_KINDS,
    METHODS_BY_PLANE,
    PLANE_BY_METHOD,
    PLANES,
    EastWestKind,
    Method,
    Plane,
    methods_for,
    plane_for,
)
from .eastwest import (
    KIND_CALLBACK,
    KIND_SERVICE,
    AllowList,
    MissingClientCertError,
    MissingScopeError,
    PeerCertH11Protocol,
    PeerCertHttpToolsProtocol,
    Principal,
    SvcPlaneError,
    SvcPlaneErrorCodes,
    UnknownCNError,
    Verifier,
    build_allow_list,
    build_uvicorn_ssl_kwargs,
    peer_cn,
)
from .errors import (
    AuthzError,
    AuthzUnavailable,
    CapabilityDenied,
    SessionMiss,
    StepUpRequired,
    Unauthenticated,
)
from .trustcontext import (
    DEVICE_TRUST_ATTESTED,
    DEVICE_TRUST_BOUND,
    DEVICE_TRUST_UNTRUSTED,
    SESSION_TRUST_AUTHENTICATED,
    SESSION_TRUST_ELEVATED,
    Cache,
    HttpTrustContextClient,
    NullCache,
    RedisCache,
    TrustContext,
    TrustContextCache,
    TrustContextClient,
)
from .assurance import check_session_elevated
from .entitlement import (
    AuthenticatedUser,
    AuthServiceResolver,
    CapabilityEnforcer,
    GrantAllResolver,
    Resolver,
    build_enforcer,
)
from .principal import Principal as UserPrincipal
from .identity import (
    DEFAULT_DECODE_OPTIONS,
    InvalidToken,
    JWKSStore,
    JWKSVerifier,
    JWTDecodeOptions,
)

__all__ = (
    "AllowList",
    "AuthenticatedUser",
    "AuthServiceResolver",
    "AuthzError",
    "AuthzUnavailable",
    "build_allow_list",
    "build_enforcer",
    "build_uvicorn_ssl_kwargs",
    "Cache",
    "CapabilityDenied",
    "CapabilityEnforcer",
    "check_session_elevated",
    "DEFAULT_DECODE_OPTIONS",
    "DEVICE_TRUST_ATTESTED",
    "DEVICE_TRUST_BOUND",
    "DEVICE_TRUST_UNTRUSTED",
    "EAST_WEST_KINDS",
    "EastWestKind",
    "GrantAllResolver",
    "HttpTrustContextClient",
    "InvalidToken",
    "JWKSStore",
    "JWKSVerifier",
    "JWTDecodeOptions",
    "KIND_CALLBACK",
    "KIND_SERVICE",
    "Method",
    "METHODS_BY_PLANE",
    "methods_for",
    "MissingClientCertError",
    "MissingScopeError",
    "NullCache",
    "peer_cn",
    "PeerCertH11Protocol",
    "PeerCertHttpToolsProtocol",
    "Plane",
    "PLANE_BY_METHOD",
    "plane_for",
    "planes",
    "PLANES",
    "Principal",
    "RedisCache",
    "Resolver",
    "SESSION_TRUST_AUTHENTICATED",
    "SESSION_TRUST_ELEVATED",
    "SessionMiss",
    "StepUpRequired",
    "SvcPlaneError",
    "SvcPlaneErrorCodes",
    "TrustContext",
    "TrustContextCache",
    "TrustContextClient",
    "Unauthenticated",
    "UnknownCNError",
    "UserPrincipal",
    "Verifier",
    "__version__",
)

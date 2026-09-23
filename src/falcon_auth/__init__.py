"""falcon-auth — every post-transport trust decision a Falcon service makes.

Four parts, one question: **may this caller do this?**

    eastwest/      is this peer service who its certificate says, and does it hold this scope
    identity/      who is this user
    assurance/     how strongly, and how recently, did they authenticate
    entitlement/   what class of thing may this principal do

Three modules sit above the parts because they are the shared vocabulary the package exists
to unify — ⛔ none of them ever moves inside a part:

    planes.py          the four planes, the registry, and the mount that records them
    principal.py       one principal model, both planes
    trustcontext.py    ONE call to auth, read by both assurance and entitlement

**The boundary this package keeps.** The east-west, identity and assurance parts may
*establish* who a caller is and how strongly. They may never *decide* permission — only
`entitlement/` decides. A guard test asserts the import direction, because packaging is no
longer holding that line.

⛔ **Out of scope, permanently.** Ownership ("is this *their* object") and domain ("does the
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
# Landed: eastwest (A1).
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

__all__ = (
    "AllowList",
    "KIND_CALLBACK",
    "KIND_SERVICE",
    "MissingClientCertError",
    "MissingScopeError",
    "PeerCertH11Protocol",
    "PeerCertHttpToolsProtocol",
    "Principal",
    "SvcPlaneError",
    "SvcPlaneErrorCodes",
    "UnknownCNError",
    "Verifier",
    "__version__",
    "build_allow_list",
    "build_uvicorn_ssl_kwargs",
    "peer_cn",
)

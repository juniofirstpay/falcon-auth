"""Part 1 — east-west: peer services over mTLS.

Authorizes a service-plane call by mapping the peer certificate's Common Name to an explicit
set of `noun:verb` scopes. ⛔ An unknown or unmapped CN gets **zero** scopes and is denied; an
empty allow-list rejects everything and never means "allow all".

The CN is read from `scope["extensions"]["tls"]["peer_cert_der"]`, which `mtls` injects. This
part **trusts** that CN: chain validation is TLS's job, delegated to the handshake, where
`CERT_OPTIONAL` means an unverifiable certificate never reaches the application.

⚠ `mtls` is the one module here that is **boot-time transport wiring** rather than a
request-time decision — it configures uvicorn's SSL context so a CN can be read at all.

⭐ **Ported from `falcon-svcplane` behaviour-identical**, with its tests as the correctness
check. Anything that changes what this code *does* belongs in a separate commit, so a failure
during migration can be attributed to one or the other.
"""

from __future__ import annotations

from .errors import (
    MissingClientCertError,
    MissingScopeError,
    SvcPlaneError,
    SvcPlaneErrorCodes,
    UnknownCNError,
)
from .mtls import (
    PeerCertH11Protocol,
    PeerCertHttpToolsProtocol,
    build_uvicorn_ssl_kwargs,
)
from .verifier import (
    KIND_CALLBACK,
    KIND_SERVICE,
    AllowList,
    Principal,
    Verifier,
    build_allow_list,
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
    "build_allow_list",
    "build_uvicorn_ssl_kwargs",
    "peer_cn",
)

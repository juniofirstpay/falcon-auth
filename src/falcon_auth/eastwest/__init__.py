"""Part 1 — east-west: peer services over mTLS.

Authorizes a service-plane call by mapping the peer certificate's Common Name to an explicit
set of `noun:verb` scopes. An unknown or unmapped CN gets **zero** scopes and is denied; an
empty allow-list rejects everything and never means "allow all".

The CN is read from `scope["extensions"]["tls"]["peer_cert_der"]`, which `mtls` injects. This
part **trusts** that CN: chain validation is TLS's job, delegated to the handshake, where
`CERT_OPTIONAL` means an unverifiable certificate never reaches the application.

`mtls` is the one module here that is **boot-time transport wiring** rather than a
request-time decision — it configures uvicorn's SSL context so a CN can be read at all.

**Ported from `falcon-svcplane` behaviour-identical**, with its tests as the correctness
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


# ── the uvicorn protocols, resolved on access (PEP 562) ──────────────────────
#
# These two names SUBCLASS uvicorn, so importing them eagerly here would put an ASGI server on
# the import path of every consumer -- including ones that never serve HTTP. Resolving them in
# `__getattr__` keeps `falcon_auth.eastwest.PeerCertH11Protocol` working while `import falcon_auth` stays server-free.
#
# The trade, stated plainly: a missing uvicorn now fails at ACCESS rather than at import. That
# is later than ideal, and it only reaches a consumer who asked for the uvicorn integration
# without installing the extra -- who gets an ImportError naming it.
_UVICORN_PROTOCOLS = ("PeerCertH11Protocol", "PeerCertHttpToolsProtocol")


def __getattr__(name: str) -> object:
    if name in _UVICORN_PROTOCOLS:
        try:
            from . import uvicorn_protocols
        except ImportError as e:  # pragma: no cover - depends on env
            raise ImportError(
                f"{name} needs uvicorn, which is an optional dependency of falcon-auth. "
                f"Install it with: pip install falcon-auth[uvicorn]"
            ) from e
        value = getattr(uvicorn_protocols, name)
        globals()[name] = value  # cache: __getattr__ runs once per name
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

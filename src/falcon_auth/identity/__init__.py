"""Part 2 — identity: who is this user.

Verifies a JWT against a signing-key set fetched from a remote JWKS endpoint, with the key
selected by the token's `kid` header and the algorithm **pinned server-side** so it can never
be chosen by the token.

The fetch is **injected**: the consumer supplies a coroutine returning the parsed
`{"keys": [...]}` document, so each service keeps its own transport — its mTLS session, its
timeouts, its certificate-rotation story — and the store is testable without a network.

What reaches the principal is an **allowlist**, never a splat. The principle is *established
versus asserted*: this part vouches for what it verified, and a caller must not be able to
assert anything an authorization layer will act on.

**Ported** from the copy running in two services, with the stricter of each repo's
hardenings merged: one had the claim allowlist, the other required `sub` and honoured `nbf`.
`JWKSStore`'s code is identical to that original, verified by AST comparison.
"""

from __future__ import annotations

from .jwks import (
    DEFAULT_DECODE_OPTIONS,
    InvalidToken,
    JWKSStore,
    JWKSVerifier,
    JWTDecodeOptions,
)

__all__ = (
    "DEFAULT_DECODE_OPTIONS",
    "InvalidToken",
    "JWKSStore",
    "JWKSVerifier",
    "JWTDecodeOptions",
)

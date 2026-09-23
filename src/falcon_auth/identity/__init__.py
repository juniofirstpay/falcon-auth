"""Part 2 — identity: who is this user.

Verifies a JWT against a signing-key set fetched from a remote JWKS endpoint, with the key
selected by the token's `kid` header and the algorithm **pinned server-side** so it can never
be chosen by the token.

⭐ The fetch is **injected**: the consumer supplies a coroutine returning the parsed
`{"keys": [...]}` document, so each service keeps its own transport — its mTLS session, its
timeouts, its certificate-rotation story — and the store is testable without a network.

⛔ What reaches the principal is an **allowlist**, never a splat. The principle is *established
versus asserted*: this part vouches for what it verified, and a caller must not be able to
assert anything an authorization layer will act on.

Planned modules:
    jwks.py    JWKSStore · JWKSVerifier · InvalidToken · DEFAULT_DECODE_OPTIONS
"""

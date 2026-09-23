# IDENTITY.md — how a user's token becomes a name

Identity is the **user plane**: a person's app calling us with a JWT. There is no certificate to
read, so the question is different from [east-west](EASTWEST.md)'s:

> Did the auth service really issue this token, is it still valid, and who does it say this is?

In one sentence: **checking a signature against a published keyring.** The auth service signs
tokens with a private key and publishes the matching public keys at a JWKS endpoint. We fetch
that keyring, find the key the token names, and check the signature.

Note what this does **not** do. It establishes *who* the caller is. It says nothing about what
they may do — that is entitlement's job — and nothing about
how recently they proved themselves, which is assurance's.

---

## The pieces

| File | Job |
|---|---|
| `identity/jwks.py` · `JWKSStore` | holds the issuer's public keys, and keeps them current |
| `identity/jwks.py` · `JWKSVerifier` | checks one token against those keys, returns its claims |
| `identity/jwks.py` · `InvalidToken` | the single failure type — every rejection raises it |
| `adapters/authenticators.py` | the Falcon adapter: pull the header, hand over the token |

`JWKSVerifier` takes a bare **string** and returns claims. It never sees a Falcon request, so it
is exercisable without a web framework — and the package performs no HTTP of its own. The fetch
is injected, so each consumer keeps its own transport, timeouts and certificate story.

---

## Phase 1 — boot

```
your app startup
│
├─ JWKSStore(fetcher, ttl=300.0)                                   jwks.py
│     fetcher is YOUR async callable returning the parsed {"keys": [...]}
│     the package makes no HTTP call and reads no configuration
│
├─ JWKSVerifier(store, issuer=..., audience=...,                   jwks.py
│               algorithms=["RS256"], leeway=...,
│               forwarded_claims=frozenset({...}))
│     forwarded_claims is REQUIRED with no default -- see below
│
├─ await store.warm()                                              jwks.py
│     eager fetch so the first request does not pay the latency
│     a failure is LOGGED, not raised -- the server still starts, and the lazy
│     path retries on the first request
│
├─ store.start_polling(60.0)                                       jwks.py
│     background refresh, so a key rotation is picked up before anyone misses
│     idempotent: a second call while running is a no-op
│
└─ auth.add_authenticator("jwt", RemoteJWKSAuthenticator("Authorization", verifier))
```

### Three ways the keyring refreshes, and why all three

| Trigger | Catches |
|---|---|
| `warm()` at boot | the cold start — nobody pays the fetch on the first request |
| `start_polling(60)` | a rotation, *before* any token signed with the new key arrives |
| a cache miss in `get_key` | a rotation that outran the poller |

The third is the safety net, and it is what makes rotation work at all: the issuer can rotate
whenever it likes and the first token carrying an unseen `kid` triggers a refetch.

---

## Phase 2 — a request arrives

```
request with `Authorization: Bearer <token>`
│
└─ RemoteJWKSAuthenticator                          adapters/authenticators.py
   │   reads the header · matches the scheme (case-insensitive) · takes the token
   │
   └─ verifier.verify(token)                                       jwks.py
      │
      ├─ jwt.get_unverified_header(token)
      │     unparseable  ──►  InvalidToken("malformed_header")
      │
      ├─ kid = header["kid"]
      │     absent       ──►  InvalidToken("missing_kid")
      │
      ├─ store.get_key(kid)
      │  │
      │  ├─ cached AND fresh?  ──►  return it, no lock, no fetch
      │  │
      │  └─ otherwise, under the single-flight lock:
      │        re-check  (another coroutine may have just refreshed)
      │        _refresh()
      │        │   fetch failed?  ──►  LOG, and fall through to whatever is cached
      │        └─ return self._keys.get(kid)
      │
      │     still None  ──►  InvalidToken("unknown_kid")
      │
      ├─ jwt.decode(token, key.key,
      │             algorithms=["RS256"],          <-- PINNED, never read from the token
      │             options=DEFAULT_DECODE_OPTIONS,
      │             audience=..., issuer=..., leeway=...)
      │     │
      │     ├─ bad signature · expired · wrong iss · wrong aud · missing sub
      │     │      ──►  InvalidToken(<the PyJWT error class name>)
      │     └─ ──►  claims
      │
      └─ verifier.principal_claims(claims)
            keeps ONLY the allowlisted names; `sub` is excluded deliberately
            │
            └─ the adapter builds the user and sets req.context.user
```

---

## The four things worth understanding

### 1. The algorithm is pinned server-side

`algorithms=["RS256"]` is passed by us and **never read from the token's header**. This is the
algorithm-confusion defence, and it is the classic JWT vulnerability:

- an attacker sets `alg: none` and strips the signature entirely
- or sets `alg: HS256` and signs with our **public** key as the HMAC secret — the public key is
  published at the JWKS endpoint, so anyone can do this

Both produce a token that verifies, if the verifier trusts the header's `alg`. Pinning it
server-side makes both impossible: an RS256 verifier presented with an HS256 token simply fails,
because it never asks the token what algorithm to use.

### 2. `sub` is required, not optional metadata

It is in `require`, alongside `iat` and `exp`. Without it, a validly-signed token with no `sub`
would authenticate successfully and then fail deeper in the stack — a **500 where a 401
belongs**. Requiring it moves the failure to the one place that can answer it properly.

### 3. `forwarded_claims` is required, with no default

This one is the whole reason the parameter exists. The naive form is:

```python
user_cls(id=claims["sub"], type="user", **claims)   # every claim, splatted on
```

That object is then read to make authorization decisions. A token carrying an `entitlements`
claim would be **proposing its own permissions** — and permissions that ride a token make
revocation mean token lifetime. Suspend a compromised user and they keep transacting until it
expires.

An allowlist makes that unreachable by construction rather than by luck. It has no default
because the right value is whatever the consumer's authorization layer looks sessions up by;
defaulting it would put an authorization fact inside this package and leave one constant defined
on both sides of a seam that must silently agree. And it is a constructor argument, never a
settings key — "which token claims may influence authorization" is one config edit away from
being no allowlist at all.

`sub` is excluded from the forwarded set on purpose: callers pass it explicitly as the user's id
rather than letting it through as a claim.

### 4. A stale key is served when the refresh fails

If the JWKS endpoint is down but we already hold a key for this `kid`, that key is used.

This is a deliberate choice of availability over freshness, and it is the right way round: a
signing key that was valid five minutes ago is almost certainly still valid, whereas refusing
every request because the issuer's endpoint blipped turns a dependency wobble into a total
outage. The token's own `exp` still applies, so a stale key cannot extend anyone's session.

---

## Every way a token is rejected

All of them raise `InvalidToken`, and the adapter turns that into an unauthenticated request.

| `reason` | What happened |
|---|---|
| `malformed_header` | not a parseable JWT at all |
| `missing_kid` | no `kid` header, so we cannot tell which key to check |
| `unknown_kid` | a `kid` we do not have, even after a refetch |
| `InvalidSignatureError` | signed by something other than the named key |
| `ExpiredSignatureError` | past `exp` |
| `InvalidIssuerError` / `InvalidAudienceError` | issued by, or for, somebody else |
| `MissingRequiredClaimError` | no `sub`, `iat` or `exp` |
| `ImmatureSignatureError` | `nbf` says not yet valid |

`verify_nbf` is on while `nbf` is *not* in `require` — so a token without one stays valid, but a
token that declares itself not-yet-valid is refused rather than ignored. `leeway` absorbs
ordinary clock skew.

---

## One thing the name does not promise

The `scheme` argument is a **literal string match** on what precedes the credential in the
header. Passing `scheme="DPoP"` means the string `DPoP` is what the adapter looks for. It does
**not** implement RFC 9449: no proof JWT is parsed, no `cnf`/`jkt` thumbprint is bound, nothing
ties the token to a client key.

A token accepted here is a **bearer** credential — replayable by whoever holds it until `exp`.
Worth stating plainly, because the opposite assumption is easy and expensive: a reader who takes
the scheme name at face value will under-rate anything that leaks a token, like a debug log, a
crash dump or a proxied header.

Under C-038 this is correct rather than a gap. Proof-of-possession is discharged at the
perimeter: the gateway calls auth's forward-auth, auth validates the token **and** the proof, and
a resource service receives a bearer already proven. No service other than auth parses DPoP.

---

## `pin_keys` — for tests only

`store.pin_keys([...])` loads a fixed key set and stops fetching; `warm()` and polling become
no-ops. It makes the verifier exercisable offline.

A pinned store **never rotates**. A production deployment that reaches this path has silently
opted out of key rotation, so keep it behind an explicit dev-only branch.

---

## Where this sits

Identity is the USER plane's half of [`FLOW.md`](FLOW.md)'s four planes, the counterpart to
[EASTWEST.md](EASTWEST.md)'s SERVICE and CALLBACK. The plane middleware decides that a route
takes a JWT; this decides whether the JWT is real and whose it is.

What it hands on is a **name, and nothing more**. Everything downstream — which grants the
session holds, how recently the person authenticated, whether they own the object — is resolved
server-side from that name, never read off the token.

# falcon-auth#6: the identity provider's credentials, and how authenticators should be built

> ⛔ **Superseded 2026-10-07 — kept for the record.** The platform ruled differently from parts of
> this design:
>
> - **C-060** (`v30`, RUL-152) gives **five planes**, with a `Client` plane for the identity
>   provider's pre-user routes. It names methods by how they're checked; **a route declares
>   exactly one credential**, and the wrong-plane search counts only I/O-free credentials.
> - **C-061**: a broken property refuses start. C-060's reason calls a permissive profile a
>   loophole.
> - **Auth won't use falcon-auth's constructs** (AUTH-ADR-139), so step 4 and §17.1 are moot, and
>   falcon-auth is a pinned artifact for **resource services only** (RUL-157).
> - The wrong-plane answer is **`404 PLAT0006`** (RUL-158).
>
> What falcon-auth owes is tracked in #11.

> **Status:** a recommendation. Nothing in it has been built or posted. Prepared 2026-10-01 for the
> falcon-auth#6 discussion.
>
> **Read against:**
>
> | Repository | Commit |
> |---|---|
> | falcon-auth | `v0.2.0` / `6c86f3f` |
> | ppi-backend-auth | `24eddd0`, plus open PRs #203 `3b9e0af`, #142 `bf8a3f5`, #185 `8c38cae`, #214 `db008d7`, #210 `02387df`, #186 `726f61c`, #211 `3bad158` |
> | ppi-platform-conventions | `v25` + RUL-132 (C-055/C-056 proposed, unpushed) |
>
> **Related:** ppi-backend-auth#246 (auth's adoption umbrella; #6 is its item P1) · ppi-backend-auth#243 (the
> platform-conventions audit of auth).

---

## Contents

1. [Summary](#1-summary)
2. [The issue as raised](#2-the-issue-as-raised)
3. [The conventions in play](#3-the-conventions-in-play)
4. [What falcon-auth does today](#4-what-falcon-auth-does-today)
5. [What auth actually accepts](#5-what-auth-actually-accepts)
6. [Analysis](#6-analysis)
7. [The issue's options, evaluated](#7-the-issues-options-evaluated)
8. [Recommendation: the design](#8-recommendation-the-design)
9. [Recommendation: auth's routes under the design](#9-recommendation-auths-routes-under-the-design)
10. [Recommendation: the path](#10-recommendation-the-path)
11. [Platform asks](#11-platform-asks)
12. [Auth-side actions, and defects found](#12-auth-side-actions-and-defects-found)
13. [Effect on other consumers](#13-effect-on-other-consumers)
14. [Positions taken in the discussion](#14-positions-taken-in-the-discussion)
15. [Open questions, and what was not verified](#15-open-questions-and-what-was-not-verified)
16. [Glossary](#16-glossary)
17. [Appendix: the HTTP root in its final shape](#17-appendix-the-http-root-in-its-final-shape)

---

## 1. Summary

**The problem.** Auth is the identity provider, so its bootstrap surface (attest → register → authenticate → token)
has to accept credentials that exist before any user does. C-038 fixes a closed set of authentication methods — JWT ·
mTLS · HMAC · one-shot token — and five of auth's nine credential classes have no name in it. Three of auth's routes
also accept either of two credential types.

**The finding.** Every auth hook is a hand-written combination of four independent things:

| Part | What it covers |
|---|---|
| **carrier** | where the credential is read from |
| **check** | how it is verified |
| **binding** | proof of possession: DPoP, in one of three modes |
| **single use** | whether the credential is spent when used |

Writing these combinations by hand is where auth's defects come from.

**The recommendation.**

- **Build authenticators from those four parts.** Each route accepts exactly one credential. Each authenticator
  belongs to exactly one plane.
- **Extend the vocabulary by checks, not carriers.** Two checks join the existing ones:
  - `REFERENCE` — a store lookup, reusable until expiry;
  - `PROOF` — a DPoP proof alone.
- **Fence the new checks to the identity provider.** Both are allowed on USER only for auth, which puts RUL-048 into
  code.
- **Split the three dual-credential routes.** In each, the credential type already changes what the route does.
- **Phase it.**
  - Steps 1–2 ship now and change nothing for existing consumers.
  - Step 3 is one request to the platform.
  - Step 4 (DPoP binding in the package) follows the ruling.

---

## 2. The issue as raised

falcon-auth#6, filed by vishal-junio on 2026-09-28: *"Plane/method vocabulary cannot describe the identity
provider's own credentials (auth adoption)."*

**Its framing.**
- The plane **registry** (`mount` / `verify_app`) fits auth.
- The per-request **`PlaneAuthenticationMiddleware`** does not.
- A team decision is needed, and probably a platform ruling on C-038 / C-006.

**Auth's credential classes, as the issue lists them:**

| # | Credential | Carrier | Routes | Fits a plane + method? |
|---|---|---|---|---|
| 1 | none | — | `/_info`, `/.well-known/jwks.json`, `/links` | PUBLIC ✓ |
| 2 | device-attestation evidence (integrity token + nonce) | body | `/attest` | ✗ |
| 3 | auth-minted software statement | `X-Software-Statement` | `/clients:register`, `/clients/{ref}/reattest` (dead-state branch) | ✗ — nearest is `ONE_SHOT_TOKEN`, which sits on CALLBACK |
| 4 | DPoP proof by a registered client key (install-scoped, pre-user) | `DPoP` | `/clients/{ref}/keys:bind`, `/authentication`, `/token:refresh` | ✗ |
| 5 | #4 + a pre-login client-session bearer | `DPoP` + `Authorization: Bearer` | `/authentication/otp:*`, `/token:create`, `/users:register` | ✗ |
| 6 | DPoP-bound access token (RFC 9449) | `Authorization: DPoP` + `DPoP` | `/sessions/*`, `/mfa:*`, `/mpin/reset:*`, `/devices/*`, `/users/{ref}/keys:bind`, … | USER / JWT ✓, with a DPoP-verifying authenticator from the host |
| 7 | #6 **or** #5, chosen by the `Authorization` scheme | either | `/mpin/forgot/*` | ✗ — USER is pinned to one method |
| 8 | auth-link token + self-signed DPoP proof | `Authorization: Link` + `DPoP` | `/links/{context,phone,otp}` | ✗ — minted by auth but multi-use, so not `ONE_SHOT_TOKEN` |
| 9 | mTLS client-certificate CN | TLS | 11 service-plane routes | SERVICE / MTLS ✓ |

**Its options:**

| | Approach | Change in falcon-auth |
|---|---|---|
| A | Extend C-038's closed method set with the bootstrap methods, then add them to `planes.py` | new `Method` constants and map rows, after a platform ruling |
| B | Plane = caller kind. Auth labels end-user routes USER, adopts the **registry only**, and keeps its own hooks for per-request checking | none |
| C | Label the bootstrap routes PUBLIC | none — but `public_routes()` would report `/token:create` as needing no credential, which is false |

**Auth's leaning** was B. B leaves C-038's wrong-plane 404 unmet on auth.

**Its three questions:**
1. Is plane = caller kind the intended reading? Could USER carry several methods on an identity provider, with each
   route pinned to one?
2. Is the middleware meant for resource services only, or should the identity provider conform too?
3. Are dual-credential routes acceptable under C-031's "one method per source" reasoning, or must they split?

The platform-conventions audit (ppi-backend-auth#243) reached the same finding independently: *"the four-plane
taxonomy has no vocabulary for an install-scoped, pre-user, post-attestation principal."* That finding was listed as
a conflict to raise. It has not yet been raised in the conventions repo: there is no candidate, fork or question
for it.

---

## 3. The conventions in play

### 3.1 The rules

| Rule | What it says | Effect on #6 |
|---|---|---|
| **C-038** (ratified `v18`) | One authentication method per plane, from a closed set: USER = **JWT** (bearer), SERVICE = **mTLS**, CALLBACK = **HMAC or one-shot token**, PUBLIC = none. Proof of possession (DPoP) is "discharged at the perimeter … ⛔ no other service parses or knows about DPoP". | Rows 2–5 and 8 have no method. Option A needs a ruling. |
| **RUL-046 §5** (verbatim) | "Every plane uses one authentication method: JWT, mTLS, one shot tokens or HMAC." | The closed set is the authority's own words. |
| **RUL-049 F4 / Q86** | The middleware holds `plane → [methods]`. USER and SERVICE are each pinned to one method; CALLBACK may list two, and C-031's per-source choice draws from that set. | "Several methods on USER" (option B) reopens a closed question. |
| **C-038 resolution table** | 1 the plane selects the primary method · 2 primary present and invalid → **401** · 3 primary absent → look for other methods' credentials · 4 a valid credential for another plane → **404**, logged and flagged · 5 nothing → **401**. Q88: verify at most one secondary credential. | The middleware implements this. B forgoes step 4 on auth. |
| **RUL-048** | "DPoP validation is only the gateway's and auth's domain. No other service needs to know about or use DPoP." | Auth is already the named DPoP exception. A DPoP verifier in the package must be fenced to auth. |
| **C-006** (ratified `v9`, clauses superseded) | One plane per endpoint, refused at startup; one resource class per plane. "The plane follows the credential that authorizes the call." Health probes sit outside the plane system (RUL-033). Every PUBLIC route states a reason. | `/_info` need not be PUBLIC. "Plane = caller kind" contradicts "the plane follows the credential". |
| **C-052** (ratified `v23`) | Planes stay four. Caller kind is the **actor type** (`CUSTOMER` · `OPERATOR` · `SERVICE` · `SYSTEM`), declared per route inside a plane. An operator plane was rejected because *"a plane is an authentication method (C-038)"*. | Option B's "plane = caller kind" is now the job of actor type. No actor type fits a pre-user app install. |
| **C-031** (ratified) | One verification method per callback source — ⛔ never "any of these". "Accepting several methods means an attacker picks the weakest." | Directly answers the issue's question 3. |
| **C-030** (ratified) | A single-use authorization is verified and consumed atomically **before** the change, **after** idempotency, and bound to a JCS hash of the request body. | Single-use tokens must be consumed in the handler's transaction, not in middleware. Whether the body binding applies to the software statement is open. |
| **CAND-44** (staged, unruled) | Client attestation is "auth's domain, like DPoP"; a client has an identity of its own, distinct from the user's. | The nearest existing name for rows 2–5. |
| **C-056** (proposed, RUL-132) | Service-plane authorization joins the Casbin policy: the allow-list says which peer a certificate is (`cn → source`), and policy rows in code say what it may do. | Row 9 only. No effect on the rest of #6. |

### 3.2 Auth's registered exceptions (`exceptions/ppi-backend-auth.md`)

These are already recorded, with owner vishal.ranjan and review date 2026-12-18:

- C-006: no plane registry.
- C-006: `UserRoute` spans two planes.
- C-006: classes are named by URL prefix.
- C-006: no per-request plane check.
- C-038: no wrong-plane 404 and no flag.

The non-conformance that option B leaves is already a registered exception, not new debt.

---

## 4. What falcon-auth does today

| Piece | Where | Behaviour |
|---|---|---|
| Plane vocabulary | `planes.py` | `METHODS_BY_PLANE`: USER `{JWT}`, SERVICE `{MTLS}`, CALLBACK `{HMAC, ONE_SHOT_TOKEN}`, PUBLIC `{}`. The docstring says USER and SERVICE are "not permitted to grow". `PLANE_BY_METHOD` is built by `_invert`, which **refuses to import** if a method sits under two planes, because the wrong-plane 404 must be able to name a credential's plane. The module docstring still reads "a plane is the kind of caller", which C-052 has overtaken. |
| Middleware | `adapters/middleware.py` | Implements the C-038 table. `_primary_for(plane)` demands an authenticator for **every** method of the plane. `_find_foreign_credential` stops at the first verification. `verify()` (`5dd61d6`) checks at startup that every mounted plane has authenticators. |
| Authenticators | `adapters/authenticators.py` | Two, tri-state: `jwt_authenticator(verifier, user_cls, header_name="Authorization", scheme="Bearer")` and `mtls_authenticator(verifier)`. **No HMAC or one-shot authenticator exists**, although both constants do. |
| Registry | `adapters/routing.py` | `mount` / `verify_app`; one plane per endpoint and per resource class; PUBLIC needs a reason; `DEFAULT_PROBE_PATHS` for probes. **No per-route method pin.** |
| Identity | `identity/` | JWKS verification of a JWT. No DPoP. |

**Consequence for option B:** if USER carried several methods, `_primary_for` would require an authenticator for
every one of them on every USER route. Without a per-route pin, any of them could open any USER route.

---

## 5. What auth actually accepts

### 5.1 Every route on `main` (`app/http.py`), with the hooks that gate it

| Route | Gate (`app/routes/*`, `app/hooks/*`) |
|---|---|
| `GET /_info` | none — health probe |
| `GET /.well-known/jwks.json` | rate limit only |
| `GET /links` | none — the gate's HTML shell |
| `GET /test/integrity-token` | none; mounted only when a test secret is configured |
| `POST /attest` | none in a hook — body evidence checked in the responder |
| `POST /clients:register` | `X-Software-Statement`, checked in the responder |
| `POST /clients/{ref}/keys:bind` | `validate_dpop(allow_expired_key=True)`, then a **scheme branch**: `DPoP` (proof only) or `Bearer` (key-rotation token) |
| `POST /clients/{ref}/reattest` | `X-Software-Statement`, then a **runtime branch**: `Authorization` present → `validate_authenticated(allow_expired_key=True)`; absent → dead-state recovery |
| `POST /authentication` | `validate_dpop()` |
| `POST /authentication/otp:generate`, `/authentication/otp:validate` | `validate_dpop()` + `validate_client_session` |
| `POST /users:register` | `validate_dpop()` + `validate_client_session` |
| `POST /token:create` | `validate_dpop()` + `validate_client_session` |
| `POST /token:refresh` | `validate_dpop()`; the refresh token is in the body |
| `GET /links/context`, `POST /links/phone`, `POST /links/otp` | `validate_auth_link_gate` |
| `POST /mpin/forgot:begin`, `/mpin/forgot/{ref}:resend`, `:verify`, `:complete` | `validate_recovery_carrier` (dual credential) |
| `POST /mfa:generate`, `/mfa/{ref}:validate` | `validate_authenticated()` |
| `POST /mpin/reset:begin`, `:complete` | `validate_authenticated()` |
| `POST /users/{ref}/keys:bind`, `/users/{ref}/sessions:revoke` | `validate_authenticated()` |
| `GET /sessions/{ref}`; `POST /sessions/{ref}:revoke`, `/challenge:invoke`, `/challenge:authenticate` | `validate_authenticated()` |
| `POST /devices/binding:begin`; `GET /devices/binding/{ref}`; `POST /devices/binding/{ref}/otp:generate`, `:end`, `:cancel`; `POST /devices/binding:downgrade` | `validate_authenticated()` |
| `GET /internal/forward-auth` | `require_service_scope("forward-auth:decide")` |
| `GET /internal/revocations/sessions`, `/internal/revocations/user-epochs` | `revocations.sessions:read`, `revocations.user_epochs:read` |
| `GET /internal/clients/rotations` | `clients.rotations:read` |
| `POST /auth/links`, `/auth/links/{ref}:revoke` | `auth_links:generate`, `auth_links:revoke` |
| `POST /internal/mfa/{ref}:authorize` | `mfa:authorize` |
| `GET /internal/sessions/{ref}/trust-context` | `trust:read` |
| `POST /internal/sessions/{ref}/operations/{op}:verify` | `step_up:verify` |
| `POST /internal/onboarding:complete` | `onboarding:complete` |
| `GET /internal/users/{ref}` | `users:read` — on `UserRoute`, the class that also serves `/users:register` |

There are 11 service-plane routes. Open PRs add two routes:
- `POST /devices/threats:report` (#185): DPoP proof only, via `validate_dpop()`.
- `GET /internal/revocations/tokens` (#214): service plane, `revocations.tokens:read`.

### 5.2 Each credential, from the code and auth's ADRs

| Credential | Carrier | Check | Binding | Single use | Source |
|---|---|---|---|---|---|
| **Access token** | `Authorization: DPoP <jwt>` | JWT signature; claims `iss aud sub jti iat exp sid scope cnf.jkt`; then the session row (state `ENABLED`) | DPoP, **mode chosen by the session** (ADR-091): web without a device → self-signed, thumbprint = `cnf.jkt` = the session's; otherwise the key must resolve to a registered client, plus key age | no; #214 adds a per-`jti` denylist | `services/token.py:159-167`, `services/access_decision.py:58-150` |
| **DPoP proof** (general) | `DPoP` header | RFC 9449: signature, `htm`, `htu` (normalized, ADR-116), `iat`; `ath` only when the scheme is `DPoP` (ADR-028/050); nonce and `jti` on writes only (ADR-067) | — | nonce single-use, one per thumbprint, 300 s; **check and delete are two separate steps, not atomic** | `modules/dpop/validator.py`, `nonce.py:32-54` |
| **Client key (DPoP alone)** | `DPoP` | as above, plus the key must resolve to an **enabled registered client**; key age ≤ 90 days unless `allow_expired_key` (rotation routes, ADR-034/055); #142 adds an attestation-freshness gate (`E3307`, skipped with `allow_expired_key`) | itself | — | `hooks/dpop.py`, `validator.py` |
| **Client session** (pre-login) | `Authorization: Bearer <opaque>` | `token_urlsafe(32)`; SHA-256 lookup in Postgres `client_sessions` behind a Redis snapshot; 600 s | DPoP with a client key: the proof's `client_id` must equal the session's — **skipped if no proof is on the request** | multi-use until closed at token issuance | `hooks/client_session.py:27-48`, `modules/client_session/services/flows.py:31,150,175-188` |
| **Refresh token** | JSON **body** of `/token:refresh` | `token_urlsafe(32)`, hashed on the session row; 90 days; rotated by compare-and-swap (ADR-110); none for web sessions (ADR-090) | DPoP with a client key, key-age checked | rotated on use | `session/services/tokens.py:84`, `routes/token.py:80-89` |
| **Auth-link token** | `Authorization: Link <opaque>` | `token_urlsafe(32)`; SHA-256 hex lookup; usable while `CREATED`/`VERIFIED`, 168 h (ADR-088/104) | **self-signed** DPoP; the device pin is set at `/phone` and required at `/otp` (600 s, ADR-089) | multi-use | `hooks/auth_link_gate.py:84-150` |
| **Software statement** | `X-Software-Statement` | ES256 JWT minted by auth, 300 s; carries `jti`, the public key and its thumbprint, the verdict; #203 adds `device_id` and `platform` | the client key it registers (by thumbprint) | **yes** — `consumed_ssa` insert on `jti`, `ON CONFLICT DO NOTHING`, first step of the handler's transaction (ADR-014/056) | `modules/attestation/services/ssa.py:66-97`, `consumed_ssa.py`, `services/client.py:97` |
| **Key-rotation token** | `Authorization: Bearer <opaque>` on `keys:bind` | `token_urlsafe(32)`, hashed, 300 s, bound to `client_id`; issuing one expires earlier ones | DPoP proof present (no `ath`) | **yes** — consumed under `FOR UPDATE` in the service's transaction | `modules/client/services/key_rotation_token.py`, `routes/client.py:138-150` |
| **Attestation evidence** | JSON body of `/attest` | the platform provider (Play Integrity): signature, `timestampMillis` ≤ 300 s | the nonce is the client-key thumbprint (`routes/attestation.py:100`); #203 makes it `sha256(thumbprint ‖ device_id)`. **Neither is issued by the server.** | **no** — nothing records the token. It can be replayed within 300 s, minting a new software statement each time. | `routes/attestation.py:60-140`; #203 `providers/play_integrity.py:147-167` |
| **mTLS CN** | TLS | allow-list lookup | — | — | `hooks/svcplane.py` (via `falcon-svcplane`) |

### 5.3 Why auth accepts two credentials on three routes

| Route | Credential A → effect | Credential B → effect | Stated rationale |
|---|---|---|---|
| `/mpin/forgot/*` | access token → the acting session survives | pre-login client session → fresh tokens issued at `:complete` | ADR-099 §2: forgot-MPIN must work before login *and* for an authenticated session (for example after a biometric login). A step-up challenge can't serve, because it requires a session. |
| `/clients/{ref}/reattest` | access token → extends device trust; `ClientReattestResponse` | software statement only (no DPoP) → `KeyRotationTokenIssueResponse` | ADR-034's two ways of transferring trust (holding the current key vs the platform vouching). **No ADR discusses the runtime branch itself.** |
| `/clients/{ref}/keys:bind` | `DPoP` scheme, proof only (the token is not validated, by ADR-034: rotation is independent of session state) → rotate | `Bearer` key-rotation token (single-use) → recovery rotation | ADR-034 Layer-0 rotation; "Decision B" in the route |

**In all three, the credential type already changes the effect or the response.** The issue lists only the first
two; `keys:bind` is a third.

---

## 6. Analysis

### 6.1 Four independent parts

Every auth credential decomposes into the same four parts:

| Part | Question | Values in auth |
|---|---|---|
| **Carrier** | where is it read? | `Authorization: DPoP` · `Authorization: Bearer` · `Authorization: Link` · `X-Software-Statement` · the `DPoP` header alone · the TLS certificate · the body |
| **Check** | how is it verified? | signature (**JWT**) · store lookup (**REFERENCE**) · peer certificate (**MTLS**) · key proof alone (**PROOF**) · external provider (attestation) |
| **Binding** | must the caller prove they hold a key? | none · DPoP **client** (key → registered client) · DPoP **token** (`cnf.jkt` + the session's thumbprint) · DPoP **self-signed** |
| **Single use** | is it spent on use? | reusable · consumed in the handler's own transaction |

Auth's hooks are these combinations written out by hand:

| Hook | Carrier | Check | Binding |
|---|---|---|---|
| `validate_authenticated` | DPoP scheme | JWT | token |
| `validate_client_session` | Bearer | REFERENCE | client |
| `validate_auth_link_gate` | Link | REFERENCE | self-signed |
| `validate_dpop` | DPoP header | PROOF | client |

### 6.2 Why the hand-written form fails

- **A binding that lives in a separate hook can be skipped.** `validate_client_session` checks the client only *if*
  a proof is on the request (`client_session.py:42`); nothing but hook order makes it run.
- **The DPoP nonce is single-use, so a proof must be checked exactly once, in a mode chosen up front** (ADR-050 §4,
  ADR-091). Two separate hooks cannot guarantee that. `validate_authenticated` was merged from two hooks for exactly
  this reason.
- **A runtime branch inside a route is two endpoints behind one path.** It's invisible to a registry keyed on method +
  path, and C-031's reasoning applies: a route that accepts two credentials lets the caller pick the weaker.

### 6.3 Terms, settled

- **Bearer:** possession alone authorizes (RFC 6750). It describes how a token is *used*, not its *format*.
- **Opaque / reference token:** a random handle checked by store lookup, as opposed to a self-contained JWT checked by
  signature. "Opaque" describes format only, and one-shot tokens are opaque too.
- **Sender-constrained:** bound to a key; each request carries a DPoP proof signed by that key (RFC 9449). The
  scheme becomes `DPoP`.

In auth:
- Row 6 is sender-constrained.
- Row 5 is opaque and sent with `Bearer`, but auth also requires a client-key proof — sender-constrained in practice.

**So methods are named by how they are checked**: `REFERENCE_TOKEN`, not "bearer" or "opaque".

### 6.4 Attestation is not a one-shot token as it stands

A one-shot token, in C-031's words, is *"a one-shot token the service minted … consumed single-use"*. The attestation
token fails on every count:

- the platform mints it, not auth;
- its nonce is derived by the client, not issued by the server;
- auth records no consumption, so it can be replayed for 300 s.

C-031 also warns that *"authenticity is never established from a value the provider supplies"*. And no caller
identity exists before `/attest`; the token is input being judged, not a credential.

The software statement and the key-rotation token **do** fit: auth mints each, and each is consumed once in the
handler's transaction.

---

## 7. The issue's options, evaluated

| | Verdict | Reason |
|---|---|---|
| **A** — grow C-038's method set | **Partly right, at the wrong grain** | Growing the set is needed, but naming carriers (attestation evidence, software statement, client-key DPoP, link token) grows it by four for one service. Naming checks grows it by two (`REFERENCE`, `PROOF`), and those two are enough because carrier and binding become configuration. |
| **B** — plane = caller kind, registry only | **Not recommended** | C-052 moved caller kind to the actor type and calls a plane an authentication method. "Several methods on USER" reopens Q86. It leaves the wrong-plane 404 unmet, and auth's hooks — where its defects live — stay hand-written. |
| **C** — bootstrap routes PUBLIC | **Rejected** | It would be false for every route except `/attest` (see §9) and would advertise `/token:create` as needing no credential. |

---

## 8. Recommendation: the design

### 8.1 The pieces

```python
Selector(header="Authorization", scheme="Bearer")      # scheme=None for e.g. X-Software-Statement

JWTAuthenticator(verifier, selector, binding=...)          # binding is REQUIRED, see 8.3
ReferenceAuthenticator(lookup, selector, binding=..., single_use=False, timeout=...)
ProofAuthenticator(DPoPBinding(mode="client"))             # the DPoP proof is the whole credential
MTLSAuthenticator(verifier)                                # today's mtls_authenticator

DPoPBinding(mode="client" | "token" | "self_signed",
            nonces=<host store>, resolve_client=<host lookup>)
PROVEN_AT_PERIMETER                                        # marker: the gateway checked the proof (RUL-048)
```

These map onto the earlier direction from the discussion:
- `BearerJWT` → `JWTAuthenticator`;
- `BearerReference` → `ReferenceAuthenticator`;
- "DPoP as its own authenticator" → `ProofAuthenticator`;
- DPoP alongside a token → a **binding**, not a second authenticator.

### 8.2 The lookup contract (`ReferenceAuthenticator`)

| Outcome | Meaning | Answer |
|---|---|---|
| returns a principal | the token is known and live | continue |
| raises `Unauthenticated` | unknown, expired, revoked | **401** |
| raises `AuthzUnavailable` | the store or the HTTP source couldn't be reached | **503** |

Conditions:
- The lookup is the host's. It may make a database call, or an HTTP call to a source outside the service.
- It runs only when the selector matches, and under a timeout.
- **The package never caches its result.** Instant revocation is the only advantage a reference token has over a JWT.
- Inside the platform, an HTTP lookup against auth from another service would put auth on that service's hot path,
  which C-016 forbids. So the HTTP path is for sources outside the platform (CAND-45, not designed).

### 8.3 Binding is part of the authenticator, and must be declared

**The binding runs inside the token authenticator.** It runs once, in the mode the verified credential selects. For
the access token, the session decides between web self-signed and the app's client key (ADR-091). A token
authenticator and a separate DPoP authenticator would let the middleware accept the token at the first valid one and
never check the proof.

**The binding must be declared**, and that is a revision since auth's P4 decision (ppi-backend-auth#246).

- **P4:** forward-auth is the DPoP enforcement point. Services that consume tokens verify the JWT only, configured
  with `scheme="DPoP"`.
- **The earlier rule** ("a `DPoP`-scheme token without a binding refuses startup") would break every one of them.
- **Revised:**
  - a `DPoP`-scheme selector requires either a `DPoPBinding` (auth itself) or `PROVEN_AT_PERIMETER` (consumers);
  - omitting both refuses startup.

The downgrade stays visible in code without blocking the estate's model. P4's accepted residual — a request that
bypasses the gateway is accepted on the token alone — is unchanged; its mitigation is network position.

**What the package does for DPoP:**
- RFC 9449 checks: `typ`, `alg`, the embedded key, signature, `htm`, `htu` normalized as in ADR-116, the `iat` window;
- `ath` exactly when the scheme is `DPoP`;
- issuing the next nonce on writes even when the request fails.

**What stays with the host:**
- the nonce store;
- looking up the client by thumbprint, including key age and #142's attestation-freshness check;
- the link gate's device pin.

P4's possible later ask — a stateless proof check for consumers — is `DPoPBinding` without a nonce store.

### 8.4 Single use

- `single_use=True` **checks** the token in the middleware but **does not spend it**.
- The principal carries a handle, and the handler consumes it inside its own transaction, after idempotency (C-030).
- Spending it in middleware would burn it on a failed change or on a retry.
- Auth already does this for the software statement (`services/client.py:97`) and the key-rotation token.

### 8.5 Registration rules

1. **Each authenticator belongs to exactly one plane.** Its method must be allowed on that plane.
2. **Selectors must not overlap across planes**, or startup is refused. Within one plane they may:
   - **why within is safe:** routes pin one authenticator, so on any route only that one runs as the primary, and a
     credential of another kind simply fails it (401). That's correct: the endpoint's credential is wrong.
     `client_session` and `key_rotation` both read `Authorization: Bearer`, and the proof variants share the `DPoP`
     header (§8.7).
   - **why across matters:** the wrong-plane search (C-038 step 3) looks for a credential of *another* plane. There,
     a shared selector would turn a valid credential of one plane into an *invalid* one of the other.
   - (Amended 2026-10-01. The first draft said "across the middleware", which the instance table breaks twice.)
3. **Each route names one authenticator** (`mount(..., credential="client_session")`). That is the default when its
   plane has only one. A plane with several authenticators and a route that names none is refused at startup — C-031's
   per-source rule (the Q86 reading) applied to routes.
4. **The wrong-plane 404 looks up the plane by authenticator, not by method.** So `ONE_SHOT` can serve CALLBACK (a token
   in a callback URL) and USER (the software statement) without breaking `_invert`.
   - A valid credential for **another plane** → 404, as now.
   - A valid credential for **another route on the same plane** (an access token sent to a client-session route) →
     **401**: the endpoint's own credential is absent, and nothing about the plane is revealed.
5. **`REFERENCE` and `PROOF` on USER only with `identity_provider=True`** on the registry. That puts RUL-048 into code:
   every other service's USER plane stays JWT only.
6. **`verify()`** (`5dd61d6`) extends to check each route's pinned authenticator at startup, not only plane coverage.

### 8.6 One credential per route

**Rule:** one credential authenticates the route; any other token is **payload** the handler exchanges. Under this
rule:
- the refresh token in the body of `/token:refresh` is payload;
- the software statement on an authenticated `/reattest` is payload.

**The three dual-credential routes split** (path names are illustrative; auth chooses):

| Today | After |
|---|---|
| `/mpin/forgot/*` | a pre-login set (client session) and a logged-in set (access token), e.g. `/mpin/forgot/*` and `/sessions/{ref}/mpin/forgot/*` |
| `/clients/{ref}/reattest` | `…/reattest` (access token; software statement as payload) and a dead-state recovery endpoint (software statement as the credential) |
| `/clients/{ref}/keys:bind` | `…/keys:bind` (client-key proof) and a recovery rotation (key-rotation token) |

### 8.7 Instances: one per configured credential

An authenticator **instance** is one configured credential: carrier + check + binding mode + options (single use,
expired key allowed). Auth would configure nine:

| Instance | Piece | Plane | Carrier | Binding | Routes |
|---|---|---|---|---|---|
| `access_token` | `JWTAuthenticator` | USER | `Authorization: DPoP` | `token` (the session picks web self-signed vs app client, ADR-091) | logged-in routes |
| `access_token_rotation` | same, `allow_expired_key=True` | USER | `Authorization: DPoP` | `token` | authenticated reattest |
| `client_session` | `ReferenceAuthenticator` | USER | `Authorization: Bearer` | `client` | otp, `token:create`, `users:register`, pre-login forgot-MPIN |
| `key_rotation` | `ReferenceAuthenticator`, `single_use=True` | USER | `Authorization: Bearer` | `client`, expired key allowed | recovery key rotation |
| `link` | `ReferenceAuthenticator` | USER | `Authorization: Link` | `self_signed` | `/links/*` |
| `client_proof` | `ProofAuthenticator` | USER | `DPoP` header only | `client` | `/authentication`, `/token:refresh`, `threats:report` |
| `client_proof_rotation` | same, `allow_expired_key=True` | USER | `DPoP` header only | `client` | `keys:bind` |
| `software_statement` | JWT check, `single_use=True` | USER | `X-Software-Statement` | — | register, dead-state reattest |
| `mtls` | `MTLSAuthenticator` | SERVICE | TLS certificate | — | service routes |

- **The heavy parts are shared, not repeated.** One `DPoPVerifier` (nonce store, client lookup, `htu`
  reconstruction) serves every binding; one token verifier serves every JWT check. An instance is thin configuration
  over them.
- **A variant such as `allow_expired_key` is its own instance, not a per-request flag.** A route pins one instance,
  and that is where "this route accepts a proof from an expired key" belongs. Today auth writes it inside each
  route's hook.

---

## 9. Recommendation: auth's routes under the design

| Routes | Plane · authenticator | Binding | Single use |
|---|---|---|---|
| `/_info` | outside the plane system (RUL-033; `DEFAULT_PROBE_PATHS`) | — | — |
| `/.well-known/jwks.json`, `GET /links` | PUBLIC, with a stated reason | — | — |
| `/attest` | **PUBLIC, with a stated reason**, until auth issues a server challenge (§6.4) | — | — |
| `/clients:register`, dead-state reattest | USER · `ONE_SHOT` (`X-Software-Statement`, JWT check) | — | yes, by `jti` |
| recovery key rotation | USER · `ONE_SHOT` (`Bearer`, REFERENCE check) | DPoP client, expired key allowed | yes |
| `/authentication`, `keys:bind`, `/token:refresh`, `/devices/threats:report` (#185) | USER · `PROOF` | DPoP client (expired key allowed on `keys:bind`) | — |
| `/authentication/otp:*`, `/token:create`, `/users:register`, pre-login forgot-MPIN | USER · `REFERENCE` (`Bearer` client session) | DPoP client | no (closed when tokens are issued) |
| `/links/{context,phone,otp}` | USER · `REFERENCE` (`Link`) | DPoP self-signed; the pin stays with the host | no |
| `/sessions/*`, `/mfa:*`, `/mpin/reset:*`, `/devices/*`, `/users/{ref}/*`, logged-in forgot-MPIN, authenticated reattest | USER · `JWT` (`Authorization: DPoP`) | DPoP token; the session decides the mode | — |
| the 11 service-plane routes, plus `/internal/revocations/tokens` (#214) | SERVICE · `MTLS` | — | — |

Two related C-006 items:
- `UserRoute` must split: `/users:register` and `/internal/users/{ref}` are on different planes.
- C-051 (ratified `v24`) puts service routes under `/v1/svc/…`. That rides auth's G5 move to `/v1` paths.

---

## 10. Recommendation: the path

| Step | What | Needs a ruling? | Effect on existing consumers |
|---|---|---|---|
| **1** | `Selector`; `JWTAuthenticator` / `ReferenceAuthenticator`; the three-outcome lookup; the declared binding with `PROVEN_AT_PERIMETER`; startup refusal on shared selectors. `jwt_authenticator` stays as an alias. | no | none — the alias keeps today's behaviour; a `DPoP` scheme without a declared binding warns for one release, then refuses |
| **2** | Each authenticator on one plane; per-route pin in `mount`; wrong-plane lookup by authenticator; `verify()` covers pins; the middleware takes the same `exempt_paths` as `verify_app`, so probes pass (§17.1) | no | none while a plane has one authenticator; the probe exemption fixes a failure that any service mounting the middleware would hit today |
| **3** | One request to the platform (§11) | **yes** | — |
| **4** | `ProofAuthenticator`, `DPoPBinding`, `ONE_SHOT` on USER, the `identity_provider` fence | after step 3 | none — opt-in, auth only |
| **5** | Auth adopts the middleware, splits the three routes, adds the attestation challenge, fixes the defects in §12 | after step 4 | — |

---

## 11. Platform asks

To raise on ppi-platform-conventions as **one** proposal, against C-038 / C-006:

1. **Two checks join the closed set, for the identity provider's USER plane only:** `REFERENCE_TOKEN` (a store lookup,
   reusable until expiry) and `DPOP_PROOF` (a key proof alone). RUL-048 already makes auth the DPoP exception; this
   names what it uses.
2. **`ONE_SHOT_TOKEN` is allowed on USER** for credentials auth mints and consumes (software statement, key-rotation
   token). The wrong-plane 404 looks up the plane by authenticator, so each method no longer has to sit under one
   plane.
3. **A route accepts exactly one credential.** C-031's per-source rule is applied to routes; auth splits its three
   dual-credential routes.
4. **Side questions:**
   - Does C-030's body binding apply to a bootstrap credential tied to a key, like the software statement?
   - Which C-052 actor type does a pre-user app install have? None of `CUSTOMER` / `OPERATOR` / `SERVICE` / `SYSTEM` fits.
5. **Optional:** promote CAND-44 (client attestation) far enough to state that a client has its own identity and that
   `/attest` is PUBLIC until a server challenge exists.

---

## 12. Auth-side actions, and defects found

**Actions under this design:**
- adopt the middleware;
- split `/mpin/forgot/*`, `/reattest` and `keys:bind`;
- split `UserRoute`;
- issue and consume a server challenge at `/attest`.

**Defects found in auth while reading the code (not yet reported to auth):**

| # | Defect | Where | Consequence |
|---|---|---|---|
| D1 | The client-session binding is skipped when no DPoP proof is on the request | `app/hooks/client_session.py:42-48` | the binding depends on hook order; the hook also never checks that the scheme is `Bearer` |
| D2 | `consume_client_session` has no state condition and no row-count check | `modules/client_session/services/flows.py:175-188` | contradicts ADR-033's atomic consume |
| D3 | ADR-008's "one active client session per phone" unique index doesn't exist | `client_session` model and migration (non-unique index only) | the invariant is unenforced |
| D4 | The DPoP nonce is checked and deleted in two separate, non-atomic steps | `modules/dpop/nonce.py:32-54` | a race can spend one nonce twice; ADR-010's tolerant window is not built either |
| D5 | The attestation token can be replayed within 300 s, minting a new software statement each time | `routes/attestation.py`; #203 does not change it | the docs call it "one-shot per platform policy" (`attest.md:178-180`), but the server doesn't enforce that |
| D6 | ADR-050 puts the `ath` check before `jti`; the code checks it last, after the nonce is spent | `validator.py` step 8 | a request failing `ath` still burns its nonce |
| D7 | Forward-auth rebuilds the request URL itself and ignores `X-Forwarded-Prefix` | `routes/forward_auth.py:15-38` vs `hooks/forwarded.py` | two `htu` reconstructions that can disagree |

D1–D4 and D6 disappear structurally once the binding runs inside one authenticator and nonces go through one store
contract. D5 needs the attestation challenge.

⚠ D6 and D7 come from a research pass over auth's ADRs and code and have not been re-checked line by line. Confirm
them before reporting them to auth. D1–D5 were read directly.

---

## 13. Effect on other consumers

| Consumer | Change |
|---|---|
| Services consuming tokens (persona, orders, …) | none required. On step 1 they switch to `JWTAuthenticator(selector=Selector("Authorization", "DPoP"), binding=PROVEN_AT_PERIMETER)`, which states P4 in code. Until then the alias keeps working, with a deprecation warning for the undeclared binding. |
| Services with one authenticator per plane | none from step 2: the pin defaults. |
| Services other than auth | can never register `REFERENCE` or `PROOF` on USER (the `identity_provider` fence). |
| Gateway | unchanged: still the DPoP enforcement point for consumers (P4). |

---

## 14. Positions taken in the discussion

| Topic | Position | Status |
|---|---|---|
| DPoP | its own authenticator (`ProofAuthenticator`) where it is the whole credential; a **binding** inside the token authenticator otherwise | agreed |
| Token authenticators | `BearerJWT` / `BearerReference` with a header + prefix selector; reference takes a host lookup (database or HTTP) | agreed; renamed by check, binding made explicit |
| Naming | by check, not by "bearer" or "opaque": `REFERENCE_TOKEN` | agreed |
| Attestation + software statement as ONE_SHOT | the software statement fits; `/attest` does not until a server challenge exists | software statement agreed; attestation pushed back |
| Selectors | must not overlap across the middleware | agreed |
| Lookup | three outcomes; no caching in the package | agreed |
| Single use | checked in middleware, consumed in the handler's transaction | agreed |
| Dual-credential routes | split | recommended |
| Option B (plane = caller kind) | not recommended, given C-052 | recommended |
| DPoP scheme without a binding | **revised**: must be declared (`DPoPBinding` or `PROVEN_AT_PERIMETER`), not refused outright — follows auth's P4 | revised 2026-10-01 |

---

## 15. Open questions, and what was not verified

**Open questions:**
- Which actor type (C-052) a pre-user app install has.
- Whether C-030's body binding applies to the software statement.
- Path names for the split routes (auth's choice).
- Whether CAND-44 should be promoted alongside this proposal.

**Not verified:**
- The Go gateway validator (`gwvalidator`) and the gateway's epoch check.
- The iOS attestation provider.
- Whether Falcon runs stacked `before` hooks top-down. No interpreter with Falcon was available when this was
  checked; it bears on D1.
- The implementation of the Play Integrity provider on `main`. The freshness check was read on #203's head.
- How the stacked PRs interact when merged (for example, #186 reverts #203's nonce formula on its own base).
- Whether ADR-035's `credential_setup_token` is live.

---

## 16. Glossary

| Term | Meaning here |
|---|---|
| plane | the authentication method an endpoint is mounted for: `USER` · `SERVICE` · `CALLBACK` · `PUBLIC` (C-038, C-052) |
| actor type | who the caller is, declared per route inside a plane: `CUSTOMER` · `OPERATOR` · `SERVICE` · `SYSTEM` (C-052) |
| method / check | how a credential is verified: `JWT` · `MTLS` · `HMAC` · `ONE_SHOT_TOKEN`; proposed: `REFERENCE_TOKEN`, `DPOP_PROOF` |
| carrier / selector | where a credential is read: header name + scheme |
| binding | proof of possession, DPoP, in mode `client` · `token` · `self_signed`, or `PROVEN_AT_PERIMETER` |
| bearer | possession alone authorizes (RFC 6750) |
| reference (opaque) token | a random handle checked by store lookup |
| sender-constrained | bound to a key and proven per request (RFC 9449) |
| software statement (SSA) | the signed JWT auth mints at `/attest`, spent once at registration |
| client session | the pre-login, multi-use reference token bound to a registered client key |
| wrong-plane 404 | C-038 step 4: a valid credential for another plane answers as not-found, logged and flagged |

---

## 17. Appendix: the HTTP root in its final shape

What auth's `app/http.py` looks like once steps 1–5 (§10) are done. **Illustrative:**
- the names marked *new* are this design's, not shipped API;
- the host functions (`lookup_client_session` and so on) are auth's own code, moved out of today's hooks;
- paths assume auth's G5 move to `/v1` (C-039) and C-051's `svc` prefix;
- the split route names are placeholders auth chooses.

### 17.1 Auth (`ppi-backend-auth/app/http.py`)

```python
import falcon
import falcon.asgi

from falcon_auth.planes import PUBLIC, SERVICE, USER
from falcon_auth.adapters import (
    PlaneAuthenticationMiddleware, PlaneRegistry, mount, verify_app, register_error_handlers,
    # new in steps 1 and 4
    Selector, JWTAuthenticator, ReferenceAuthenticator, ProofAuthenticator, MTLSAuthenticator,
)
from falcon_auth.identity import DPoPVerifier                 # new in step 4
from falcon_auth.eastwest import Verifier, build_allow_list
from falcon_auth.entitlement import build_enforcer, verify_policy

from app.config import app_ctx, settings
from app.errors import NotFoundError
from app.authn import (                                       # auth's own lookups, lifted out of today's hooks
    load_access_session,        # claims -> session principal; exposes the bound thumbprint and the proof mode (ADR-091)
    lookup_client_session,      # token -> snapshot | raises Unauthenticated (unknown/expired) | AuthzUnavailable
    peek_key_rotation_token,    # token -> handle; checked here, CONSUMED in the handler's transaction
    lookup_link,                # token -> link | raises Unauthenticated(E3901/E3909/E3910/E3911)
    verify_software_statement,  # SSA JWT -> claims incl. jti; spent in the handler's transaction
    resolve_client,             # DPoP thumbprint -> enabled Client; key age and #142 freshness live here
    gate_pin,                   # the link gate's phone -> otp device pin (ADR-089)
)
from app.authz import SVC_REGISTRY, PEERS, GRANTS            # C-056 (proposed): peer -> entitlement rows, in code
from app.routes import ...                                    # resource classes, one plane each (C-006)


# ── shared verifiers: built once, used by every authenticator that needs them ─────────────

dpop = DPoPVerifier(                                          # one nonce store, one client lookup, one htu
    nonces=app_ctx.dpop_nonces,                               # atomic check-and-spend (fixes D4)
    resolve_client=resolve_client,
    trust_forwarded_headers=settings.http.trust_forwarded_headers,   # ADR-116; forward-auth reuses it (D7)
)
enforcer = build_enforcer(SVC_REGISTRY, peers=PEERS)          # C-056 (proposed)
verify_policy(SVC_REGISTRY, grant_register=GRANTS, peers=PEERS)
mtls = Verifier(build_allow_list(settings.svcplane.allow_list, peers=enforcer.peers))


# ── the credentials auth accepts: one instance each (§8.7) ────────────────────────────────

BEARER = Selector("Authorization", "Bearer")
DPOP_SCHEME = Selector("Authorization", "DPoP")

authenticators = {
    # logged in: DPoP-bound access token; the session picks web self-signed vs app client (ADR-091)
    "access_token": JWTAuthenticator(
        app_ctx.token_verifier, DPOP_SCHEME, plane=USER,
        principal=load_access_session, binding=dpop.token()),
    "access_token_rotation": JWTAuthenticator(
        app_ctx.token_verifier, DPOP_SCHEME, plane=USER,
        principal=load_access_session, binding=dpop.token(allow_expired_key=True)),

    # pre-login: reference tokens, each bound to the registered client key
    "client_session": ReferenceAuthenticator(
        lookup_client_session, BEARER, plane=USER,
        binding=dpop.client()),                               # inside the authenticator: cannot be skipped (D1)
    "key_rotation": ReferenceAuthenticator(
        peek_key_rotation_token, BEARER, plane=USER,
        binding=dpop.client(allow_expired_key=True), single_use=True),
    "link": ReferenceAuthenticator(
        lookup_link, Selector("Authorization", "Link"), plane=USER,
        binding=dpop.self_signed(pin=gate_pin)),

    # the client key alone
    "client_proof": ProofAuthenticator(dpop.client(), plane=USER),
    "client_proof_rotation": ProofAuthenticator(dpop.client(allow_expired_key=True), plane=USER),

    # minted by auth, spent once
    "software_statement": JWTAuthenticator(
        verify_software_statement, Selector("X-Software-Statement", None), plane=USER,
        binding=None, single_use=True),                       # not a DPoP scheme, so no binding is required

    # service plane
    "mtls": MTLSAuthenticator(mtls, plane=SERVICE),
}


# ── registry, middleware, app ─────────────────────────────────────────────────────────────

PROBES = frozenset({"/_info"})                                # outside the plane system (RUL-033)

registry = PlaneRegistry(
    identity_provider=True,                                   # new: REFERENCE / PROOF / ONE_SHOT on USER (RUL-048)
    allow_dev_routes=settings.testing.enabled,
)
authn = PlaneAuthenticationMiddleware(
    registry,
    authenticators=authenticators,
    not_found_error=lambda: NotFoundError(),                  # the host's own not-found body (C-038 step 4)
    on_plane_mismatch=app_ctx.security_events.plane_mismatch,
    exempt_paths=PROBES,                                      # new: see the note below the listing
)

app = falcon.asgi.App(middleware=[ClientIPMiddleware(), LoggingMiddleware(), authn])
register_error_handlers(app)
# Gone: APIVersionPresenceMiddleware (C-039, G5) and AppVersionMiddleware (#186).

app.add_route("/_info", HealthCheck())                        # a probe, deliberately unregistered


# ── PUBLIC: each states its reason (C-006, RUL-035) ───────────────────────────────────────

mount(registry, app, "/.well-known/jwks.json", jwks_route, plane=PUBLIC,
      reason="RFC 8615 key discovery; unversioned pending a C-039 ruling")
mount(registry, app, "/v1/links", gate_shell_route, plane=PUBLIC,
      reason="the auth-link gate's HTML shell; its API calls carry the link token")
mount(registry, app, "/v1/attest", attestation_route, suffix="attest", plane=PUBLIC,
      reason="attestation evidence is judged, not a credential; PUBLIC until auth issues a server challenge (§6.4)")
mount(registry, app, "/v1/test/integrity-token", testing_route, suffix="integrity_token",
      plane=PUBLIC, reason="mock integrity-token minter", dev_only=True)


# ── USER, minted by auth and spent once ───────────────────────────────────────────────────

mount(registry, app, "/v1/clients:register", client_registration_route, suffix="register",
      plane=USER, credential="software_statement")
mount(registry, app, "/v1/clients/{client_ref}/reattest:recover", client_recovery_route, suffix="reattest",
      plane=USER, credential="software_statement")                       # split from /reattest
mount(registry, app, "/v1/clients/{client_ref}/keys:recover", client_recovery_route, suffix="keys",
      plane=USER, credential="key_rotation")                            # split from keys:bind


# ── USER, the client key alone ────────────────────────────────────────────────────────────

mount(registry, app, "/v1/authentication", authentication_route,
      plane=USER, credential="client_proof")
mount(registry, app, "/v1/token:refresh", token_route, suffix="refresh",
      plane=USER, credential="client_proof")                            # the refresh token is body payload
mount(registry, app, "/v1/devices/threats:report", device_threats_route, suffix="report",
      plane=USER, credential="client_proof")                            # #185
mount(registry, app, "/v1/clients/{client_ref}/keys:bind", client_route, suffix="keys_bind",
      plane=USER, credential="client_proof_rotation")


# ── USER, the pre-login client session ────────────────────────────────────────────────────

for path, suffix in [("/v1/authentication/otp:generate", "otp_generate"),
                     ("/v1/authentication/otp:validate", "otp_validate")]:
    mount(registry, app, path, authentication_route, suffix=suffix,
          plane=USER, credential="client_session")
mount(registry, app, "/v1/token:create", token_route, suffix="create",
      plane=USER, credential="client_session")
mount(registry, app, "/v1/users:register", user_registration_route, suffix="register",
      plane=USER, credential="client_session")                          # UserRoute split (C-006)
for path, suffix in [("/v1/mpin/forgot:begin", "begin"),
                     ("/v1/mpin/forgot/{ref}:resend", "resend"),
                     ("/v1/mpin/forgot/{ref}:verify", "verify"),
                     ("/v1/mpin/forgot/{ref}:complete", "complete")]:
    mount(registry, app, path, mpin_recovery_route, suffix=suffix,
          plane=USER, credential="client_session")                      # pre-login half of the split


# ── USER, the auth-link gate ──────────────────────────────────────────────────────────────

for path, suffix in [("/v1/links/context", "context"),
                     ("/v1/links/phone", "phone"),
                     ("/v1/links/otp", "otp")]:
    mount(registry, app, path, auth_link_gate_route, suffix=suffix,
          plane=USER, credential="link")


# ── USER, logged in ───────────────────────────────────────────────────────────────────────

LOGGED_IN = [
    ("/v1/sessions/{session_ref}", session_route, None),
    ("/v1/sessions/{session_ref}:revoke", session_route, "revoke"),
    ("/v1/sessions/{session_ref}/challenge:invoke", session_route, "challenge_invoke"),
    ("/v1/sessions/{session_ref}/challenge:authenticate", session_route, "challenge_authenticate"),
    ("/v1/sessions/{session_ref}/mpin/forgot:begin", session_mpin_recovery_route, "begin"),  # logged-in half
    ("/v1/sessions/{session_ref}/mpin/forgot/{ref}:verify", session_mpin_recovery_route, "verify"),
    ("/v1/sessions/{session_ref}/mpin/forgot/{ref}:complete", session_mpin_recovery_route, "complete"),
    ("/v1/mfa:generate", mfa_route, "generate"),
    ("/v1/mfa/{mfa_ref}:validate", mfa_route, "validate"),
    ("/v1/mpin/reset:begin", mpin_reset_route, "begin"),
    ("/v1/mpin/reset:complete", mpin_reset_route, "complete"),
    ("/v1/users/{user_ref}/keys:bind", user_route, "keys_bind"),
    ("/v1/users/{user_ref}/sessions:revoke", user_route, "sessions_revoke"),
    ("/v1/devices/binding:begin", devices_route, "binding_begin"),
    ("/v1/devices/binding/{ref}", devices_route, "binding"),
    ("/v1/devices/binding/{ref}/otp:generate", devices_route, "binding_otp_generate"),
    ("/v1/devices/binding/{ref}:end", devices_route, "binding_end"),
    ("/v1/devices/binding/{ref}:cancel", devices_route, "binding_cancel"),
    ("/v1/devices/binding:downgrade", devices_route, "binding_downgrade"),
]
for path, resource, suffix in LOGGED_IN:
    mount(registry, app, path, resource, suffix=suffix, plane=USER, credential="access_token")
mount(registry, app, "/v1/clients/{client_ref}/reattest", client_route, suffix="reattest",
      plane=USER, credential="access_token_rotation")     # the software statement is body payload here


# ── SERVICE: mTLS; each responder declares its capability (C-055/C-056) ───────────────────

SVC = [
    ("/v1/svc/forward-auth", svc_forward_auth_route, None),
    ("/v1/svc/revocations/sessions", svc_revocations_route, "sessions"),
    ("/v1/svc/revocations/user-epochs", svc_revocations_route, "user_epochs"),
    ("/v1/svc/revocations/tokens", svc_revocations_route, "tokens"),                    # #214
    ("/v1/svc/clients/rotations", svc_client_rotations_route, None),
    ("/v1/svc/auth/links", svc_auth_links_route, "generate"),
    ("/v1/svc/auth/links/{link_ref}:revoke", svc_auth_links_route, "revoke"),
    ("/v1/svc/mfa/{mfa_ref}:authorize", svc_mfa_route, "authorize"),
    ("/v1/svc/sessions/{session_ref}/trust-context", svc_session_route, "trust_context"),
    ("/v1/svc/sessions/{session_ref}/operations/{operation_id}:verify", svc_session_route, "operation_verify"),
    ("/v1/svc/onboarding:complete", svc_onboarding_route, "complete"),
    ("/v1/svc/users/{user_ref}", svc_user_route, None),                                 # UserRoute split
]
for path, resource, suffix in SVC:
    mount(registry, app, path, resource, suffix=suffix, plane=SERVICE)   # one authenticator: the pin defaults


# ── refuse to start on any wiring gap ─────────────────────────────────────────────────────

verify_app(app, registry, exempt_paths=PROBES)    # every route registered (C-006)
authn.verify()                                    # every route's pinned authenticator exists and sits on its plane;
                                                  # no two planes share a selector (§8.5 rules 1-3, 6)
```

**What moved where.**

| Today | Final shape |
|---|---|
| a hook on every responder (`validate_authenticated`, `validate_dpop`, `validate_client_session`, `validate_auth_link_gate`, `validate_recovery_carrier`) | one `credential=` per mount; the middleware runs it |
| DPoP checked by whichever hook happens to run | checked once, inside the authenticator, in the mode the credential selects |
| runtime branches inside `/reattest`, `keys:bind`, `/mpin/forgot/*` | separate endpoints, each pinned to one credential |
| `require_service_scope` on service responders, checked against nothing | `require_service_capability(mtls, "trust:read", enforcer=enforcer)` on the responder, checked when the decorator runs (C-056) |
| `/internal/...` paths, unversioned | `/v1/svc/...` (C-039, C-051) |
| classes named by URL prefix (`InternalSessionRoute`) | classes named by plane (`svc_session_route`), and `UserRoute` split (C-006) |
| `X-API-Version` and app-version middleware | gone (C-039, #186) |

**What the handlers still do.** The middleware authenticates, and the responders keep only what is theirs:

```python
class ClientRegistrationRoute:
    async def on_post_register(self, req, resp):
        ssa = req.context.auth_principal                   # checked, not spent
        async with self.db.transaction() as tx:
            await ssa.consume(tx)                          # spent with the change, after idempotency (C-030)
            client = await self.clients.register(tx, ssa.claims)
        ...

class SvcSessionRoute:
    @falcon.before(require_service_capability(mtls, "trust:read", enforcer=enforcer))
    async def on_get_trust_context(self, req, resp, session_ref): ...
```

**New requirement found while writing this listing.** The middleware has no probe exemption today: an unregistered
`/_info` reaches `process_resource`, has no registry row, and raises `UnregisteredRoute`. `verify_app` already exempts
probe paths. The middleware needs the same `exempt_paths`, or every probe fails the day the middleware is mounted.

### 17.2 A consuming service (for example persona or orders)

Nothing about the identity provider leaks into a consumer. Its USER plane stays JWT only, and the DPoP binding is
declared as proven upstream (P4):

```python
from falcon_auth.adapters import (
    PlaneAuthenticationMiddleware, PlaneRegistry, mount, verify_app,
    Selector, JWTAuthenticator, MTLSAuthenticator, PROVEN_AT_PERIMETER,   # new in step 1
)

authenticators = {
    "access_token": JWTAuthenticator(
        jwks_verifier, Selector("Authorization", "DPoP"), plane=USER,
        binding=PROVEN_AT_PERIMETER),          # the gateway's forward-auth checked the proof (RUL-048, P4)
    "mtls": MTLSAuthenticator(mtls, plane=SERVICE),
}
registry = PlaneRegistry()                     # identity_provider=False: REFERENCE / PROOF refused on USER
authn = PlaneAuthenticationMiddleware(registry, authenticators=authenticators,
                                      not_found_error=OrderNotFound, exempt_paths=PROBES)
app = falcon.asgi.App(middleware=[authn])

mount(registry, app, "/v1/orders/{order_id}", orders_route, plane=USER)       # one USER authenticator: pin defaults
mount(registry, app, "/v1/svc/orders/{order_id}", svc_orders_route, plane=SERVICE)

verify_app(app, registry, exempt_paths=PROBES)
authn.verify()
```

Capability checks stay on the responders, as today: `require(enforcer, resolver, "orders:read")` on USER, and
`require_service_capability(mtls, "orders:read", enforcer=enforcer)` on SERVICE.

# What falcon-auth built and proposes behind the platform asks

> ✅ **Outcome, 2026-10-07:** all nine asks are closed.
>
> | Ruling | What it settled |
> |---|---|
> | C-055/C-056 (`v26`) | ratified |
> | RUL-134 | grants wire, no `grant_epoch` |
> | RUL-135 | probes and `/.well-known` stay unversioned |
> | C-058 (`v28`) | the body hash is **raw bytes**, not JCS |
> | C-060/C-061 (`v30`) | five planes; one credential per route; I/O-free search; conformance cases |
> | C-062 (`v31`) | client identity; attestation |
> | RUL-157/158/159 | falcon-auth pinned for resource services at `46b4012`; wrong-plane answer `PLAT0006` |
>
> §2–§5 below describe the constructs as they stood at the pin. The rebuild for #11 changes:
> - removes the permissive profile;
> - removes `credential=[...]` lists;
> - refuses `CLIENT`;
> - narrows the wrong-plane search.

> **Purpose:** context for the platform authority while ruling on juniofirstpay/platform-conventions
> #6–#14. Those issues state the **asks**. This document states the **constructs** behind them:
> what is already built (`main`, after PR #10), what is proposed, and which of them carry a rule
> the platform may want to own rather than leave as library detail.
>
> **Read against:** falcon-auth `main` @ `46b4012` (PR #10 merged) · `v0.2.0` (PR #9) ·
> ppi-backend-auth `24eddd0`. Prepared 2026-10-06.
>
> **Related:** falcon-auth#6 (the design: [`ISSUE-6-AUTHENTICATORS.md`](ISSUE-6-AUTHENTICATORS.md)) ·
> falcon-auth#8 (C-055/C-056) · platform-conventions#5 C1 (register falcon-auth as a platform artifact).

---

## 1. Why this exists

**The asks don't describe the mechanism.** Conventions state what binds services, not how a library is built (PROCESS
§6; the conventions thread made the same call in ADR-018), so the asks were written without describing the mechanism.
That's right for the asks.

**But the platform still needs to see the mechanism, for three reasons:**

1. **Some constructs carry a rule the platform may want to own** (§4). `PROVEN_AT_PERIMETER` turns RUL-048 and auth's
   P4 into something stated in code. The rules the middleware always refuses are what make "several methods on a
   plane" safe. Ruling on #6 without them means ruling on a weaker version of the proposal than what's built.
2. **The probe exemption bears directly on #13.** It is the same RUL-033 treatment of probes that #13 asks C-039 to
   adopt.
3. **Platform-conventions#5 C1 asks to register falcon-auth as a platform artifact.** If that's ruled, a change to
   these constructs comes back as a ruling, so the platform should know what's there.

---

## 2. The constructs that are built

### 2.1 Authenticators: a configured credential (falcon-auth#6, step 1)

A credential is four parts: **carrier · check · binding · single use**. One instance of a class below is one
configured credential.

| Construct | Where | What it is | Rule it implements |
|---|---|---|---|
| `Selector(header, scheme)` | `adapters/authenticators.py` | where a credential is read. A header in **another scheme reads as absent**, not invalid; the scheme is case-insensitive; `scheme=None` takes the whole value. `Selector.TLS` stands for the peer certificate. | C-038 steps 2–3: "absent" and "invalid" must stay distinguishable |
| `PlaneAuthenticator` | same | the base every configured credential shares: `planes`, `method`, `selector`, `single_use`. The middleware's tri-state contract: principal / `None` / raises. | C-038 resolution table |
| `JWTAuthenticator(verifier, selector, *, plane, user_cls \| principal, binding, single_use)` | same | checked by signature. Errors: `InvalidToken` → 401; any other verifier failure → 503. The principal comes from `user_cls`, from the host's loader (auth loads its session there, ADR-091), or is the claims themselves. | falcon-auth#1 A4 (401 vs 503) |
| `ReferenceAuthenticator(lookup, selector, *, plane, binding, single_use, timeout)` | same | checked by the host's lookup (database or HTTP). **Three outcomes:** principal, 401 `Unauthenticated`, 503 `AuthzUnavailable`. A presented but unknown token is 401, never absent. A timeout is 503. **Never cached in the package.** | instant revocation is a reference token's whole advantage; C-016 (no identity provider on the hot path) |
| `MTLSAuthenticator(verifier, *, plane=SERVICE)` | same | the peer certificate against the allow-list. No certificate → absent; an unknown CN raises. | C-018, C-038 step 4 |
| `CustomAuthenticator(attempt, *, plane, method, selector)` | same | a host's own tri-state callable, given the plane, method and carrier the middleware needs | — |
| `Binding` (protocol: `bind(req, principal, token)`) | same | **proof of possession, run inside the authenticator, after the credential.** It can't be skipped the way a separate hook can (auth's `client_session.py:42` checks the client only *if* a proof is present). | RFC 9449; auth ADR-050 §4 / ADR-091 (one proof, checked once) |
| `PROVEN_AT_PERIMETER` | same | a binding that declares the proof was checked upstream. **A `DPoP`-scheme token with no declared binding logs a `DeprecationWarning` now, and a later release refuses it.** It changes nothing at request time. | **RUL-048; auth's P4** (see §4) |
| `single_use=True` | `JWTAuthenticator`, `ReferenceAuthenticator` | **checked in middleware, never spent there**; the handler consumes it in its own transaction, after idempotency. The method becomes `ONE_SHOT_TOKEN`. | **C-030** (verified and consumed atomically with the change; a retry doesn't spend twice) |
| `REFERENCE_TOKEN` | `planes.py` (`Method`) | a name for "opaque, looked up, reusable until expiry". It sits under **no plane** in `METHODS_BY_PLANE`, and `PLANE_BY_METHOD` is still exactly four methods. | named by how it's checked, not "bearer" or "opaque" |
| `jwt_authenticator`, `mtls_authenticator`, `RemoteJWKSAuthenticator(binding=)` | same | the earlier names, kept. They build the classes above; the boolean authenticator accepts only `PROVEN_AT_PERIMETER`. | backward compatibility |

### 2.2 Which credentials a route accepts (falcon-auth#6, step 2)

| Construct | Where | What it is |
|---|---|---|
| `mount(..., credential="name" \| ["a", "b"])` · `Registration.credentials` | `adapters/routing.py` | pins one credential, or several tried in order. Unpinned accepts every authenticator on the plane, which is exactly one wherever a plane has one. |
| `PlaneAuthenticationMiddleware(authenticators=...)` | `adapters/middleware.py` | takes `{Method: callable}` (the original shape, unchanged) or `{name: PlaneAuthenticator}`. Mixing the two is refused. |
| the wrong-plane 404, generalized | same | fires only for a valid credential from an authenticator on **no plane of the route's**. A credential from the **same** plane that the route doesn't accept → **401, not flagged**, so nothing about the plane is revealed. |
| `verify(profile="strict" \| "permissive")` · `ConventionDeviation` · `Profile` | same | the startup checks; see §3 |
| `exempt_paths` (default `DEFAULT_PROBE_PATHS`) | same | stands aside only for a probe that was **never registered**. A registered route is never exempt. Before this, an unregistered probe raised `UnregisteredRoute` on every request. |
| `AUTH_CREDENTIAL_ATTR` (`req.context.auth_credential`) | same | which named credential opened the route. A handler that must spend a single-use credential reads it. |

### 2.3 The service plane in the policy (falcon-auth#8, `v0.2.0`; C-055/C-056, proposed)

| Construct | Where | What it is |
|---|---|---|
| `MissingCapabilityError` · `require_service_capability` · `Verifier.require_capability` · `Principal.capabilities` · `SvcPlaneErrorCodes.missing_capability` | `eastwest/`, `adapters/hooks.py` | **C-055:** one word, *capability*. The old names still work with a warning. The wire is unchanged until ratification (`title: "MissingScopeError"`, `extras.scope`, 9002). |
| `build_allow_list(..., capabilities: / scopes:)` | `eastwest/verifier.py` | reads both keys, with one startup warning naming the CNs that use the old key. A row with both keys is refused. **This fallback is required:** a missing key reads as an empty set and would 403 every service route, silently. |
| `build_enforcer(registry, peers={peer: [entitlements]})` · `CapabilityEnforcer.peers` / `allows_peer` | `entitlement/enforcer.py` | **C-056:** `g, <peer>, <entitlement>` rows in the same policy, under the unchanged AUTHZ-MODEL §2. An undeclared peer is refused before casbin is consulted (the #1 A2 shape). |
| `verify_policy(..., peers=)` · `check_peers` | `entitlement/flatness.py` | refuses: a peer named like a grant or an entitlement; a third hop; a peer row naming an entitlement that opens nothing |
| `build_allow_list(..., peers=)` | `eastwest/verifier.py` | refuses a SERVICE row naming an undeclared peer. **Ignores leftover capabilities with a warning** for one release (the adoption window). Warns for a declared peer with no certificate bound. |
| `require_service_capability(..., enforcer=)` | `adapters/hooks.py` | checks the capability **when the decorator runs**, as `require()` does on the user plane. A CALLBACK principal is refused. |

---

## 3. The rules the middleware enforces

| Rule | Kind | Under `strict` | Under `permissive` |
|---|---|---|---|
| a plane with mounted routes and nothing that can open them | **always refused** (startup, and at the first request) | `UnregisteredRoute` | `UnregisteredRoute` |
| a pin naming an unknown authenticator, or one on another plane | **always refused** | `UnregisteredRoute` | `UnregisteredRoute` |
| two authenticators accepted on **one route** reading the same header | **always refused**: a valid credential of one kind would be an invalid one of the other | `PlaneConflict` | `PlaneConflict` |
| authenticators on **different planes** reading the same header | **always refused**, at construction: the wrong-plane search couldn't tell them apart | `PlaneConflict` | `PlaneConflict` |
| a PUBLIC route naming a credential | **always refused**, at mount | `PlaneConflict` | `PlaneConflict` |
| a `DPoP` scheme with no declared binding | **warning → refusal in a later release** | warns | warns |
| **R1:** a plane carries a method C-038 doesn't put there | recommendation | `ConventionDeviation` | logged once |
| **R2:** an authenticator attached to more than one plane | recommendation | `ConventionDeviation` | logged once |
| **R3:** a route accepts two authenticators of the **same** method (CALLBACK's HMAC + one-shot token, both on C-038's map, passes) | recommendation | `ConventionDeviation` | logged once |

**Why the line falls where it does:**
- The "always refused" rules are the ones without which the middleware would give a **wrong answer**: a legitimate
  caller getting 401, or a credential misread as another plane's.
- R1–R3 are what C-038 and C-031 rule. A service may depart from them only knowingly, and the permissive profile
  makes every departure visible in the startup log.

---

## 4. Which constructs carry a platform rule

| Construct | The rule inside it | Today | Suggested home |
|---|---|---|---|
| `PROVEN_AT_PERIMETER` + the declared-binding warning | **a service that receives sender-constrained tokens states who checked the proof**: the gateway (RUL-048, P4), or itself | library behaviour only | a sentence in **C-038**'s User row, beside "DPoP is discharged at the perimeter". Today a `DPoP` token configured with no binding is indistinguishable from a bearer token, which is what a stolen one would be. |
| the always-refused rules (§3) | **several credentials on one plane are safe only if** each route pins its own, carriers are disjoint on a route and across planes, and the wrong-plane test is "no plane of this route's" | library behaviour only | the conditions attached to **#6 option (a)**. A ruling that allows several methods without them allows less safe wiring than what's built. |
| `single_use` checked here, spent in the handler | C-030's "verified and consumed atomically, after idempotency" | already C-030 | none new; relevant to **#8** |
| `exempt_paths` (unregistered probes only) | probes sit outside the plane system | RUL-033 | the same reasoning **#13** asks C-039 to adopt |
| the `scopes:` fallback and the leftover-capabilities window | an authorization config change must never silently empty a peer's holding | C-056 §3 (proposed, amended) | **#11** |
| `R1`–`R3` and the two profiles | how C-038 / C-031 conformance is checked in a Python service | C-006 places enforcement "in-process, by every service"; conformance checks are owed | a `Conformance:` line in C-038 naming `verify(profile="strict")` as the mechanised check for Python services |

Everything else in §2 is library detail and needs no ruling.

---

## 5. Proposed, not built (falcon-auth#6, step 4)

Waits on platform-conventions#6 (and #8 for the software statement).

| Construct | What it would be |
|---|---|
| `ProofAuthenticator(binding, *, plane)` | a DPoP proof by a registered client key as the **whole** credential: auth's `/authentication`, `/token:refresh`, `keys:bind`, `/devices/threats:report` |
| `DPoPBinding(mode="client" \| "token" \| "self_signed", nonces=, resolve_client=)` | the RFC 9449 checks (`typ`, `alg`, embedded key, signature, `htm`, `htu` normalized as in ADR-116, `iat`, `ath` only when the scheme is `DPoP`), plus issuing the next nonce on writes. The host supplies the nonce store (atomic check-and-spend), the client lookup (with key age and attestation freshness), and the link gate's pin. One verifier shared by every binding. |
| `DPOP_PROOF` | a `Method` name for the key proof alone |
| an identity-provider allowance in `strict` | if #6 rules option (a): the identity provider's USER plane passes strict with {JWT, REFERENCE_TOKEN, ONE_SHOT_TOKEN, DPOP_PROOF} |
| a stateless proof check for consumers | `DPoPBinding` without a nonce store. P4 lists it as "not pursued now", as defence in depth against a gateway bypass. |

---

## 6. Map: platform asks → constructs

| Platform issue | Constructs it touches |
|---|---|
| [#6](https://github.com/juniofirstpay/platform-conventions/issues/6) C-038, identity provider's USER plane | §2.1 (all), §2.2, §3, §4 rows 1–2, §5 |
| [#7](https://github.com/juniofirstpay/platform-conventions/issues/7) one credential per route | `mount(credential=[...])`, R3, the one-route header rule |
| [#8](https://github.com/juniofirstpay/platform-conventions/issues/8) C-030 for key-bound bootstrap credentials | `single_use`, `ONE_SHOT_TOKEN` on USER |
| [#9](https://github.com/juniofirstpay/platform-conventions/issues/9) C-052 actor type for pre-user routes | none built; the C-052 actor-type guard is owed separately |
| [#10](https://github.com/juniofirstpay/platform-conventions/issues/10) CAND-44 | none; `/attest` mounts as PUBLIC with a reason |
| [#11](https://github.com/juniofirstpay/platform-conventions/issues/11) ratify C-055 / C-056 | §2.3 |
| [#12](https://github.com/juniofirstpay/platform-conventions/issues/12) grants wire | `TrustContext.grants` (required, `list[str]`), no grants cache (RUL-072) |
| [#13](https://github.com/juniofirstpay/platform-conventions/issues/13) unversioned probes and `/.well-known` | `exempt_paths`, `verify_app(exempt_paths=)` |
| [#14](https://github.com/juniofirstpay/platform-conventions/issues/14) body hash | `verify_operation_for`'s `BodyHasher`; falcon-auth#7 |

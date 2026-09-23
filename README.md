# falcon-auth

Every post-transport trust decision a Falcon service makes, in one package: east-west mTLS identity, token authentication, session assurance, and entitlement.

One question — **may this caller do this?** — answered in four parts that previously lived in three different places.

- **Self-contained.** No dependency on `falcon-svcplane`; its logic lives here. Nothing is imported from the `falcon_utils` namespace.
- **One plane vocabulary, one principal.** The split it replaces defined both twice, in two packages, with different spellings.
- **Framework-agnostic cores.** Nothing outside `falcon_auth.adapters` imports Falcon. A token string, two reference strings, a raw ASGI scope — each core is exercisable without a web framework.
- **No transport, no configuration.** The package performs no HTTP and reads no settings. A consumer injects its session getter and passes every value as an argument.
- **Fail-closed by default.** An empty allow-list denies every east-west route; an unmapped CN gets zero scopes; a capability with no registry row is detectable, because absence must never mean "ungated".

---

## Install

Pipfile:

```
falcon-auth = { git = "https://github.com/juniofirstpay/falcon_auth.git", ref = "<sha>" }
```

Pin a `ref`. This package sits on the authorization path of every consuming service; a push reaching production unannounced is the failure mode it exists to design away.

---

## The four parts

| Part | Answers | Key symbols |
|---|---|---|
| `eastwest/` | is this peer service who its certificate says, and does it hold this scope | `Verifier` · `build_allow_list` · `peer_cn` |
| `identity/` | who is this user | `JWKSStore` · `JWKSVerifier` |
| `assurance/` | how strongly, how recently | `SessionTrust` · `check_session_elevated` |
| `entitlement/` | what class of thing may they do | `AuthServiceResolver` · `CapabilityEnforcer` |

Three modules sit above them, because they are the shared vocabulary the package exists to unify — none ever moves inside a part:

| Module | Holds |
|---|---|
| `planes.py` | `Plane` · `Method` · `METHODS_BY_PLANE` · `PLANE_BY_METHOD` — the four planes and the one method each authenticates |
| `principal.py` | the user-plane principal (`UserPrincipal` at the package root) |
| `trustcontext.py` | **one** call to auth, read by both assurance and entitlement |

Two notes on that table, both corrections to an earlier sketch of it:

- **`planes.py` holds the vocabulary, not the route machinery.** `PlaneRegistry` and `mount()` — declaring a route's plane and refusing a mismatch at startup (C-006) — need route and version knowledge and touch Falcon, so they belong in `adapters/` beside the authentication middleware that reads the same map. They are not built yet.
- **There are two principal models, not one.** The east-west `Principal` (`cn` · `kind` · `source` · `scopes`) and the user-plane one (`user_ref` · `entitlements` · session and device trust) share **no field**. Merging them would produce a model where most attributes are `None` on any given request and a handler could not tell which kind it held, so they stay separate and are exported as `Principal` and `UserPrincipal`.

---

## The boundary this package keeps

> The east-west, identity and assurance parts may **establish** who a caller is and how strongly.
> They may never **decide** permission. Only `entitlement/` decides.

A guard test asserts the import direction. Packaging used to hold that line; module structure holds it now.

**Out of scope, permanently:** ownership ("is this *their* object") and domain ("does the object's state permit it"). Only the owning service holds the data to answer them, and any answer computed elsewhere is stale by the time it is used.

---

## Authorization: three levels

```
grant         auth's word      coarse, estate-wide, slowest-moving
entitlement   the service's    fine-grained, what a principal holds here
capability    the route's      what an endpoint demands — one noun:verb per endpoint
```

Two registries per service: **grant → entitlement** (the expansion) and **capability → entitlement** (which holding opens which route). A service adding or retiring routes changes its own entitlements and capabilities and never the grant vocabulary at auth.

Both maps live in **one** casbin policy set — `g, <grant>, <entitlement>` and `p, <entitlement>, <capability>` — exactly two hops, flat, enforced by a build-time lint because casbin chains a third silently.

The engine is not a choice: casbin is a mandated stack element and the model text is a platform artifact, never re-authored here.

---

## Status

**Six parts landed, 204 tests.** East-west is ported behaviour-identical from `falcon-svcplane` with its own tests as the correctness check; identity and entitlement are ports of code already running in two services; assurance, the plane vocabulary and the plane middleware are written from scratch.

| Landed | |
|---|---|
| `eastwest/` | verifier · errors · mtls |
| `identity/` | JWKS store, verifier, Falcon authenticator |
| `trustcontext.py` · `errors.py` · `principal.py` | one call to auth, read by two layers |
| `assurance/` | the step-up gate |
| `entitlement/` | resolver · enforcer · the capability gate |
| `planes.py` · `adapters/routing.py` · `adapters/middleware.py` | one plane per endpoint, one method per plane |

**C-038 conformance is complete**: the platform model text, the `g` layer as policy data, the any-of capability registry, per-grant first-match evaluation, the flatness lint, the grant-register boot check, and assurance served live rather than from a cache window.

**Still owed:** nothing in the package until auth emits grants. The expansion stays empty and the grant register stays empty until it does — by design, not by omission.

---

## How it runs

[`docs/FLOW.md`](docs/FLOW.md) traces what calls what across the plane system: the boot sequence, the per-request resolution, every exit and its status code, and the three seams where a consumer's own code is called.

[`docs/EASTWEST.md`](docs/EASTWEST.md) does the same for east-west: how a peer service's certificate becomes an identity, the allow-list check, and the three refusals.

[`docs/IDENTITY.md`](docs/IDENTITY.md) covers the user plane: how a JWT is checked against the issuer's rotating keyring, why the algorithm is pinned server-side, and why the claim allowlist has no default.

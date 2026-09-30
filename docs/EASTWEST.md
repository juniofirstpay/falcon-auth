# EASTWEST.md — how a peer service proves who it is

East-west is service-to-service traffic: one of our backends calling another, with no end user
involved. There is no token. The **client certificate is the identity**, and the whole question
this part answers is:

> Is this peer who its certificate says it is, and is it allowed to do this particular thing?

In one sentence: **a guest list at the door.** The certificate is the ID card, the CN is the name
printed on it, the allow-list is the guest list, and the capabilities are what that guest may do
once inside.

**One word.** What a route demands is a *capability* on both planes (C-055, proposed;
falcon-auth#8). This part used to say *scope* for the same object; the old names still work, with
a `DeprecationWarning`, and the wire has not changed — see [The three refusals](#the-three-refusals).

---

## The pieces

| File | Job |
|---|---|
| `eastwest/mtls.py` | makes the connection mutual-TLS, and gets the peer's certificate into the request |
| `eastwest/verifier.py` | reads the name off the certificate and checks it against the allow-list |
| `eastwest/errors.py` | the three refusals, and their wire shape |
| `adapters/hooks.py` | the Falcon decorators that put the verifier on a route |

---

## Phase 1 — boot

```
your app startup
│
├─ build_uvicorn_ssl_kwargs(cert_file, key_file, client_ca_file)      mtls.py
│  │
│  ├─ cert_file == ""  ──►  {}   uvicorn stays plaintext
│  │                             (dev, tests, TLS terminated upstream)
│  │
│  └─ otherwise  ──►  ssl_certfile · ssl_keyfile · ssl_version
│                     + ssl_ca_certs and CERT_OPTIONAL when a client CA is given
│
├─ uvicorn runs with the patched protocol classes                     mtls.py
│     H11Protocol / HttpToolsProtocol subclasses that capture the peer certificate
│     on connection_made and inject it into every ASGI scope they build
│
├─ build_allow_list(settings.svcplane.allow_list)                     verifier.py
│  │   each row: cn · kind · source · capabilities   (`scopes` still read, with one boot warning)
│  ├─ kind not SERVICE or CALLBACK?  ──►  raise ValueError at boot
│  ├─ a row with both `capabilities` and `scopes`?  ──►  raise ValueError at boot
│  └─ {cn: Principal(cn, kind, source, capabilities)}
│
└─ Verifier(allow_list, codes=SvcPlaneErrorCodes(...))                verifier.py
      codes are optional -- only for a consumer whose 9xxx range is already taken
```

### Why `CERT_OPTIONAL` and not `CERT_REQUIRED`

One listener serves both the user plane (a person's app, a JWT, **no** client certificate) and
the service plane (a peer backend, **a** client certificate). If the socket demanded a
certificate, every end user would be rejected at the TLS handshake before Falcon ever saw them.

`CERT_OPTIONAL` is Python's equivalent of Go's `VerifyClientCertIfGiven`:

- a certificate is presented → it **must** chain to the CA bundle, or the handshake fails
- no certificate → the handshake succeeds, and the verifier refuses the east-west route later

So chain validation is TLS's job, and "did you bring one at all" is the verifier's.

### Why the protocol classes are patched

uvicorn does not put peer-certificate information into the ASGI scope. Without the patch there is
simply nothing for the verifier to read. The subclasses capture the certificate when the
connection is made and intercept every `self.scope = {...}` assignment, so
`scope["extensions"]["tls"]["peer_cert_der"]` is there before the request runs. Pipelined
requests each get their own injection, because each one triggers a fresh scope assignment.

---

## Phase 2 — a request arrives

```
peer backend opens a connection
│
├─ TLS handshake
│     cert presented but does not chain  ──►  handshake FAILS, no HTTP at all
│     cert presented and valid           ──►  captured by the protocol subclass
│     no cert                            ──►  handshake succeeds, nothing captured
│
├─ the protocol subclass injects scope["extensions"]["tls"]["peer_cert_der"]
│
└─ the route's hook runs                                         adapters/hooks.py
   │
   │  SERVICE route:   @falcon.before(require_service_capability(verifier, "wallet:debit"))
   │  CALLBACK route:  @falcon.before(require_callback(verifier))
   │
   ├─ verifier.authenticate(req.scope)                           verifier.py
   │  │
   │  ├─ peer_cn(scope)
   │  │    reads peer_cert_der · parses the X.509 · returns the subject Common Name
   │  │    returns None when: TLS is off · no cert was presented ·
   │  │                       the DER is malformed · the cert carries no CN
   │  │
   │  ├─ CN is None            ──►  MissingClientCertError    401
   │  ├─ CN not in allow-list  ──►  UnknownCNError            403
   │  └─ ──►  Principal(cn, kind, source, capabilities)
   │
   ├─ SERVICE route only:
   │     verifier.require_capability(principal, "wallet:debit")  verifier.py
   │     ├─ principal is None, or does not hold it  ──►  MissingCapabilityError  403
   │     └─ holds it  ──►  continue
   │
   ├─ CALLBACK route: no capability check at all
   │     A callback principal carries no capabilities. Presenting a known, cert-bound identity IS
   │     the whole authorization -- the payload is then treated as data, never as authority.
   │
   └─ req.context.eastwest_principal = principal
         the handler runs
```

---

## The three refusals

| What happened | Error | Status | Why that status |
|---|---|---|---|
| No client certificate | `MissingClientCertError` | **401** | a failed *credential* — we do not know who you are |
| CN not on the allow-list | `UnknownCNError` | **403** | we know who you are; you are not on the list |
| On the list, lacks the capability | `MissingCapabilityError` | **403** | we know who you are; you may not do *this* |

The 401/403 split is deliberate (C-018). A failed credential is an **authentication** problem; a
known CN lacking the capability is an **authorization** one. Collapsing them would make an unreachable
service and an under-privileged one look identical in the logs, and those have very different
fixes.

All three render as `{code, title, description}` — the same envelope every consuming service
already emits. `MissingCapabilityError` still renders with `title: "MissingScopeError"` and
`extras.scope`: the wire changes only when C-055 is ratified and the envelope work in
falcon-auth#1 A8 lands (`PLAT0105` folds into `PLAT0102`). `MissingScopeError` is the same class,
so an existing `except` keeps working. Only the numeric `code` is overridable, via `SvcPlaneErrorCodes`, for a consumer
whose 9xxx range is already spoken for.

---

## Fail-closed, in three places

**An empty allow-list denies everyone.** It is not "no rules configured, let everything through";
it is a guest list with no names on it.

**An unknown CN gets zero capabilities.** Not a default set, not a warning — nothing.

**A bad `kind` in config raises at boot,** not at request time. A mis-typed row should fail where
the wiring is written, not silently drop a peer that then gets 403s nobody can explain.

---

## A worked example

Config:

```yaml
svcplane:
  allow_list:
    - cn: payments.internal
      kind: SERVICE
      source: payments
      capabilities: [wallet:debit, wallet:read]
    - cn: npci-rails.internal
      kind: CALLBACK
      source: npci
```

| Caller | Route | Outcome |
|---|---|---|
| `payments.internal` | SERVICE, needs `wallet:debit` | **200** — on the list, holds the capability |
| `payments.internal` | SERVICE, needs `wallet:refund` | **403** `MissingCapabilityError` — on the list, not this |
| `analytics.internal` | any east-west route | **403** `UnknownCNError` — valid cert, not on the list |
| a user's app (JWT, no cert) | any east-west route | **401** `MissingClientCertError` |
| a forged cert | anything | **no HTTP at all** — the handshake fails |
| `npci-rails.internal` | CALLBACK | **200** — being a known identity is the authorization |

Note row three: `analytics.internal` has a **perfectly valid certificate** signed by our own CA.
TLS is satisfied. It is still refused, because chaining to the CA proves the caller is *one of
ours*, not that it is *allowed here*. The allow-list is what makes that second judgement, and it
is the reason CA trust alone is not the authorization.

---

## Policy mode: the peer's capabilities in the Casbin policy (C-056, proposed)

Everything above is **allow-list mode** (C-018): each row lists what its CN may do, in config
rendered from Vault, checked against nothing. A capability typo'd on a route mounts cleanly and no
peer can ever open it; one typo'd in the allow-list grants nothing, silently (falcon-auth#8).

**Policy mode** splits the row's two jobs:

| Question | Where | Example |
|---|---|---|
| which certificate is which peer | the allow-list — config, per environment | `cn: payments.preprod.internal` → `source: payments` |
| what that peer may do | `g` rows in the service's own policy — code | `g, payments, SVC_KYC_READ` · `p, SVC_KYC_READ, kyc:read` |

The peer takes the grant's place in the same two-layer policy the user plane uses
([`ENTITLEMENT.md`](ENTITLEMENT.md)): one gate, one lint, one registry. `source` is the logical
peer name, the same in every environment, so the policy never differs between them.

```python
enforcer = build_enforcer(
    REGISTRY,                                   # capability -> entitlements, both planes
    peers={"payments": ["SVC_KYC_READ"]},       # peer -> what it holds
)
verify_policy(REGISTRY, grant_register=GRANTS, peers={"payments": ["SVC_KYC_READ"]})
verifier = Verifier(build_allow_list(settings.svcplane.allow_list, peers=enforcer.peers))

class KycRoute:
    @falcon.before(require_service_capability(verifier, "kyc:read", enforcer=enforcer))
    async def on_get(self, req, resp): ...
```

What refuses boot, and what only warns:

| Condition | Outcome |
|---|---|
| a route demands a capability with no registry row | **raises at decoration** — the #8 typo |
| an allow-list row still lists capabilities | **refused** — they would be enforced by nothing |
| a SERVICE row names a peer the policy does not declare | **refused** — a typo'd `source` |
| a peer row names an entitlement that opens nothing | **refused** by `verify_policy` |
| a peer named like a grant or an entitlement, or a third hop | **refused** by `verify_policy` |
| a declared peer bound by no CN in this environment | a boot **warning** — it may not exist here |

The check itself lives in `entitlement/` and the hook, never in `eastwest/`: east-west establishes
who called, and only `entitlement/` decides. `build_allow_list` gets the peer names as a plain set.
A CALLBACK principal on a SERVICE route is refused in both modes.

---

## Where this sits relative to the plane system

East-west is the SERVICE and CALLBACK half of [`FLOW.md`](FLOW.md)'s four planes. The plane
middleware decides *which* credential a route accepts; this decides whether the certificate that
arrived is one we know and one that may do the thing being asked.

The enclosure is always mTLS — user-plane requests also arrive over a mutually authenticated
connection, because the gateway has its own certificate. So a client certificate alone does not
make a request east-west. **The plane follows the credential that authorizes the call**, and for
east-west that is the peer CN with no user token in sight.

# OPERATION-STEPUP.md — proving it for *this* act

[ASSURANCE.md](ASSURANCE.md) covers the session-wide elevation **window**: is this session
elevated right now. This covers the other mechanism:

> Did the user step up **for this specific operation**?

They sound alike and are not the same control.

| | General elevation | Per-operation step-up |
|---|---|---|
| Asks | is the session elevated **now**? | did they step up **for this act**? |
| Bounded by | a time window | a single consumed challenge |
| Bound to | nothing in particular | the request body |
| Reusable | yes, for the window | **no** — single use |
| Use for | a **read** | a **write** |

## Why a mutation cannot use the window

An elevation window authorizes a **period**. Gate a write on it and one step-up authorizes
*every* write until the window closes — the user proved themselves once and paid for a hundred
mutations.

That is not a weaker version of the same control. It is a different control that happens to
report the same tier. Reading twice is reading the same thing twice; writing twice is not.

**So one resource legitimately carries both.** A profile route gates its `GET` on the window and
its `PATCH` on a per-operation challenge. That is the intended shape, not a redundancy.

```python
class ProfileResource:
    @falcon.before(require_elevated_for_this_service)
    async def on_get(self, req, resp): ...

    @falcon.before(idempotency_lookup)
    @falcon.before(require_profile_mutation_stepup)
    async def on_patch(self, req, resp): ...
```

---

## The flow

```
client mints X-Operation-Id, runs step-up under it     challenge -> PASSED
│
└─ PATCH /profile   X-Operation-Id: op-1
   │
   ├─ @falcon.before(idempotency_lookup)        RUNS FIRST
   │     cached response for op-1?  ──►  return it, and NEVER reach the gate
   │
   └─ @falcon.before(require_operation_step_up(...))    adapters/hooks.py
      │
      ├─ operation_id = req.get_header("X-Operation-Id")
      │     absent  ──►  Unauthenticated, and nothing is spent
      │
      ├─ session_ref, user_ref = refs(req)            your extractor
      │
      ├─ body_hash(await req.get_media())             your canonicalizer
      │     get_media(), NEVER stream.read() -- see below
      │
      └─ verify_operation(...)                        assurance/operation.py
         │
         ├─ POST …/operations/{operation_id}:verify   CONSUMES the challenge
         │     410 / 8501  ──►  OperationChallengeMiss
         │     403         ──►  AuthzUnavailable   our cert lacks step_up:verify
         │
         ├─ target_session_tier < required
         │       ──►  StepUpRequired   a real challenge, for a weaker policy
         │
         ├─ request_body_hash != ours
         │       ──►  OperationBodyMismatch
         │
         └─ ──►  OperationVerification, and the handler runs
```

---

## Three things that are not obvious

### 1. The idempotency lookup **must** run first

`X-Operation-Id` is also the idempotency key, so the same value identifies both the challenge
and the cached response. That is fine — until a response is lost in flight:

```
1. client sends PATCH with op-1
2. :verify  ──►  200, challenge CONSUMED
3. write succeeds
4. response DROPS                          client sees nothing
5. client retries with op-1                exactly what the key is for
6. :verify  ──►  410, already consumed
7. the client gets an error instead of the cached response
```

The retry the key exists to make safe is the one that breaks. **The fix is ordering**, not a
second header: on a cache hit, return the stored response and never call `:verify`.

Falcon runs stacked `before` hooks **outermost-first** — the decorator listed first runs first.
That is the reverse of what Python's decorator semantics suggest (the innermost *wraps* first
but *executes* last), so it is measured and asserted rather than assumed.

### 2. The hook reads the body with `get_media()`, never `stream.read()`

Body binding is caller-side, so the hook has to see the body. Reading the **stream** in a hook
leaves the handler with nothing:

```
hook saw     : b'{"amount": 500}'
handler saw  : b''
handler media: 400 "Could not parse an empty JSON body"
```

`get_media()` caches the **deserialized** media, so hook and handler share one object. If that
ever changes, per-operation step-up cannot be a `before` hook at all — which is why there is a
test asserting the handler still sees its body.

### 3. Consume-before-execute burns a challenge on a failed write

`:verify` **spends** the authorization before the handler runs. If the write then fails, the
challenge is gone and the user must step up again rather than retry.

That is deliberate: consuming *after* the write would let a crash between write and consume
authorize a second execution. The cost is real and accepted — and it means
`OperationChallengeMiss` must be distinguishable from an ordinary failure, or a client will
retry forever into a challenge that can never become spendable again.

---

## Body binding, in plain terms

When the user stepped up, auth recorded a **fingerprint of the body they agreed to**. On
`:verify` it hands that fingerprint back — and does **not** compare it for you.

Why not? Auth does not know your body format. These are the same request to you:

```json
{"amount": 500, "to": "x"}      {"to": "x", "amount": 500}
```

…but different bytes, so different fingerprints. Only your service knows which fields matter and
how to write them down predictably. **Canonicalizing** is turning a body into one fixed string so
the same logical request always hashes the same way. That is a schema question, and the schema is
yours.

So you supply `body_hash: (parsed media) -> str`. The package calls it, compares, and refuses a
mismatch.

**Why it matters:** the user steps up to transfer ₹500. Without the comparison, that same
challenge authorizes a body saying ₹50,000.

### The asymmetry worth knowing

| auth bound a hash | we computed one | result |
|---|---|---|
| yes | yes | compare; mismatch refuses |
| **yes** | **no** | **REFUSE** — the binding exists and we cannot honour it |
| no | yes | fine — the purpose is not body-bound |
| no | no | fine |

Row two is the strict one. Treating "we have no hash" as "no check needed" would let a service
opt out of body binding by *forgetting to pass a hasher* — which is exactly how a body-bound
challenge quietly stops being body-bound.

---

## The four refusals

| Raised | Means | Client should |
|---|---|---|
| `Unauthenticated` | no `X-Operation-Id` on a route that needs one | mint one, run step-up |
| `OperationChallengeMiss` | unknown, unpassed, expired **or already consumed** | run step-up under a **new** operation id |
| `OperationBodyMismatch` | not the act that was authorized | re-raise the challenge for this body |
| `StepUpRequired` | real challenge, weaker tier than this route needs | raise a stronger challenge |

`OperationChallengeMiss` is deliberately uniform. Auth answers unknown, unpassed, expired and
consumed with one code so challenge state does not leak across the mTLS boundary — a consumed
operation "looks gone". This package keeps that uniformity rather than guessing which case it
was.

And note it is **not a retry**. That distinction is the whole reason it has its own type.

---

## What the package does not supply

- **The canonicalizer.** Yours — it is a schema question.
- **The idempotency store.** Yours, and it must run before this gate.
- **The FE step-up flow.** The client passes the factor through auth's own
  `challenge:invoke` → `:authenticate`; the service that consumes the challenge never runs it.
  The `(session_ref, operation_id)` pair is a capability only the downstream service, holding
  the same operation, can redeem.

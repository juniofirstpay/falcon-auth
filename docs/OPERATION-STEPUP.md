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

    async def on_patch(self, req, resp):
        reservation, stored = await idempotency.reserve(key=key, fingerprint=fingerprint)
        if reservation is Reservation.REPLAY:
            resp.media = stored                  # never verify -- already spent
            return
        if reservation is Reservation.IN_PROGRESS:
            resp.status = falcon.HTTP_202        # never verify -- still running
            return

        # RESERVED: the only branch that may spend a challenge
        await verify_operation_for(
            req, verifier, refs,
            expected_purpose="order_create", bind_body=True,     # needs RawBodyBuffer
        )
        ...perform the write...
```

Note the asymmetry: the read is gated by a **decorator**, the write is **not**. That is not an
inconsistency — see below.

---

## The flow

```
client mints X-Operation-ID, runs step-up under it     challenge -> PASSED
│
└─ PATCH /profile   X-Operation-ID: op-1
   │
   ├─ the before-hooks run      authn · rate limit · entitlement · map_data
   │     none of them touch the challenge
   │
   └─ on_patch, INLINE
      │
      ├─ idempotency.reserve(key, fingerprint)
      │     MISMATCH     ──►  IdempotencyKeyReusedError
      │     REPLAY       ──►  return the stored response   NOTHING SPENT
      │     IN_PROGRESS  ──►  202                          NOTHING SPENT
      │     RESERVED     ──►  a genuine first execution, continue
      │
      └─ verify_operation_for(req, verifier, refs, bind_body=True) adapters/hooks.py
         │
         ├─ operation_id = req.get_header("X-Operation-ID")
         │     absent  ──►  Unauthenticated, and nothing is spent
         │
         ├─ raw_body_hash(raw_body(req.scope))      C-058: SHA-256 over the exact bytes
         │     the bytes RawBodyBuffer kept below Falcon -- see below
         │
         └─ verify_operation(...)                   assurance/operation.py
            │
            ├─ POST …/operations/{id}:verify        CONSUMES the challenge
            │     410 / 8501  ──►  OperationChallengeMiss
            │     403         ──►  AuthzUnavailable   our cert lacks step_up:verify
            │
            ├─ purpose != expected_purpose     ──►  OperationPurposeMismatch
            ├─ request_body_hash != ours       ──►  OperationBodyMismatch
            └─ ──►  OperationVerification, then perform the write
```

---

## Four things that are not obvious

### 1. There is no `before` hook, and that is the design

`X-Operation-ID` is also the idempotency key, so the same value identifies both the challenge
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

The retry the key exists to make safe is the one that breaks. So the verify must come **after**
the idempotency reservation, and only on the branch that says this is a genuine first
execution.

**A hook cannot express that**, because in this estate the reservation is taken *inline in the
responder* — after every `before` hook has already run (see orders' `CreateOrderResource`). A
hook would consume the challenge on every replay, before `reserve` was ever called.

And the coupling is structural, not incidental: `X-Operation-ID` **is** the idempotency key, so
a route using per-operation step-up has idempotency by construction. A hook here is not
"usually wrong"; it is wrong wherever the mechanism is used at all. So the package does not
ship one, and a test asserts it does not — because a hook is the obvious thing to reach for.

### 2. The body is hashed as raw bytes, kept below Falcon

C-058 (`v28`) defines the binding over **the exact bytes received**, before any decode. A parsed
body cannot give them back, and reading Falcon's **stream** leaves whichever of the two runs
second with nothing:

```
hook saw     : b'{"amount": 500}'
handler saw  : b''
handler media: 400 "Could not parse an empty JSON body"
```

So the bytes are kept one layer down. `RawBodyBuffer` wraps the ASGI app, drains the body once,
keeps it in the ASGI scope, and replays it to Falcon **unchanged** (C-058 §1). The handler's
`get_media()` works as before, and `verify_operation_for(..., bind_body=True)` hashes the kept
bytes. Without the wrapper, `bind_body=True` raises a wiring error rather than compare against
anything else. There are tests for both.

### 3. Purpose is the gate, not a tier

An operation-scoped step-up does **not** raise the session's ambient trust tier.
`challenge:authenticate` answers **204** and writes no trust state (AUTH-ADR-112) — a proof
scoped to one operation must not grant a blanket window over the whole session, which is what
it was silently doing before that correction.

So there is no `required_tier` here. `target_session_tier` still rides on the response, but as
**provenance** — what policy the challenge was raised under — not as a statement about the
session. The session tier is [ASSURANCE.md](ASSURANCE.md)'s question, on the read path.

What gates this path is **`expected_purpose`**, and it is required with no default. Every
challenge is raised under a purpose (`ChallengePolicy` is keyed by it), and one passed for
`mpin_reset` must not be spendable on a wallet transfer. Auth cannot make that check — the
operation id is unique only *within a session*, and auth does not know which route is
redeeming it.

Note the consequence: by the time a purpose mismatch is caught, auth has already **consumed**
the challenge, because it was perfectly valid for its own purpose. The user must re-challenge.
That is the cost of catching cross-purpose replay at the only place it can be caught — and the
reason a default on `expected_purpose` would be dangerous: cross-purpose replay would become
the behaviour you get by forgetting.

### 4. Consume-before-execute burns a challenge on a failed write

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

The hash is over **bytes, not meaning** (C-058, superseding C-030's JCS clause). These are the
same object, but different bytes, so different hashes:

```json
{"amount": 500, "to": "x"}      {"to": "x", "amount": 500}
```

That is deliberate. The client hashes the final bytes it sends, as its last act (C-058 §3), and
nothing between it and the service may alter them (§1) -- so no canonicalizer is needed at either
end, and none can drift. `request_body_hash` = base64url, unpadded, SHA-256 over the body:
`falcon_auth.raw_body_hash(bytes)`.

Pass `bind_body=True` with the app wrapped in `RawBodyBuffer`. The package hashes, compares, and
refuses a mismatch. (`body_hash=`, a hasher over the parsed media, still works with a deprecation
warning; it cannot match a client following C-058.)

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
| `Unauthenticated` | no `X-Operation-ID` on a route that needs one | mint one, run step-up |
| `OperationChallengeMiss` | unknown, unpassed, expired **or already consumed** | run step-up under a **new** operation id |
| `OperationBodyMismatch` | not the act that was authorized | re-raise the challenge for this body |
| `OperationPurposeMismatch` | a real challenge, raised for a **different act** | re-challenge under the right purpose |

`OperationChallengeMiss` is deliberately uniform. Auth answers unknown, unpassed, expired and
consumed with one code so challenge state does not leak across the mTLS boundary — a consumed
operation "looks gone". This package keeps that uniformity rather than guessing which case it
was.

And note it is **not a retry**. That distinction is the whole reason it has its own type.

---

## What the package does not supply

- **The `RawBodyBuffer` wiring.** Yours -- wrap the ASGI app where the server is handed it.
- **The idempotency store.** Yours, and its reservation must resolve before this is called.
- **The FE step-up flow.** The client passes the factor through auth's own
  `challenge:invoke` → `:authenticate`; the service that consumes the challenge never runs it.
  The `(session_ref, operation_id)` pair is a capability only the downstream service, holding
  the same operation, can redeem.

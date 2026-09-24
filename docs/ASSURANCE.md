# ASSURANCE.md — how recently did they prove it

[Identity](IDENTITY.md) answers *who is this*. Entitlement answers *what class of thing may they
do*. Assurance answers a third question that neither covers:

> Did they prove who they are **recently enough**, and **strongly enough**, for this particular
> action?

In one sentence: **the bank asking for your PIN again before a large transfer.** You are already
logged in. You have every permission the transfer needs. It asks anyway, because logging in an
hour ago is not the same as proving it now.

That is why a caller can hold **every entitlement a route asks for and still be refused here**.
The two checks are answering different questions, and collapsing them produces a response that
tells the user they lack access when what they actually need is to tap a prompt.

---

## Two tiers, and no third

```
SESSION_TRUST_AUTHENTICATED = 1     signed in
SESSION_TRUST_ELEVATED      = 2     signed in, and proved it again recently
```

There is no "low" tier. Auth's own log settles it: *"you cannot be authenticated and below
baseline — the thing that looked like 'low session trust' was device-untrusted mislabelled."*
Device trust is a separate axis with its own three values; it is not a weaker session.

This is why the gate **takes no tier argument**. Its *presence* is the requirement, and
"authenticated is enough" is expressed by **not applying it**. A `tier=` parameter would imply a
choice that does not exist, and invite someone to invent a third value.

---

## The pieces

| File | Job |
|---|---|
| `assurance/stepup.py` · `check_session_elevated` | the whole check: two strings in, a context out or a raise |
| `adapters/hooks.py` · `require_elevated` | the Falcon gate that drives it |
| `trustcontext.py` · `project()` | collapses an elevation window that has passed |
| `errors.py` · `StepUpRequired` | "raise a challenge", deliberately not "you may not" |

`check_session_elevated` takes **two reference strings** and returns or raises. It never sees a
request — pulling those refs out of one is a consumer convention that depends on where that
service's authenticator put the session claim.

---

## Phase 1 — boot

There is barely any. The gate is a closure over two things:

```
require_elevated(client, refs)                              adapters/hooks.py
│
├─ client   a TrustContextClient -- the PLAIN one, never a cache-backed one
│
└─ refs     YOUR extractor: (req) -> (session_ref, user_ref)
               it knows where this service's authenticator parked the session claim,
               which is exactly why the package does not guess
```

---

## Phase 2 — a request arrives

```
the route's hooks run, in order
│
├─ @falcon.before(require("orders:read"))          entitlement FIRST
│
└─ @falcon.before(require_elevated_for_this_service)
   │
   ├─ session_ref, user_ref = refs(req)                     your extractor
   │
   └─ check_session_elevated(client, session_ref, user_ref) stepup.py
      │
      ├─ client.fetch(session_ref, user_ref=user_ref)
      │     LIVE. No cache, ever -- see below
      │     │
      │     ├─ auth 404: session dead, unknown, or not owned by this subject
      │     │       ──►  SessionMiss          re-authenticate; a challenge cannot help
      │     │
      │     └─ unreachable, or our own cert lacks trust:read
      │             ──►  AuthzUnavailable     an infrastructure fault, not the user's
      │
      ├─ context.project()                                  trustcontext.py
      │     elevated but the window has passed  ──►  collapse to AUTHENTICATED
      │     window unparseable                  ──►  collapse (the safe direction)
      │
      ├─ session_trust_level != ELEVATED
      │       ──►  StepUpRequired(required=2, present=<what they had>)
      │             the client raises a challenge and retries
      │
      └─ return the context
            the elevation window travels with it, so a caller that wants to tell the
            client how long it has does not pay for a second fetch
```

---

## The read is always fresh — and that is correctness, not performance

No cache. Three independent reasons, any one of which would be enough:

**The convention rules it.** C-038: *"assurance is live"*, and *"no blanket TTL over the whole
response: a demoted device must not keep transacting for the length of a cache window."*

**A cached elevation breaks the feature itself.** The user completes the challenge, retries, and
a stale `session_trust_level` refuses them **again**. That reads as step-up being broken, not as
a cache being warm. Elevation is the one value that changes *because of a user action* — caching
it fights the user.

**The volume argument does not apply.** Step-up gates sit on the few routes that demand
elevation. Those are precisely the routes where correctness is worth a round trip.

> This is also why C6 removed the package's read-through cache entirely. Assurance being live is
> not a property of this module alone; it is a property of the trust source.

---

## Three outcomes, kept deliberately apart

| Raised | Means | What the client should do |
|---|---|---|
| `StepUpRequired` | live session, not elevated | raise a challenge, then retry |
| `SessionMiss` | session dead, unknown, or not theirs | re-authenticate — a challenge cannot help |
| `AuthzUnavailable` | the lookup itself failed | retry; nothing the user can fix |

Collapsing these is the failure worth avoiding. Answer *"go and step up"* when the real problem
is that auth is unreachable, and you send the user to complete a challenge that **cannot** help
— and you charge an infrastructure fault to them.

### `StepUpRequired` is not a `CapabilityDenied`, on purpose

Contrast it with `SessionMiss`, which *is* one. A host that maps `CapabilityDenied` as a
catch-all renders **"you do not have access to this"** — and here that is both wrong and
unhelpful. The caller may hold every entitlement the route asks for; the only thing missing is a
recent enough proof of who they are.

So a host must map this one explicitly. That is the cost, and what it buys is a response that
tells the client **what to do next** rather than that it may not. `required` and `present` travel
on the error so the body can carry them — the client needs to know *which* challenge to raise.

---

## Ordering: entitlement first, then assurance

```python
@falcon.before(require("orders:read"), is_async=True)
@falcon.before(require_elevated_for_this_service, is_async=True)
async def on_get_object(self, req, resp, order_id): ...
```

C-033 makes this ordering load-bearing. A principal who holds **no entitlement at all** should
get a clean refusal — not be sent away to complete a challenge that was never going to help
them. Sending someone through a PIN prompt only to refuse them afterwards is a worse experience
*and* a worse audit trail.

---

## Why `project()` runs even on a fresh read

A fresh read arrives already projected by auth, so this looks redundant. It is kept because it is
free, and because the direction it can be wrong in is the safe one: if auth ever returned an
elevated session whose window had passed, honouring it would **extend an elevation nobody
granted**.

An unparseable window is treated as expired for the same reason — under-report trust, never
project an elevation that cannot be bounded.

Defence in depth on a gate. Not a substitute for auth doing it.

---

## The `**_kw` in the hook

```python
async def hook(req, resp, resource, params, *_a: Any, **_kw: Any) -> None:
```

Those absorb what `falcon.before(action, *args, **kwargs)` forwards — notably the `is_async=True`
that callers across this ecosystem still pass, believing Falcon consumes it. **Falcon 3 did;
Falcon 4 detects hooks automatically and the parameter is gone**, so a strict signature raises
`TypeError` — a 500 on every gated route.

Nothing is read from them, deliberately. A gate that varied with decorator kwargs would be a
second, invisible configuration surface.

---

## Two mechanisms, and they are not interchangeable

| | General elevation | Per-operation step-up |
|---|---|---|
| Scope | the whole session | one specific act |
| Bounded by | a time window | a single consumed challenge |
| Bound to | nothing in particular | the request body |
| Use for | a **read** | a **write** |
| Where | `assurance/stepup.py` | `assurance/operation.py` |
| Gate | `require_elevated` | `require_operation_step_up` |

Both live here, and a single resource legitimately carries both — the window on its `GET`, the
per-operation challenge on its `PATCH`. That is the intended shape, not a redundancy: the two
gates happen to report the same tier while answering different questions, one about a **state**
and one about an **act**.

A **mutation must never be gated on an elevation window.** A window authorizes a *period*, not
an *act* — so one step-up would authorize every write until it expires. That is not a smaller
version of the same control; it is a different one.

See [`OPERATION-STEPUP.md`](OPERATION-STEPUP.md) for the per-operation mechanism: what it
consumes, why the idempotency lookup must run before it, and why the hook reads the body with
`get_media()` and never `stream.read()`.

---

## Where this sits

Assurance is check two of C-033's five:

```
identity      who is this            IDENTITY.md
assurance     how recently proved    <- this document
entitlement   what class of thing
ownership     is this object theirs  the host's own tables
domain        is this state legal    the host's own rules
```

Each answers separately, and that separation is the whole design. A caller refused by one should
never receive the answer another would have given.

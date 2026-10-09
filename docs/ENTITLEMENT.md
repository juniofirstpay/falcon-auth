# ENTITLEMENT.md — what class of thing may they do

[Identity](IDENTITY.md) says who the caller is. [Assurance](ASSURANCE.md) says how recently they
proved it. Entitlement answers:

> Is this caller allowed to perform **this kind of operation** at all?

In one sentence: **a job title, and a list of what each job title unlocks.** You do not check
whether *Riya* may create an order — you check whether a **retail user** may, and separately
whether Riya is one.

Note the words "class of thing". Entitlement does **not** answer whether this is *her* order —
that is ownership, and it reads the host's own tables. Entitlement is about the *kind* of act,
never about a particular object.

---

## Three levels, and why there are three

C-038 fixes the vocabulary:

| Level | Owned by | Character | Example |
|---|---|---|---|
| **grant** | **auth**, estate-wide | the slowest-moving thing in the system | `RETAIL_USER` |
| **entitlement** | **this service** | what a principal holds *here* | `ORDER_CREATE` |
| **capability** | **the route** | what one endpoint demands | `orders:create` |

The middle level is the one people ask about. Why not map grants straight to routes?

**Because the two ends move at completely different speeds.** A service adds and retires routes
constantly; the estate's grant vocabulary must not move when it does. With the middle level, a
new route means a new **capability** row in this service — and **never** a change to auth's
vocabulary. That separation is the entire reason it exists.

---

## The pieces

| File | Job |
|---|---|
| `entitlement/resolver.py` | turn an authenticated user into a `Principal` holding grants |
| `entitlement/enforcer.py` | decide whether those grants open a capability |
| `entitlement/flatness.py` | build-time checks the policy engine cannot make itself |
| `adapters/hooks.py` · `require` | the Falcon gate |

---

## Phase 1 — boot

```
your app startup
│
├─ build_enforcer(registry, expansion=None)                     enforcer.py
│  │
│  │   registry   capability -> the entitlements that open it, ANY-OF
│  │                {"orders:create": "ORDER_CREATE",
│  │                 "txn:read": ["TXN_READ", "SUPPORT_READ"]}
│  │
│  │   expansion  grant -> the entitlements it expands to
│  │                None today: auth emits no grants and the platform
│  │                register is deliberately empty
│  │
│  ├─ normalise_registry(registry)
│  │     a bare string becomes a one-element list
│  │     empty string / empty list / list of blanks  ──►  ValueError at import
│  │
│  ├─ one `p` row per entitlement per capability      the gate
│  └─ one `g` row per entitlement per grant           the expansion
│
├─ verify_policy(registry, expansion, grant_register=[...])     flatness.py
│  ├─ check_flatness       a name on both sides?      ──►  FlatnessError
│  └─ check_grants_registered   an unlisted grant?    ──►  UnregisteredGrant
│
├─ AuthServiceResolver(client, cache, veto=...)                 resolver.py
│
└─ @falcon.before(require(enforcer, resolver, "orders:create"))
      capability has no registry row?  ──►  ValueError AT DECORATION TIME
```

Note where that last check fires: **at import**, when the module is loaded, with a human
watching. A route asking for a capability nobody registered is a wiring bug, and absence must
never quietly mean ungated.

---

## Phase 2 — a request arrives

```
the require(...) hook runs
│
├─ user = req.context.user
│     None?  ──►  Unauthenticated
│            never "anonymous is fine" -- an unauthenticated request reaching a
│            gated route is a mounting error, not a permission question
│
├─ resolver.resolve(user, consequential=False)                  resolver.py
│  │
│  ├─ session_ref = user.get("sid")
│  │     absent  ──►  CapabilityDenied
│  │             an identity we cannot ask about; fail closed rather than guess
│  │
│  ├─ client.fetch(session_ref, user_ref=user.id)
│  │     LIVE, always -- there is no warm cache
│  │     │
│  │     └─ AuthzUnavailable?
│  │          consequential  ──►  re-raise, fail closed
│  │          routine        ──►  serve the last-good copy, logged loudly
│  │                              none stored?  ──►  re-raise
│  │
│  ├─ _compose(user_ref, grants)
│  │     apply the local veto -- the ONLY subtractive lever in the model
│  │
│  └─ Principal(user_ref, entitlements=<the grants>, session_ref, trust levels)
│
├─ req.context.principal = principal
│
└─ enforcer.allows_principal(principal, "orders:create")        enforcer.py
   │
   └─ opened_by(subjects, capability)
      │   for each subject, in the caller's order:
      │      casbin: g(subject, entitlement) && entitlement -> capability
      │      first match wins, and the loop RECORDS which one
      │
      ├─ something matched  ──►  the handler runs
      └─ nothing matched    ──►  CapabilityDenied
```

---

## The engine, in one line

```
m = g(r.sub, p.sub) && r.obj == p.obj
```

Read it as: **the subject, expanded through the `g` rows, must reach an entitlement that a `p`
row pairs with the capability being asked for.**

```
  grant            entitlement           capability
  RETAIL_USER  ──g──►  ORDER_CREATE  ──p──►  orders:create
```

Three things about this are worth pausing on.

**No user identifier ever enters the engine.** `r.sub` is a grant, never a person. That is what
makes the policy a pure function of the registry — built once at import, shared across every
request without a lock.

**The model text is a platform artifact,** copied verbatim from `registry/AUTHZ-MODEL.md` and
never re-authored per service. Casbin is a mandated dependency (the platform's first library
mandate). If each service could write its own matcher, "one two-layer policy" would be a
suggestion.

**Adding the `g` layer was non-breaking,** which is not obvious and was verified rather than
assumed: casbin's default role manager counts `name1 == name2` as a link, so `enforce(entitlement,
capability)` keeps answering identically once `g` rows exist. All 23 existing tests passed
untouched through the change.

---

## Any-of: one capability, several ways in

```python
{"txn:read": ["TXN_READ", "SUPPORT_READ"]}
```

A customer reading their own transactions and a support agent reading them both pass. **One
row**, listing both — not two capabilities, which would split the route in two and make "who can
reach this?" unanswerable from a single place.

This falls out of the policy effect rather than needing a mechanism: each entitlement becomes its
own `p` row, and `some(where (p.eft == allow))` already means "any matching row allows".

The other direction — one entitlement opening many capabilities — was always expressible as
several rows naming the same entitlement. Twelve entitlements govern two to four capabilities
each today.

Alternatives are listed **explicitly**: no wildcards, no prefix matching, no role transitivity on
this axis. And a judgement call travels with it: if one alternative's blast radius differs from
another's, it belongs to a **different capability**, not the same row.

---

## Two build-time checks the engine cannot make

### Flatness

`g` is transitive in casbin, up to `maxHierarchyLevel`. Given `g, A, B` and `g, B, C`, casbin
resolves **A to C's capabilities** and raises no objection. That is reproduced as a passing test
sitting right next to the lint that rejects it.

So "exactly two hops" is a property the policy **can** violate and the engine will **never**
report. The lint rejects three shapes, which are three ways of saying one thing — *a name is a
grant or an entitlement, never both*:

```
g, A, A                          a self-link
g, A, B  +  g, B, C              B is a target and a source, so A chains to C
A is a grant AND an entitlement  the two layers stop being distinguishable
```

What a third hop costs: "which routes does this grant open" becomes unanswerable without walking
a graph, and the answer changes when a row is added somewhere else entirely.

### The grant register

Every grant in a `g` row must be listed in the platform register, and an unlisted one **refuses
boot**.

A grant is allocated by the authority and immutable once allocated. A service naming one that is
not registered has either invented authority's vocabulary or is holding a row against a retired
name. Both resolve to *"this principal holds nothing"* at runtime — which reads as a permissions
problem and is really a deployment fault.

**An empty register is the honest state today,** and it is self-consistent: nothing grants yet,
so the expansion must be empty too, and the check enforces exactly that.

> The register is **passed in**, not read. `registry/GRANTS.md` lives in another repository and
> this package reads no files and no configuration.

---

## Four decisions worth knowing

### Entitlements are resolved server-side, never read off the token

This is the load-bearing one. A claim the service acts on is authorization data whatever it is
named — and if it rides the token, **revocation becomes token lifetime**. Suspend a compromised
user and they keep transacting until it expires. For a service that moves money that is the wrong
failure mode.

It is also why [identity's](IDENTITY.md) claim allowlist exists: to make the shortcut unreachable
by construction.

### The veto is the only way to take something away

Grants compose as a **union** and the model has **no deny effect** anywhere. So a suspension can
never be expressed as a grant, or as the absence of one — it is this service's own record of
whether the subject is active, suspended or closed.

A host with no subject aggregate of its own supplies no veto, and should say so in its build
status rather than pretend the layer is enforced.

### `opened_by` records *which* subject opened the route

A boolean cannot tell C-032's audit line which grant was responsible, and that is exactly what an
audit trail is for when a principal holds several. `allows()` is defined in terms of `opened_by()`,
so the two can never disagree — asserted in the tests.

Ordering cannot change the **verdict** (union, no deny effect) — only which of several sufficient
subjects gets recorded.

### Consequential operations fail closed

Every trust read is live. What `consequential=True` selects is the behaviour when the source is
**down**: a routine read may serve the last-good copy, loudly logged; a consequential one
re-raises. Where the entitlement *is* the control, degrading to a stale answer is the wrong
direction.

---

## Who is calling, and whose records: actor types and grant kinds (C-052, C-053)

Before the capability check, `require()` answers two questions the feed makes answerable
(`registry/TRUST-CONTEXT.md`):

**1. Is this kind of caller admitted here?**
- **The declaration:** every USER route declares the actor types it admits, at mount:
  `mount(..., actor_types={"CUSTOMER"})`, `{"CUSTOMER", "OPERATOR"}`, or `{"OPERATOR"}`. There is
  no "any" (C-052 §5), and the server refuses to start on a USER route that declares none.
- **Operator-only routes** live under `/v<n>/ops/` or refuse to mount (C-052 §8, RUL-178).
- **The caller's actor type** comes from the feed, never from grants (§3).
- **Not admitted** ⇒ the route not-found, `404 PLAT0006`, rendered by the host's router miss, so
  it's byte-identical to a missing route (§6, RUL-158).
- **An operator on a customer route** is admitted only as a **shadow session** (C-053 §9).

**2. Which grants count?** Every grant has a **kind** (`registry/GRANTS.md` rule 6), and
`Subject-Ref` selects it. ⛔ Kinds never mix in one decision:

| Route admits | `Subject-Ref` | Grants that count |
|---|---|---|
| `CUSTOMER` (± `OPERATOR`) | absent | the caller's `self` grants |
| `CUSTOMER` (± `OPERATOR`) | present | the caller's **live** `subject` delegations **for that subject** |
| only `OPERATOR` | absent | the caller's `unbound` grants. Which records they reach is the service's (C-054) |
| only `OPERATOR` | present | none: refused (RUL-177) |

- **A shadow session** must send `Subject-Ref` naming its one delegation's subject (H2).
- **Every refusal about a subject** is one answer, `404 PLAT0008`, byte-identical: unknown,
  undelegated, expired, a shadow session's missing or wrong header, a header on an ops route. The
  response never reveals whether a subject exists.
- **A grant outside the session's actor type**, or one the register doesn't list, is a
  configuration mismatch: `503` (C-052 §7).

**The wiring:**
```python
enforcer = build_enforcer(REGISTRY, expansion=EXPANSION, grants={
    "CUSTOMER_GRANT": ("CUSTOMER", "self"),
    "DELEGATED_CUSTOMER_GRANT": ("CUSTOMER", "subject"),
    "AGENT_GRANT": ("OPERATOR", "unbound", "AGENT"),
})                                   # the register, copied from registry/GRANTS.md -- required
mount(registry, app, "/v1/orders/{id}", Orders(), plane=USER, actor_types={"CUSTOMER", "OPERATOR"})
```

**What the service still owns:**
- **Ownership (H3):** the object's owner equals `principal.subject_ref`, or the caller when it's
  `None`.
- **The idempotency key (H6):** include `principal.subject_ref`.
- **The audit line (H7):** `principal.opened_by` and `principal.opened_by_delegation`, with the
  actor and the subject.
- **The local veto on the subject (C-053 §10).**
- **`Vary: Subject-Ref`** (H5) is set for you.

**While auth's feed lacks `actor_type`:** `HttpTrustContextClient(...,
assume_customer_actor_type=True)` reads it as `CUSTOMER`. This is a recorded C-052 deviation
(RUL-162), off by default and logged; an assumed customer never opens an operator-only route.

---

## The dev escape hatch, and the trap inside it

`GrantAllResolver` gives every caller a fixed entitlement set without contacting auth. It exists
because a developer with no auth service reachable otherwise gets `503` on every gated route —
correct in production, useless locally.

**It must be gated behind an explicit, default-off flag, and logged loudly at startup.** Wiring
it in production makes every authenticated caller a superuser.

The instructive part is what it deliberately does **not** do: it keeps each caller's own
`user_ref`. Resolving everyone to one fixed dev subject would be simpler and is a trap — ownership
compares the caller's ref to the object's owner, so a single-subject resolver makes every object
look like it belongs to the same person. Ownership bugs then become **invisible in dev and appear
in production**.

Grant-all is about entitlements only. Identity stays real.

---

## Where this sits

Entitlement is check three of C-033's five:

```
identity      who is this            IDENTITY.md
assurance     how recently proved    ASSURANCE.md
entitlement   what class of thing    <- this document
ownership     is this object theirs  the host's own tables
domain        is this state legal    the host's own rules
```

The last two are **not** in this package and cannot be: they read the host's data. What the
package supplies is the principal they scope against. A consumer that assumes all five arrive
will be missing two.

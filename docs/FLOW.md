# FLOW.md — what calls what, and when

How the plane system executes: once at startup, and once per request. Function names are exact
and the file each lives in is marked, so this can be read beside the code.

Two conventions govern the shape:

- **C-006** — one plane per endpoint, refused at startup.
- **C-038** — the five-step resolution at request time.
- **C-060** (`v30`) — five planes; a plane holds a closed set of methods named by how they are
  checked, and **a route declares exactly one**; the wrong-plane search counts only credentials
  verifiable without I/O. `CLIENT` is the identity provider's, which does not use this package
  (RUL-157), so it is refused here.

---

## The pieces

| Module | Owns |
|---|---|
| `planes.py` | the vocabulary: five planes, the methods each holds, the I/O-free methods the search may verify, and the resource-service inverse |
| `adapters/routing.py` | the registry, `mount()`, and the boot sweep — everything decided at startup |
| `adapters/middleware.py` | the per-request assertion, and the wrong-plane 404 |

The split matters: **`routing.py` decides which door a route is. `middleware.py` checks, per
request, that the caller brought the key for that door.**

---

## Phase 1 — boot, runs once

```
your app startup
│
├─ PlaneRegistry(allow_dev_routes=False)                      routing.py
│
├─ PlaneAuthenticationMiddleware(registry, authenticators=...)  middleware.py
│     ├─ an authenticator on CLIENT, or off C-060's table?  ──► raise ConventionDeviation
│     ├─ two planes' authenticators on one carrier?         ──► raise PlaneConflict
│     └─ stores registry, authenticators, not_found_error (default: falcon.HTTPRouteNotFound)
│
├─ falcon.asgi.App(middleware=[middleware])
│
├─ mount(registry, app, path, resource, plane=..., credential=None)   routing.py
│  │
│  ├─ 0. credential= not a single name?      ──► raise PlaneConflict   one per route (C-060 §3)
│  │
│  ├─ 1. dev_only and not allow_dev_routes?  ──► return False    route never exists
│  │
│  ├─ 2. responder_methods(resource, suffix)                  routing.py
│  │        scans dir(resource) for on_get / on_post / on_get_refund
│  │        └─ none found?                   ──► raise PlaneConflict
│  │
│  ├─ 3. for each method found:
│  │       registry.register(plane, method, path, type(resource))
│  │       │
│  │       ├─ plane not in PLANES?                 ──► raise PlaneConflict
│  │       ├─ plane is CLIENT?                     ──► raise PlaneConflict   identity provider's only
│  │       ├─ PUBLIC naming a credential?          ──► raise PlaneConflict   no principal (C-060 §5)
│  │       ├─ PUBLIC with no stated reason?        ──► raise PlaneConflict
│  │       ├─ version_of(path)                                routing.py
│  │       │     "/v1/orders" -> "v1"   ·   "/webhooks/sms" -> None
│  │       ├─ endpoint already on another plane?   ──► raise PlaneConflict
│  │       ├─ class already on another plane?      ──► raise PlaneConflict
│  │       ├─ class already on another version?    ──► raise PlaneConflict
│  │       └─ store in _by_endpoint · _by_class · _version_by_class
│  │
│  └─ 4. app.add_route(path, resource)      ◄── only now, after every check passed
│
├─ verify_app(app, registry)                                  routing.py
│  │
│  ├─ falcon.inspect.inspect_routes(app)    ◄── the one deferred falcon import
│  ├─ skip exempt_paths                         /health · /ready, outside the plane system
│  ├─ skip responder.internal                   Falcon's auto-generated 405s, 24 per route
│  ├─ registry.registration_of(method, path) is None?  ──► collect
│  └─ anything collected?                   ──► raise UnregisteredRoute, naming them all
│
└─ middleware.verify()                                       middleware.py
   └─ every non-PUBLIC route resolves to exactly ONE authenticator on its plane?
        no authenticator for the plane       ──► raise UnregisteredRoute
        a pin that is unknown or off-plane   ──► raise UnregisteredRoute
        unpinned on a plane with two         ──► raise UnregisteredRoute   it must pin
```

### Two orderings that are not arbitrary

**`register()` runs before `add_route()`.** If it were the other way round, a rejected mount
would leave the app serving a route the registry disowns — which is precisely a route with no
plane, the thing the registry exists to prevent.

**`verify_app()` runs after every mount.** It is the net under `mount()`: it catches a bare
`app.add_route` elsewhere in the codebase, which is the failure the registry cannot see from
the inside.

---

## Phase 2 — every request

```
HTTP request arrives
│
├─ Falcon routes it
│     no route matches?  ──► Falcon's own 404; the middleware is NEVER called
│
└─ middleware.process_resource(req, resp, resource, params)   middleware.py
   │
   │   process_request would be too early -- it runs BEFORE routing, so there is no
   │   uri_template to look a plane up by.
   │
   ├─ template = req.uri_template          "/v1/orders/{order_id}"
   ├─ method   = req.method.upper()        "GET"
   │
   ├─ registry.registration_of(method, template)              routing.py
   │  │
   │  └─ None?
   │     ├─ registry.registered_methods(template) non-empty?  routing.py
   │     │     ──► return, stand aside         wrong verb; Falcon's 405 is correct
   │     ├─ template in exempt_paths?
   │     │     ──► return, stand aside         an unregistered probe (RUL-033)
   │     └─ otherwise
   │           ──► raise UnregisteredRoute     500, nothing in the body
   │
   ├─ plane = registration.plane
   │
   ├─ plane == PUBLIC?
   │     ├─ self._stamp(req, PUBLIC, None)
   │     └─ return          no caller principal; evidence is payload (C-060 §5)
   │
   ├─ entry = self._accepted(registration)                    middleware.py
   │     ├─ pinned (credential=)  ──► that authenticator; unknown or off-plane ──► UnregisteredRoute
   │     └─ unpinned              ──► the ONE authenticator on the plane;
   │                                  none, or two      ──► UnregisteredRoute   500
   │
   ├─ STEPS 1-2 ── await entry.attempt(req)          ◄── YOUR authenticator
   │     ├─ raises            ──► propagates, NOT caught         ──► 401
   │     ├─ returns principal ──► self._stamp(req, plane, entry, principal)
   │     │                       return                          ──► handler runs, 200
   │     └─ returns None      ──► fall through
   │
   ├─ STEPS 3-4 ── self._find_foreign_credential(req, plane)   middleware.py
   │     │
   │     └─ for each authenticator on ANOTHER plane, whose method is JWT or MTLS
   │           (planes.SEARCHABLE_METHODS -- verifiable without I/O, C-060 §6):
   │           ├─ raises            ──► stop: one verification spent (Q88)  ──► step 5
   │           ├─ returns None      ──► continue
   │           ├─ a forwarding hop  ──► continue      transport, never a caller (C-060 §6)
   │           └─ returns principal ──► foreign found
   │     │
   │     └─ found?  ──► self._refuse_wrong_plane(...)           middleware.py
   │                    ├─ logger.warning("plane_mismatch", ...)
   │                    ├─ self._on_plane_mismatch(...)   ◄── YOUR hook, the flag
   │                    └─ raise self._not_found_error()  ──► 404 PLAT0006, the router miss
   │
   └─ STEP 5 ── raise Unauthenticated                           ──► 401
```

---

## The exits

| Exit | Reached when | Result |
|---|---|---|
| `return` after `_stamp` | the route's credential is valid, or the plane is PUBLIC | **200** — handler runs |
| authenticator raises | step 2 — present but invalid; uncaught by design | **401** |
| `_refuse_wrong_plane` | step 4 — a valid, I/O-free credential for a different plane | **404 `PLAT0006`** + log + flag |
| `raise Unauthenticated` | step 5 — nothing usable at all, including a credential of the same plane the route doesn't accept, or one that would need a lookup | **401** |
| `raise UnregisteredRoute` | route never registered, or it resolves to no single credential | **500**, empty body |

---

## Where your own code is called

Three seams, and only three:

1. **your authenticators** — called once as the route's credential, then (JWT and mTLS only) during
   the step-3 search.
2. **`self._on_plane_mismatch(template, plane, method)`** — your flag. Fires only on step 4.
3. **`self._not_found_error()`** — raised on step 4. Defaults to Falcon's own
   `HTTPRouteNotFound`, so it renders exactly as your router miss does.

Everything else is the package.

### The authenticator contract is tri-state

```
returns a principal   a credential of this kind is present and VALID
returns None          no credential of this kind is present -- says nothing about others
raises                a credential of this kind is present and INVALID
```

Both collapses break the resolution table:

- Fold **invalid into None** and step 2 becomes unreachable. A forged token falls through to the
  step-3 search and is answered 404 — telling the holder that a bad token and no token are
  different things, and that the endpoint sits on some other plane.
- Fold **absent into a raise** and step 3 becomes unreachable: every wrong-plane credential
  would end at 401, and the 404 rule could never fire.

---

## Worked example

Two routes, mounted at boot:

```python
mount(registry, app, "/v1/orders/{order_id}",        OrdersResource(), plane=planes.USER)
mount(registry, app, "/v1/orders/{order_id}:refund", RefundResource(), plane=planes.SERVICE,
      suffix="refund")
```

| Who knocks | On which route | Path through the flow | Result |
|---|---|---|---|
| App user, valid JWT | USER route | steps 1-2, the route's credential returns a principal | **200** |
| App user, expired JWT | USER route | step 2, authenticator raises, not caught | **401** |
| App user, no credential | USER route | primary absent, no foreign credential found | **401** |
| Payments backend, valid cert | USER route | primary absent, step 3 finds valid MTLS | **404 `PLAT0006`** |
| A callback source's valid one-shot token | USER route | primary absent; a one-shot token needs a lookup, so it is absent to the search | **401** |
| App user via the gateway, no token | USER route | primary absent; the gateway's certificate is a forwarding hop (`transport_peers`) | **401** |
| Anyone, garbage in a header | USER route | foreign attempt raises, swallowed, falls to step 5 | **401** |
| Payments backend, valid cert | SERVICE route | steps 1-2, MTLS is the primary | **200** |

Note rows four and five. A **valid** credential for another plane is a mismatch and gets a 404.
**Garbage** is a caller with no usable credential — step 5, a 401. If nonsense counted as a
mismatch, anyone could map the estate by sending junk and watching which paths answered 404.

---

## Why step 4 answers 404 and not 403

C-038 supersedes C-006's `403 PLAT0107` here.

A 403 means *this exists, but not for you* — a confirmation. Give an attacker holding a stolen
user token a 403 and they can map the service plane with nothing but status codes:

```
/v1/orders/123            -> 200   theirs
/v1/internal/settlements  -> 403   "that exists"
/v1/internal/ledger       -> 403   "so does that"
/v1/internal/nonsense     -> 404   "that one does not"
```

With 404 everywhere, all four probes look identical and nothing is learned.

**A 404 with a distinctive body is a 403 in disguise.** If the mismatch returned
`{"error": "wrong_plane"}` while a path that does not exist returned `PLAT0006`, the attacker reads
the body instead of the status and the leak is back. The same goes for answering with the
record-level `PLAT0008`: a caller could tell an existing route from a missing one. So the answer is
the **route** not-found, `404 PLAT0006`, byte-identical to a router miss (RUL-158).

That is why `not_found_error` defaults to **`falcon.HTTPRouteNotFound`** — the exception Falcon
itself raises when no route matches. Whatever your app renders for a router miss is what a
wrong-plane caller sees, identical by construction rather than by a comment asking someone to keep
them in step. `tests/test_credentials.py` asserts the two bodies are byte-equal. Override it only
with something that renders exactly as that does.

The operator still finds out: the mismatch is logged at warning level and passed to
`on_plane_mismatch`. The caller learns nothing; you learn everything.

---

## Three Falcon behaviours the design had to accommodate

Each was established by running Falcon 4.2, not by reading about it.

**`process_resource` is the right hook.** `process_request` runs before routing, so
`req.uri_template` is not yet set and there is no key to look the plane up by.

**Falcon skips `process_resource` entirely when no route matches.** An unrouted path never
reaches the middleware, so that case needs no branch.

**Falcon runs `process_resource` for a wrong-verb request.** A `DELETE` against a GET-only
resource arrives here, and the registry has no row for that pair — indistinguishable, without
help, from a route that was never registered. `registered_methods()` tells the two apart, so a
clean 405 does not become a 500.

A fourth, in `verify_app`: **`inspect_routes` reports all 24 HTTP methods for every route**,
because Falcon generates a 405 responder for each method a class does not implement. They carry
`internal=True`. Without filtering on that flag the boot sweep flags every route on the app.

# FLOW.md — what calls what, and when

How the plane system executes: once at startup, and once per request. Function names are exact
and the file each lives in is marked, so this can be read beside the code.

Two conventions govern the shape:

- **C-006** — one plane per endpoint, refused at startup.
- **C-038** — one authentication method per plane, and a five-step resolution at request time.

---

## The pieces

| Module | Owns |
|---|---|
| `planes.py` | the vocabulary: four planes, the method each accepts, and the inverse |
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
├─ PlaneAuthenticationMiddleware(registry, ...)               middleware.py
│     stores registry, authenticators, not_found_error
│
├─ falcon.asgi.App(middleware=[middleware])
│
├─ mount(registry, app, path, resource, plane=...)            routing.py
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
└─ verify_app(app, registry)                                  routing.py
   │
   ├─ falcon.inspect.inspect_routes(app)    ◄── the one deferred falcon import
   ├─ skip exempt_paths                         /health · /ready, outside the plane system
   ├─ skip responder.internal                   Falcon's auto-generated 405s, 24 per route
   ├─ registry.registration_of(method, path) is None?  ──► collect
   └─ anything collected?                   ──► raise UnregisteredRoute, naming them all
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
   │     └─ empty?
   │           ──► raise UnregisteredRoute     500, nothing in the body
   │
   ├─ plane = registration.plane
   │
   ├─ plane == PUBLIC?
   │     ├─ self._stamp(req, PUBLIC, None, None)
   │     └─ return          no credential demanded, and none inspected
   │
   ├─ primary = self._primary_for(plane, template)            middleware.py
   │     ├─ methods_for(plane)                                planes.py
   │     │     USER -> {JWT}   SERVICE -> {MTLS}   CALLBACK -> {HMAC, ONE_SHOT_TOKEN}
   │     └─ a method with no authenticator supplied?
   │           ──► raise UnregisteredRoute     500; a route nobody could ever open
   │
   ├─ STEPS 1-2 ── for candidate in sorted(primary):
   │     await self._authenticators[candidate](req)     ◄── YOUR function
   │     │
   │     ├─ raises            ──► propagates, NOT caught         ──► 401
   │     ├─ returns principal ──► self._stamp(req, plane, candidate, principal)
   │     │                       return                          ──► handler runs, 200
   │     └─ returns None      ──► try the next candidate, then fall through
   │
   ├─ STEPS 3-4 ── self._find_foreign_credential(req, primary) middleware.py
   │     │
   │     └─ for candidate, owning_plane in sorted(PLANE_BY_METHOD.items()):   planes.py
   │           skip if already in primary, or if no authenticator was supplied for it
   │           await self._authenticators[candidate](req)  ◄── YOUR function
   │           ├─ raises            ──► swallowed, continue      broken is not a mismatch
   │           ├─ returns None      ──► continue
   │           └─ returns principal ──► return (candidate, owning_plane)
   │     │
   │     └─ found?  ──► self._refuse_wrong_plane(...)           middleware.py
   │                    ├─ logger.warning("plane_mismatch", ...)
   │                    ├─ self._on_plane_mismatch(...)   ◄── YOUR hook, the flag
   │                    └─ raise self._not_found_error()  ◄── YOUR exception   ──► 404
   │
   └─ STEP 5 ── raise Unauthenticated                           ──► 401
```

---

## The exits

| Exit | Reached when | Result |
|---|---|---|
| `return` after `_stamp` | primary credential valid, or the plane is PUBLIC | **200** — handler runs |
| authenticator raises | step 2 — present but invalid; uncaught by design | **401** |
| `_refuse_wrong_plane` | step 4 — valid credential for a different plane | **404** + log + flag |
| `raise Unauthenticated` | step 5 — nothing usable at all | **401** |
| `raise UnregisteredRoute` | route never registered, or plane has no authenticator | **500**, empty body |

---

## Where your own code is called

Three seams, and only three:

1. **`self._authenticators[method](req)`** — your credential checkers. Called once per primary
   method, then again per foreign method during the step-3 search.
2. **`self._on_plane_mismatch(template, plane, method)`** — your flag. Fires only on step 4.
3. **`self._not_found_error()`** — your not-found exception, raised on step 4.

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
- Fold **absent into a raise** and step 3 becomes unreachable, which breaks CALLBACK — the one
  plane that legitimately tries two methods.

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
| App user, valid JWT | USER route | steps 1-2, first candidate returns a principal | **200** |
| App user, expired JWT | USER route | step 2, authenticator raises, not caught | **401** |
| App user, no credential | USER route | primary absent, no foreign credential found | **401** |
| Payments backend, valid cert | USER route | primary absent, step 3 finds valid MTLS | **404** |
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
`{"error": "wrong_plane"}` while a genuine missing order returned `{"code": "ORDR0404"}`, the
attacker reads the body instead of the status and the leak is back.

That is why `not_found_error` is a **required argument with no default**. The middleware raises
*your* exception — the same one your handler raises when a record genuinely does not exist — so
the two responses are identical by construction rather than by a comment asking someone to keep
them in step. `tests/test_adapters_middleware.py` asserts it.

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

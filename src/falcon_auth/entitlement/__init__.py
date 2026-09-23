"""Part 4 — entitlement: what class of thing may this principal do.

**Three levels**, per C-038:

    grant         auth's word — coarse, estate-wide, the slowest-moving
    entitlement   the service's word — fine-grained, what a principal holds here
    capability    the route's word — what an endpoint demands, one `noun:verb` per endpoint

Two registries per service — **grant → entitlement** (the expansion) and **capability →
entitlement** (which holding opens which route). The point of the split: a service adding or
retiring routes changes its own entitlements and capabilities and never the grant vocabulary
at auth.

**Entitlements are resolved server-side, never read off the token.** A claim the service acts
on is authorization data whatever it is named, and if it rides the token then revocation becomes
token lifetime.

**The engine and the model are the platform's.** casbin is a mandated stack element and the
model text is a single platform artifact (`registry/AUTHZ-MODEL.md` §2), never re-authored here.
Both layers live in one policy set: `g, <grant>, <entitlement>` and `p, <entitlement>,
<capability>`, exactly two hops, flat — enforced by a build-time lint, because casbin chains a
third silently.

**This is the only part that decides.** The others establish.

The error vocabulary lives at the package root: `trustcontext` raises two of them, and
`SessionMiss` subclasses `CapabilityDenied` in a way that cannot be split across modules.
"""

from __future__ import annotations

from .enforcer import MODEL_TEXT, CapabilityEnforcer, build_enforcer
from .resolver import (
    AuthenticatedUser,
    AuthServiceResolver,
    GrantAllResolver,
    Resolver,
)

__all__ = (
    "AuthServiceResolver",
    "AuthenticatedUser",
    "CapabilityEnforcer",
    "GrantAllResolver",
    "MODEL_TEXT",
    "Resolver",
    "build_enforcer",
)

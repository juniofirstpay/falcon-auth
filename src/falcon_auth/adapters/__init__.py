"""The Falcon integration — the only place in this package that imports Falcon.

Everything else is driven by plain values, so the cores stay exercisable without a web framework
and a non-Falcon consumer could use them unchanged.

Named `adapters` rather than `falcon` deliberately: a subpackage called `falcon` inside a
package that imports `falcon` resolves correctly under Python 3's absolute imports but reads
ambiguously and confuses tooling.

**The two hook families disagree about stray keyword arguments, and that is not yet
reconciled.** `falcon.before(action, *args, **kwargs)` forwards every extra keyword to the hook,
including the `is_async=True` that callers across this ecosystem still pass believing Falcon
consumes it — Falcon 3 did; Falcon 4 detects hooks automatically and the parameter is gone.

    east-west hooks (ported here)   STRICT `(req, resp, resource, params)`
                                    passing `is_async=True` raises TypeError — a 500 on a
                                    gated route. Consumers must omit it.
    entitlement hooks (not yet)     absorb `*_a, **_kw` and read nothing from them

The east-west hooks are strict **because that is how they behave today**, and A1 is a
behaviour-identical port. Making the two families agree is a deliberate later change, not a
tidy-up smuggled into the port.

Modules:
    hooks.py            require (entitlement) · require_elevated (assurance)
                        require_service_scope · require_callback (east-west)
                        principal_from_request
    errors.py           register_error_handlers · render_svcplane_error
    authenticators.py   RemoteJWKSAuthenticator
    routing.py          PlaneRegistry · mount · verify_app -- one plane per endpoint,
                        refused at startup (C-006)
    middleware.py       PlaneAuthenticationMiddleware -- the per-request assertion that the
                        caller's credential matches the endpoint's plane, and the
                        wrong-plane 404 (C-038)
"""

from __future__ import annotations

from .authenticators import RemoteJWKSAuthenticator
from .errors import register_error_handlers, render_svcplane_error
from .middleware import (
    AUTH_METHOD_ATTR,
    AUTH_PRINCIPAL_ATTR,
    PLANE_ATTR,
    Authenticator,
    PlaneAuthenticationMiddleware,
)
from .routing import (
    DEFAULT_PROBE_PATHS,
    Endpoint,
    PlaneConflict,
    PlaneRegistry,
    Registration,
    UnregisteredRoute,
    mount,
    verify_app,
)
from .hooks import (
    PRINCIPAL_ATTR,
    HookFn,
    RefExtractor,
    require,
    principal_from_request,
    require_callback,
    require_elevated,
    require_service_scope,
)

__all__ = (
    "AUTH_METHOD_ATTR",
    "AUTH_PRINCIPAL_ATTR",
    "Authenticator",
    "DEFAULT_PROBE_PATHS",
    "Endpoint",
    "HookFn",
    "mount",
    "PLANE_ATTR",
    "PlaneAuthenticationMiddleware",
    "PlaneConflict",
    "PlaneRegistry",
    "PRINCIPAL_ATTR",
    "principal_from_request",
    "RefExtractor",
    "register_error_handlers",
    "Registration",
    "RemoteJWKSAuthenticator",
    "render_svcplane_error",
    "require",
    "require_callback",
    "require_elevated",
    "require_service_scope",
    "UnregisteredRoute",
    "verify_app",
)

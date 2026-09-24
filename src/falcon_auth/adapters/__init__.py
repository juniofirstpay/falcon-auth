"""The Falcon integration — the only place in this package that imports Falcon.

Everything else is driven by plain values, so the cores stay exercisable without a web framework
and a non-Falcon consumer could use them unchanged.

Named `adapters` rather than `falcon` deliberately: a subpackage called `falcon` inside a
package that imports `falcon` resolves correctly under Python 3's absolute imports but reads
ambiguously and confuses tooling.

**Every hook here absorbs stray keyword arguments, and that is deliberate.**
`falcon.before(action, *args, **kwargs)` forwards every extra keyword straight to the hook,
including the `is_async=True` that callers across this ecosystem still pass believing Falcon
consumes it — Falcon 3 did; Falcon 4 detects hooks automatically and the parameter is gone.

A strict signature therefore raises `TypeError` and answers **500 on a gated route**, where a
401 or 403 belongs. Reproduced on Falcon 4.2: the same east-west route answers 500 with
`is_async=True` and 401 without it, so the failure is invisible until someone writes the form
the whole estate writes.

The east-west hooks shipped strict because A1 was a behaviour-identical port and reconciling
the families was recorded as a later change rather than a tidy-up smuggled into the port. This
is that change; all four now take `*_a, **_kw`.

Nothing is read from them, on purpose: a gate that varied with decorator kwargs would be a
second, invisible configuration surface.

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
    DEFAULT_OPERATION_HEADER,
    PRINCIPAL_ATTR,
    HookFn,
    RefExtractor,
    require,
    principal_from_request,
    require_callback,
    require_elevated,
    require_operation_step_up,
    require_service_scope,
)

__all__ = (
    "AUTH_METHOD_ATTR",
    "AUTH_PRINCIPAL_ATTR",
    "Authenticator",
    "DEFAULT_OPERATION_HEADER",
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
    "require_operation_step_up",
    "require_service_scope",
    "UnregisteredRoute",
    "verify_app",
)

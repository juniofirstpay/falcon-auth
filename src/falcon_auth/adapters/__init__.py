"""The Falcon integration — the only place in this package that imports Falcon.

Everything else is driven by plain values, so the cores stay exercisable without a web framework
and a non-Falcon consumer could use them unchanged.

⚠ Named `adapters` rather than `falcon` deliberately: a subpackage called `falcon` inside a
package that imports `falcon` resolves correctly under Python 3's absolute imports but reads
ambiguously and confuses tooling.

⚠ **The two hook families disagree about stray keyword arguments, and that is not yet
reconciled.** `falcon.before(action, *args, **kwargs)` forwards every extra keyword to the hook,
including the `is_async=True` that callers across this ecosystem still pass believing Falcon
consumes it — Falcon 3 did; Falcon 4 detects hooks automatically and the parameter is gone.

    east-west hooks (ported here)   STRICT `(req, resp, resource, params)`
                                    ⛔ passing `is_async=True` raises TypeError — a 500 on a
                                    gated route. Consumers must omit it.
    entitlement hooks (not yet)     absorb `*_a, **_kw` and read nothing from them

⭐ The east-west hooks are strict **because that is how they behave today**, and A1 is a
behaviour-identical port. Making the two families agree is a deliberate later change, not a
tidy-up smuggled into the port.

Modules:
    hooks.py            require_service_scope · require_callback · principal_from_request
    errors.py           register_error_handlers · render_svcplane_error
    authenticators.py   RemoteJWKSAuthenticator

Planned:
    middleware.py       the plane → [methods] authentication middleware (C-038)
"""

from __future__ import annotations

from .authenticators import RemoteJWKSAuthenticator
from .errors import register_error_handlers, render_svcplane_error
from .hooks import (
    HookFn,
    principal_from_request,
    require_callback,
    require_service_scope,
)

__all__ = (
    "HookFn",
    "RemoteJWKSAuthenticator",
    "principal_from_request",
    "register_error_handlers",
    "render_svcplane_error",
    "require_callback",
    "require_service_scope",
)

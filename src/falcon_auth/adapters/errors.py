"""Falcon error rendering for this package's east-west exceptions.

SCOPE, stated plainly because an earlier version of this docstring overpromised: this maps
`SvcPlaneError` and **nothing else**. Six other package exceptions -- `Unauthenticated`,
`CapabilityDenied`, `SessionMiss`, `StepUpRequired`, `AuthzUnavailable`,
`OperationChallengeMiss` -- have no handler here and therefore render as **500** unless the
host maps them. The mapping a host is expected to apply is the table in
:mod:`falcon_auth.errors`.

That gap is issue #1 A8, and it is **deferred deliberately** rather than overlooked. Two
reasons, both about not breaking a consumer silently:

- The wire shape here is `{code:int, title, description}`, which C-001 forbids (it requires
  `{code, message, extras}` with `^[A-Z]{4}[0-9]{4}$`). Changing it means changing what every
  peer calling this service reads. Nothing in the estate BRANCHES on the codes -- checked --
  but clients here parse bodies defensively (`body.get("title", "unknown_error")`), so a
  vanished field degrades silently rather than failing loudly, and the allow-lists that would
  tell us who actually calls a given surface are Vault-rendered, not in the repos.

- Falcon's error handlers are **last-registration-wins**. A consumer that followed the
  documented mapping and then called :func:`register_error_handlers` would have its own
  handler silently replaced by ours. So even the apparently-safe half -- registering the
  missing six -- carries the same class of risk.

When it is picked up: an opt-in signature where the host supplies its own codes avoids the
override entirely, and folding the change into each service's migration off `falcon-svcplane`
costs consumers one breaking change instead of two, since that import is changing anyway.
"""

from __future__ import annotations

from typing import Any

import falcon
import falcon.asgi

from ..eastwest.errors import SvcPlaneError


async def render_svcplane_error(
    req: falcon.asgi.Request,
    resp: falcon.asgi.Response,
    ex: SvcPlaneError,
    params: dict[str, Any],
) -> None:
    """Falcon error handler: render a :class:`SvcPlaneError` on the response.

    Emits ``application/json`` with the wire format hardened in
    :mod:`falcon_auth.eastwest.errors` — uniform across every consuming repo.
    """
    resp.status = ex.http_status
    resp.media = ex.json()


def register_error_handlers(
    app: falcon.asgi.App[falcon.asgi.Request, falcon.asgi.Response],
) -> None:
    """Plumb :class:`SvcPlaneError` → its response envelope.

    One line, called once at boot. All three east-west error subclasses share
    :class:`SvcPlaneError` as their base, so a single handler covers them.

    NOTE: it covers **only** that family. See the module docstring: the rest of the package's
    exceptions render as 500 until the host maps them, which is issue #1 A8, deferred.
    """
    app.add_error_handler(SvcPlaneError, render_svcplane_error)


__all__ = (
    "register_error_handlers",
    "render_svcplane_error",
)

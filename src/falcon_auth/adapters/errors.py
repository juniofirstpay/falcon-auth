"""Falcon error handling for the errors falcon-auth raises -- and only those.

:func:`register_falcon_auth_error_handler` registers ONE handler, for
:class:`~falcon_auth.wire.FalconAuthError` -- the base of every exception raised from inside this
package -- and renders each in C-001's shape, the same shape the host renders its own errors in::

    {"code": "PLAT0102", "message": "You do not have access to this.", "extras": {"capability": "kyc:read"}}

It does not touch anything else. The host's domain errors, Falcon's framework errors (router 404,
405, malformed media) and unhandled exceptions are the host's, rendered by the host's own
serializer from its own register (C-001). That includes the plane middleware's wrong-plane
answer, which raises Falcon's ``HTTPRouteNotFound`` precisely so the host's router-miss handler
renders it (``PLAT0006``, RUL-158).

**C-048 holds by construction:** the ``message`` comes from the register by code, never from the
exception; the exception's own text is the ``trace``, logged with the code, request id, path and
method, and ⛔ never serialized. Values the caller may see are each class's ``wire_extras()``. A
``503`` carries ``Retry-After`` (C-002).

**Opt-in.** Peers parse error bodies defensively (``body.get("title", "unknown_error")``), so a
host switches when it chooses, with its callers. Falcon keeps one handler per class and selects the
most specific in the exception's MRO, so a host handler for a falcon-auth subclass still wins.

:func:`register_error_handlers` -- the pre-C-001 east-west shape ``{code:int, title,
description}`` -- is deprecated.
"""

from __future__ import annotations

import warnings
from typing import Any

import falcon
import falcon.asgi
from structlog import get_logger

from ..eastwest.errors import SvcPlaneError
from ..wire import MessageLookup, FalconAuthError, envelope

logger = get_logger("falcon_auth.adapters.errors")


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
    """⚠ Deprecated: the pre-C-001 east-west shape ``{code:int, title, description}``.

    Use :func:`register_falcon_auth_error_handler`, which renders every falcon-auth error --
    these three included -- in C-001's shape.
    """
    warnings.warn(
        "register_error_handlers renders the pre-C-001 shape; use "
        "register_falcon_auth_error_handler",
        DeprecationWarning,
        stacklevel=2,
    )
    app.add_error_handler(SvcPlaneError, render_svcplane_error)


# ── C-001 ────────────────────────────────────────────────────────────────────────────────


def register_falcon_auth_error_handler(
    app: falcon.asgi.App[falcon.asgi.Request, falcon.asgi.Response],
    *,
    messages: MessageLookup | None = None,
    retry_after: int = 5,
) -> None:
    """Render the errors falcon-auth raises in C-001's shape ``{code, message, extras?}``.

    One handler, for :class:`~falcon_auth.wire.FalconAuthError` and every subclass. Nothing else
    is registered: the host's own errors stay the host's.

    :param messages: the host's register, ``code -> message`` (or ``None`` to use the copy in
        :data:`falcon_auth.wire.PLAT_CODES`). Pass the same lookup the host's own serializer uses,
        and the two cannot disagree on copy.
    :param retry_after: seconds, on a ``503`` (C-002).
    """

    async def handle(req: Any, resp: Any, ex: FalconAuthError, params: Any) -> None:
        render_falcon_auth_error(req, resp, ex, messages=messages, retry_after=retry_after)

    app.add_error_handler(FalconAuthError, handle)


def render_falcon_auth_error(
    req: Any,
    resp: Any,
    ex: FalconAuthError,
    *,
    messages: MessageLookup | None = None,
    retry_after: int = 5,
) -> None:
    """Write one falcon-auth error onto ``resp``. Exposed for a host that keeps a single error
    handler of its own and wants to delegate falcon-auth's errors to it."""
    status, body = envelope(ex.plat_code, ex.wire_extras(), messages=messages)
    # C-048 §3: every error is logged with its code, trace, request id, path and method.
    logger.warning(
        "falcon_auth_error",
        code=ex.plat_code,
        status=status,
        trace=ex.trace(),
        request_id=getattr(req.context, "request_id", None) or req.get_header("X-Request-ID"),
        path=req.path,
        method=req.method,
    )
    resp.status = falcon.code_to_http_status(status)
    resp.media = body
    if status == 503:
        resp.set_header("Retry-After", str(retry_after))


__all__ = (
    "register_error_handlers",
    "register_falcon_auth_error_handler",
    "render_falcon_auth_error",
    "render_svcplane_error",
)

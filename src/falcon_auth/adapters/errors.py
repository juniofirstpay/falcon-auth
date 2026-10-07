"""Falcon error handling for the errors falcon-auth raises -- and only those.

**C-001 by default** (platform-conventions RUL-161). :func:`register_error_handlers` -- the call
hosts already make -- registers ONE handler, for :class:`~falcon_auth.wire.FalconAuthError`, the
base of every exception raised from inside this package, and renders each in C-001's shape, the
same shape the host renders its own errors in::

    {"code": "PLAT0102", "message": "You do not have access to this.", "extras": {"capability": "kyc:read"}}

East-west included: no certificate is ``401 PLAT0103``, an unknown CN ``403 PLAT0104``, a missing
capability ``403 PLAT0102`` with ``extras.capability`` (C-055 §3, RUL-160). A host that registers
:func:`render_svcplane_error` itself gets the same.

**Turning it off is explicit.** ``register_error_handlers(app, legacy_shape=True)`` keeps the
pre-C-001 east-west shape ``{code: 9000-9002, title, description}`` -- and the consumer records a
**C-001 exception** in its ``exceptions/<service>.md`` (RUL-161). It warns.

It does not touch anything else. The host's domain errors, Falcon's framework errors (router 404,
405, malformed media) and unhandled exceptions are the host's, rendered by the host's own
serializer from its own register (C-001). That includes the plane middleware's wrong-plane
answer, which raises Falcon's ``HTTPRouteNotFound`` precisely so the host's router-miss handler
renders it (``PLAT0006``, RUL-158).

**C-048 holds by construction:** the ``message`` comes from the register by code, never from the
exception; the exception's own text is the ``trace``, logged with the code, request id, path and
method, and ⛔ never serialized. Values the caller may see are each class's ``wire_extras()``. A
``503`` carries ``Retry-After`` (C-002).

Falcon keeps one handler per class and selects the most specific in the exception's MRO, so a
host handler for a falcon-auth subclass -- persona maps several to its own codes -- still wins.
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
    """Falcon error handler for the east-west errors: C-001's shape (RUL-161).

    A host that registers this itself -- ``app.add_error_handler(SvcPlaneError,
    render_svcplane_error)`` -- gets ``401 PLAT0103`` / ``403 PLAT0104`` / ``403 PLAT0102``
    without changing a line. The pre-C-001 body is :func:`render_svcplane_error_legacy`.
    """
    render_falcon_auth_error(req, resp, ex)


async def render_svcplane_error_legacy(
    req: falcon.asgi.Request,
    resp: falcon.asgi.Response,
    ex: SvcPlaneError,
    params: dict[str, Any],
) -> None:
    """⚠ The pre-C-001 east-west body, ``{code: 9000-9002, title, description, extras?}``.

    Using it is a C-001 exception the consumer records (RUL-161).
    """
    resp.status = ex.http_status
    resp.media = ex.json()


def register_error_handlers(
    app: falcon.asgi.App[falcon.asgi.Request, falcon.asgi.Response],
    *,
    legacy_shape: bool = False,
    messages: MessageLookup | None = None,
    retry_after: int = 5,
) -> None:
    """Render falcon-auth's errors -- every one, east-west included -- in C-001's shape.

    The default since RUL-161. ``legacy_shape=True`` keeps the pre-C-001 east-west body for a
    consumer whose callers have not moved: it warns, and the consumer records a C-001 exception.
    In that mode the other falcon-auth errors are left unregistered, as they were before.

    :param messages: the host's register, ``code -> message``; see
        :func:`register_falcon_auth_error_handler`.
    :param retry_after: seconds, on a ``503`` (C-002).
    """
    if legacy_shape:
        warnings.warn(
            "register_error_handlers(legacy_shape=True) renders the pre-C-001 east-west shape. "
            "C-001 is the default (RUL-161); keeping the old shape is a C-001 exception the "
            "consumer records",
            DeprecationWarning,
            stacklevel=2,
        )
        app.add_error_handler(SvcPlaneError, render_svcplane_error_legacy)
        return
    register_falcon_auth_error_handler(app, messages=messages, retry_after=retry_after)


# ── C-001 ────────────────────────────────────────────────────────────────────────────────


def register_falcon_auth_error_handler(
    app: falcon.asgi.App[falcon.asgi.Request, falcon.asgi.Response],
    *,
    messages: MessageLookup | None = None,
    retry_after: int = 5,
) -> None:
    """Render the errors falcon-auth raises in C-001's shape ``{code, message, extras?}``.

    What :func:`register_error_handlers` does by default; kept under this name too. One handler,
    for :class:`~falcon_auth.wire.FalconAuthError` and every subclass. Nothing else is
    registered: the host's own errors stay the host's.

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
    "render_svcplane_error_legacy",
)

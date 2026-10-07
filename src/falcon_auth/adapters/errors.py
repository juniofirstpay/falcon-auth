"""Falcon error rendering: every error in one shape, C-001's.

:func:`register_platform_error_handlers` is the one to use. It renders **every** exception this
package raises, Falcon's own framework errors (router 404, 405, malformed media, ...) and, if
asked, anything unhandled -- all as::

    {"code": "PLAT0102", "message": "You do not have access to this.", "extras": {"capability": "kyc:read"}}

Each package exception names its platform register row (``plat_code``, :mod:`falcon_auth.wire`),
so the package renders the envelope itself: every condition it raises is a COMMON one, with a
PLAT code (C-008, C-043), and none is the host's to choose. That retires falcon-auth#1 A8's plan
of host-supplied codes.

**C-048 holds by construction:** the ``message`` comes from the register by code, never from the
exception; the exception's own text is the ``trace``, logged with the code, request id, path and
method, and ⛔ never serialized. Values the caller may see are each class's ``wire_extras()``.
A ``503`` carries ``Retry-After`` (C-002).

**Opt-in, and called FIRST.** Two hazards made falcon-auth#1 A8 a deliberate deferral, and both
still hold:

- peers parse error bodies defensively (``body.get("title", "unknown_error")``), so a vanished
  ``title`` degrades a client silently rather than breaking it -- the host switches when it
  chooses, with its callers;
- Falcon keeps one handler per exception class and selects the MOST SPECIFIC class in the
  exception's MRO. Called first, this leaves the host free to override any class afterwards; a
  host handler for the same class registered BEFORE it is replaced.

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
from ..wire import MessageLookup, PlatformError, envelope

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

    Use :func:`register_platform_error_handlers`, which renders every package error -- these
    three included -- in C-001's shape.
    """
    warnings.warn(
        "register_error_handlers renders the pre-C-001 shape; use "
        "register_platform_error_handlers",
        DeprecationWarning,
        stacklevel=2,
    )
    app.add_error_handler(SvcPlaneError, render_svcplane_error)


# ── C-001 ────────────────────────────────────────────────────────────────────────────────

#: Falcon's framework errors, by class, most specific first. Anything else that is an
#: `HTTPError` falls to :data:`_BY_STATUS`.
_FRAMEWORK: tuple[tuple[type[falcon.HTTPError], str], ...] = (
    (falcon.HTTPRouteNotFound, "PLAT0006"),        # router miss, and the wrong-plane answer
    (falcon.HTTPMethodNotAllowed, "PLAT0007"),
    (falcon.HTTPPayloadTooLarge, "PLAT0005"),
    (falcon.HTTPUnsupportedMediaType, "PLAT0004"),
)

#: An `HTTPError` the host raised itself, by status. A status with no row here is rendered as
#: `PLAT0301` with its own status kept -- and logged, because the host should map it.
_BY_STATUS: dict[int, str] = {
    400: "PLAT0001",
    401: "PLAT0101",
    403: "PLAT0102",
    404: "PLAT0008",
    405: "PLAT0007",
    409: "PLAT0010",
    412: "PLAT0014",
    413: "PLAT0005",
    415: "PLAT0004",
    428: "PLAT0015",
    500: "PLAT0301",
    503: "PLAT0302",
}


def register_platform_error_handlers(
    app: falcon.asgi.App[falcon.asgi.Request, falcon.asgi.Response],
    *,
    messages: MessageLookup | None = None,
    framework: bool = True,
    unhandled: bool = True,
    retry_after: int = 5,
) -> None:
    """Render every error in C-001's shape ``{code, message, extras?}``. Call it FIRST.

    :param messages: the host's own register, ``code -> message`` (or ``None`` to use the copy in
        :data:`falcon_auth.wire.PLAT_CODES`).
    :param framework: also render Falcon's ``HTTPError`` -- the router's 404 (``PLAT0006``, which
        the plane middleware's wrong-plane answer reuses, RUL-158) and 405, malformed media, and
        any ``HTTPError`` the host raises (by status). C-001: "every" includes framework errors.
    :param unhandled: also render any other exception as ``500 PLAT0301``, logging it.
    :param retry_after: seconds, on every ``503`` (C-002).

    Host overrides go AFTER this call: Falcon selects the most specific class, one handler per
    class, so registering a domain exception -- or one of these classes -- later wins.
    """
    async def platform(req: Any, resp: Any, ex: PlatformError, params: Any) -> None:
        _render(req, resp, ex.plat_code, ex.wire_extras(), ex.trace(), messages, retry_after)

    async def http_error(req: Any, resp: Any, ex: falcon.HTTPError, params: Any) -> None:
        code = next((c for cls, c in _FRAMEWORK if isinstance(ex, cls)), None)
        status = int(ex.status_code)
        if code is None:
            code = _BY_STATUS.get(status)
        if code is None:
            logger.warning("http_error_unmapped", status=status, path=req.path)
            code = "PLAT0301"
        _render(req, resp, code, {}, f"{type(ex).__name__}: {ex.title} {ex.description or ''}",
                messages, retry_after, headers=ex.headers, status=status)

    async def anything(req: Any, resp: Any, ex: Exception, params: Any) -> None:
        logger.exception("unhandled_exception", path=req.path, method=req.method)
        _render(req, resp, "PLAT0301", {}, f"{type(ex).__name__}: {ex}", messages, retry_after)

    if unhandled:
        app.add_error_handler(Exception, anything)
    if framework:
        app.add_error_handler(falcon.HTTPError, http_error)
    app.add_error_handler(PlatformError, platform)


def _render(
    req: Any,
    resp: Any,
    code: str,
    extras: dict[str, Any],
    trace: str,
    messages: MessageLookup | None,
    retry_after: int,
    *,
    headers: Any = None,
    status: int | None = None,
) -> None:
    row_status, body = envelope(code, extras, messages=messages)
    # A host-raised HTTPError keeps its own status; everything else takes its row's.
    final_status = status if status is not None else row_status
    # C-048 §3: every error is logged with its code, trace, request id, path and method.
    logger.warning(
        "error_response",
        code=code,
        status=final_status,
        trace=trace,
        request_id=getattr(req.context, "request_id", None) or req.get_header("X-Request-ID"),
        path=req.path,
        method=req.method,
    )
    resp.status = falcon.code_to_http_status(final_status)
    resp.media = body
    for name, value in (headers or {}).items():
        resp.set_header(name, value)          # e.g. 405's Allow
    if final_status == 503:
        resp.set_header("Retry-After", str(retry_after))


__all__ = (
    "register_error_handlers",
    "register_platform_error_handlers",
    "render_svcplane_error",
)

"""Falcon error rendering for this package's exceptions.

One handler registration, called once at boot. As further parts land their error types
register here too, so a consuming service plumbs the whole package's wire format in one line.
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
    """Plumb :class:`SvcPlaneError` → the uniform response envelope.

    One line, called once at boot. All three east-west error subclasses share
    :class:`SvcPlaneError` as their base, so a single handler covers them.
    """
    app.add_error_handler(SvcPlaneError, render_svcplane_error)


__all__ = (
    "register_error_handlers",
    "render_svcplane_error",
)

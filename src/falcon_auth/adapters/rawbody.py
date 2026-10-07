"""Keep the request body's exact bytes, for a one-shot body binding (C-058, `v28`).

C-058 §2-§4: ``request_body_hash`` is base64url, unpadded, SHA-256 over **the exact bytes of the
request body**, hashed by the consuming service **as received, before any decode**. A parsed
body cannot give that back -- key order, whitespace and number formatting are gone -- so the
bytes must be kept before anything reads them.

Falcon reads the body lazily through its own stream, and its public API offers no way to see the
raw bytes and still let a handler call ``get_media()`` afterwards: whichever reads second gets
``b""``. So this sits one layer down, as an **ASGI wrapper** around the app: it drains the
request body once, keeps the bytes in the ASGI scope, and replays them to the app unchanged. The
app -- every middleware, hook and handler -- sees exactly the body the client sent (C-058 §1:
⛔ never altered), and :func:`raw_body` reads the same bytes back for hashing.

Wire it at the edge of the app, where the ASGI server is handed it::

    app = falcon.asgi.App(middleware=[...])
    ...
    asgi_app = RawBodyBuffer(app)          # what uvicorn serves

The cost is memory: the whole body is held for the request's life. JSON request bodies are what
this platform carries; a route taking uploads should set ``max_bytes``.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

__all__ = ("RAW_BODY_SCOPE_KEY", "RawBodyBuffer", "raw_body")

#: Where the bytes are kept, in the ASGI scope. Namespaced so it cannot collide with a server's
#: or another middleware's key.
RAW_BODY_SCOPE_KEY = "falcon_auth.raw_body"

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class RawBodyBuffer:
    """ASGI wrapper: drain the body once, keep its exact bytes, replay them to ``app``.

    :param app: the ASGI application -- a ``falcon.asgi.App``.
    :param max_bytes: refuse a body larger than this with ``413``, before the app runs. ``None``
        (the default) holds whatever arrives -- a limit at the gateway is the usual place for it.
    """

    def __init__(self, app: Callable[..., Awaitable[None]], *, max_bytes: int | None = None):
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                # The client went away mid-body. Nothing to authorize; let the app see it.
                await self._app(scope, _replay(b"", receive, first=message), send)
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if self._max_bytes is not None and size > self._max_bytes:
                await _too_large(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        scope[RAW_BODY_SCOPE_KEY] = body
        await self._app(scope, _replay(body, receive), send)


def raw_body(scope: Scope) -> bytes | None:
    """The exact bytes :class:`RawBodyBuffer` kept for this request, or ``None`` if it did not
    run -- which is a wiring fault for any route that binds its body, never an empty body."""
    value = scope.get(RAW_BODY_SCOPE_KEY)
    return value if isinstance(value, bytes) else None


def _replay(body: bytes, receive: Receive, *, first: Message | None = None) -> Receive:
    """A ``receive`` that hands the app the buffered body once, then defers to the real one --
    so a later ``http.disconnect`` still reaches the app."""
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            if first is not None:
                return first
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


async def _too_large(send: Send) -> None:
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-length", b"0")]})
    await send({"type": "http.response.body", "body": b""})

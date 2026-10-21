"""The package's own outbound calls, under C-064: no redirect followed, one attempt per call.

falcon-auth makes exactly two calls of its own, both to auth, both on a session the HOST hands it
(``session_getter``): the trust-context read (`trustcontext.HttpTrustContextClient`) and the
operation verify (`assurance.operation.HttpOperationVerifier`). The JWKS fetch is the host's,
injected into `identity.jwks.JWKSStore`, so it is not here.

C-064 (`v34`, RUL-192), as it lands on those two calls:

    §2  a 3xx is the call's ANSWER, never a second request. aiohttp follows redirects unless
        told not to PER REQUEST (``allow_redirects=False``) -- a session-level setting does not
        reach these calls -- so the package says it on every call to a plain
        ``aiohttp.ClientSession``. The 3xx is unmapped: ``AuthzUnavailable``, its ``Location``
        in the log only (C-048).
    §3  one attempt. aiohttp re-sends an idempotent request once on a dropped connection
        (``ClientSession._retry_connection``). That is the SESSION's, set where the session is
        built (§4: one construction point per service), so the package does not reach into the
        host's session to change it; it logs ``outbound_session_resends_on``, once per session,
        naming the fix.
    §4  a host whose factory hands out its own wrapper -- orders' ``StrictSession``, which takes
        no ``allow_redirects`` and enforces both rules itself -- passes it as is. The package calls
        any session with only ``get(url, params=, headers=)`` / ``post(url, data=, headers=)``,
        the shape such a wrapper exposes, and adds ``allow_redirects=False`` only for a plain
        ``aiohttp.ClientSession``.

C-066 §3-§4 (`v37`), the answer by KIND when auth gives no usable answer -- one mapping for both
calls, :func:`transport_failure` and :func:`status_failure`:

    unavailable -- refused, connect timeout, 5xx    503 PLAT0302 + Retry-After  AuthzUnavailable
    timed out AFTER the request was sent            504 PLAT0303                UpstreamTimeout
    unusable -- 3xx, bad shape, unmapped status     502 PLAT0304                UpstreamBadResponse
    auth refused THIS service (403)                 500 PLAT0301                AuthzMisconfigured

The first three are ``AuthzUnavailable``s, so a routine operation still gets the last-good copy
for each (C-017, unamended by RUL-212); the fourth is not -- a broken deployment is not
hidden behind a cache. Auth's own codes stay in the log (C-048, C-066 §4-§5).
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

import aiohttp
from structlog import get_logger

from .errors import (
    AuthzError,
    AuthzMisconfigured,
    AuthzUnavailable,
    UpstreamBadResponse,
    UpstreamTimeout,
)

__all__ = (
    "OutboundSession",
    "get",
    "post",
    "refuse_redirect",
    "status_failure",
    "transport_failure",
)

#: aiohttp's connect-phase timeout (3.10+): nothing was sent, so the outcome is known -- none.
_CONNECT_TIMEOUT: tuple[type[BaseException], ...] = tuple(
    t for t in (getattr(aiohttp, "ConnectionTimeoutError", None),) if t is not None
)

logger = get_logger("falcon_auth.outbound")

#: Sessions already reported for leaving aiohttp's re-send on -- by ``id``, once each.
_reported: set[int] = set()


class OutboundSession(Protocol):
    """The two methods the package calls. A plain ``aiohttp.ClientSession`` satisfies it, and so
    does a host's own wrapper that enforces C-064 itself."""

    def get(
        self, url: str, *, params: Mapping[str, str] | None = ..., headers: Mapping[str, str] | None = ...
    ) -> AbstractAsyncContextManager[Any]: ...

    def post(
        self, url: str, *, data: bytes | None = ..., headers: Mapping[str, str] | None = ...
    ) -> AbstractAsyncContextManager[Any]: ...


def get(
    session: Any, url: str, *, params: Mapping[str, str], headers: Mapping[str, str]
) -> AbstractAsyncContextManager[Any]:
    """One GET, redirects off (§2)."""
    cm: AbstractAsyncContextManager[Any] = session.get(
        url, params=params, headers=headers, **_options(session)
    )
    return cm


def post(
    session: Any, url: str, *, body: Any, headers: Mapping[str, str]
) -> AbstractAsyncContextManager[Any]:
    """One POST of a JSON body, redirects off (§2). The body goes as bytes -- ``data=``, never
    aiohttp's ``json=`` -- so a host's wrapper with no ``json`` keyword takes it too."""
    data = json.dumps(body, separators=(",", ":")).encode()
    cm: AbstractAsyncContextManager[Any] = session.post(
        url, data=data, headers={**headers, "Content-Type": "application/json"}, **_options(session)
    )
    return cm


async def refuse_redirect(response: Any, *, call: str) -> None:
    """A 3xx is this call's answer, and an unmapped one (§2): ⛔ never followed."""
    if not 300 <= response.status < 400:
        return
    await logger.aerror(
        "outbound redirect not followed", call=call, status=response.status,
        location=response.headers.get("Location"),
    )
    raise UpstreamBadResponse(f"{call}: auth answered {response.status}, a redirect (C-064)")


def transport_failure(e: BaseException, *, call: str) -> AuthzUnavailable:
    """The C-066 answer for a call that got no response at all.

    A timeout is ``504`` -- an unknown outcome -- unless aiohttp can say it happened while
    CONNECTING, before anything was sent: then auth is simply unavailable, ``503``. A timeout
    that cannot be placed (the session's ``total``) is read as after-send: an unknown outcome is
    the honest answer when nothing proves the request never left.
    """
    if _CONNECT_TIMEOUT and isinstance(e, _CONNECT_TIMEOUT):
        return AuthzUnavailable(f"{call}: could not connect to auth in time")
    if isinstance(e, TimeoutError):
        return UpstreamTimeout(f"{call}: auth timed out after the request was sent")
    return AuthzUnavailable(f"{call}: auth unreachable ({type(e).__name__})")


def status_failure(status: int, *, call: str) -> AuthzError:
    """The C-066 answer for a status the call does not otherwise map."""
    if status == 403:
        return AuthzMisconfigured(f"{call}: auth refused this service's certificate (403)")
    if status >= 500:
        return AuthzUnavailable(f"{call}: auth answered {status}")
    return UpstreamBadResponse(f"{call}: auth answered {status}, which is not mapped")


def _options(session: Any) -> dict[str, Any]:
    if not isinstance(session, aiohttp.ClientSession):
        return {}  # the host's own wrapper: C-064 is its factory's (§4)
    if getattr(session, "_retry_connection", False) and id(session) not in _reported:
        _reported.add(id(session))
        logger.warning(
            "outbound_session_resends_on",
            fix="set session._retry_connection = False where the session is built (C-064 §3)",
        )
    return {"allow_redirects": False}

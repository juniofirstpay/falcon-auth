"""Falcon integration: hook factories + error-handler registration.

The hooks are **closure factories** (Shape A) — the caller binds a specific
:class:`~falcon_auth.eastwest.verifier.Verifier` at decoration time. This avoids
module-level state, keeps two verifiers in the same process independent, and
makes each route file's identity gate visible in its imports.

Typical wiring::

    # boot (app/http.py or equivalent)
    from falcon_auth.eastwest import Verifier, build_allow_list
    from falcon_auth.adapters.hooks import register_error_handlers

    verifier = Verifier(build_allow_list(settings.svcplane.allow_list))
    register_error_handlers(http_app)

    # per route
    from falcon_auth.adapters.hooks import require_service_scope
    from app.services import verifier   # the singleton constructed at boot

    class InternalRevocationsRoute:
        @falcon.before(require_service_scope(verifier, "revocations.sessions:read"))
        async def on_get_sessions(self, req, resp): ...

The verifier stashes the authenticated :class:`~falcon_auth.eastwest.verifier.Principal`
on ``req.context.eastwest_principal`` — handlers that need to know *who*
called them can read it with :func:`principal_from_request`.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import falcon
import falcon.asgi

from ..assurance.stepup import check_session_elevated
from ..eastwest.verifier import Principal, Verifier
from ..trustcontext import TrustContextClient


_PRINCIPAL_CTX_ATTR = "eastwest_principal"


HookFn = Callable[
    [falcon.asgi.Request, falcon.asgi.Response, object, dict[str, Any]],
    Awaitable[None],
]


def require_service_scope(verifier: Verifier, scope: str) -> HookFn:
    """Return a Falcon ``before`` hook that gates a SERVICE route on ``scope``.

    Fail-closed: no client cert →
    :class:`~falcon_auth.eastwest.errors.MissingClientCertError` (401), unknown CN
    → :class:`~falcon_auth.eastwest.errors.UnknownCNError` (403), missing scope →
    :class:`~falcon_auth.eastwest.errors.MissingScopeError` (403).
    """

    async def hook(
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        resource: object,
        params: dict[str, Any],
    ) -> None:
        principal = verifier.authenticate(req.scope)
        verifier.require_scope(principal, scope)
        setattr(req.context, _PRINCIPAL_CTX_ATTR, principal)

    return hook


def require_callback(verifier: Verifier) -> HookFn:
    """Return a Falcon ``before`` hook that gates a CALLBACK route.

    CALLBACK principals carry no scopes — the mere fact that the caller
    presented a known cert-bound identity is the whole authorization. Body is
    treated as data, not a command.
    """

    async def hook(
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        resource: object,
        params: dict[str, Any],
    ) -> None:
        principal = verifier.authenticate(req.scope)
        setattr(req.context, _PRINCIPAL_CTX_ATTR, principal)

    return hook


def principal_from_request(req: falcon.asgi.Request) -> Principal | None:
    """Return the verified east-west principal on ``req``, or ``None``."""
    return getattr(req.context, _PRINCIPAL_CTX_ATTR, None)


#: How a service finds the two references on a request. The package cannot know this: the
#: session claim lands wherever that service's authenticator put it, which is a consumer
#: convention, not a fact about auth.
RefExtractor = Callable[[falcon.asgi.Request], tuple[str, str]]


def require_elevated(client: TrustContextClient, refs: RefExtractor) -> HookFn:
    """Return a Falcon ``before`` hook that gates a route on an ELEVATED session.

    The hook's **presence is the requirement** -- there is no tier argument, because there
    are two tiers and "authenticated is enough" is expressed by not applying it.

    Apply it **after** the entitlement gate. C-033 makes that ordering load-bearing: a
    principal who holds no entitlement at all should get a clean refusal, not be sent away to
    complete a challenge that was never going to help them::

        @falcon.before(require("orders:read"), is_async=True)
        @falcon.before(require_elevated_for_this_service, is_async=True)
        async def on_get_object(self, req, resp, order_id): ...

    Raises `StepUpRequired` (the client raises a challenge and retries), `SessionMiss` (the
    session is gone -- re-authenticate instead), or `AuthzUnavailable` (the lookup failed --
    a challenge cannot fix that).
    """

    async def hook(
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        resource: object,
        params: dict[str, Any],
        *_a: Any,
        **_kw: Any,
    ) -> None:
        # `*_a, **_kw` absorb what `falcon.before(action, *args, **kwargs)` forwards --
        # notably the `is_async=True` callers across this ecosystem still pass, believing
        # Falcon consumes it. Falcon 3 did; Falcon 4 detects hooks automatically and the
        # parameter is gone, so a strict signature raises TypeError: a 500 on a gated route.
        # Nothing is read from them on purpose -- a gate that varied with decorator kwargs
        # would be a second, invisible configuration surface.
        session_ref, user_ref = refs(req)
        await check_session_elevated(client, session_ref, user_ref)

    return hook


__all__ = (
    "HookFn",
    "RefExtractor",
    "principal_from_request",
    "require_callback",
    "require_elevated",
    "require_service_scope",
)

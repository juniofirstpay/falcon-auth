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
                        require_service_capability · require_callback (east-west)
                        principal_from_request
    errors.py           register_error_handlers -- falcon-auth's OWN errors, in C-001's
                        shape by default (RUL-161), the same as the host's;
                        legacy_shape=True is the recorded exception
    authenticators.py   RemoteJWKSAuthenticator (boolean, for Authentication) ·
                        JWTAuthenticator / ReferenceAuthenticator / MTLSAuthenticator /
                        CustomAuthenticator (tri-state, for the plane middleware) --
                        each a configured credential: Selector + check + Binding;
                        jwt_authenticator / mtls_authenticator build them
    hooks.py            ... plus verify_operation_for -- per-operation step-up, called
                        INLINE from a responder rather than as a hook, because the
                        idempotency reservation it must follow is itself inline
    rawbody.py          RawBodyBuffer -- an ASGI wrapper keeping the request body's exact
                        bytes for the C-058 body hash, replayed to Falcon unchanged
    routing.py          PlaneRegistry · mount · verify_app -- one plane per endpoint,
                        refused at startup (C-006)
    middleware.py       PlaneAuthenticationMiddleware -- the per-request assertion that the
                        caller presented the endpoint's one credential, and the
                        wrong-plane 404 PLAT0006 (C-038, C-060)
"""

from __future__ import annotations

from .authenticators import (
    PROVEN_AT_PERIMETER,
    Binding,
    CustomAuthenticator,
    JWTAuthenticator,
    MTLSAuthenticator,
    PlaneAuthenticator,
    ReferenceAuthenticator,
    RemoteJWKSAuthenticator,
    Selector,
    jwt_authenticator,
    mtls_authenticator,
)
from .errors import (
    register_error_handlers,
    register_falcon_auth_error_handler,
    render_falcon_auth_error,
    render_svcplane_error,
    render_svcplane_error_legacy,
)
from .middleware import (
    ACTOR_TYPES_ATTR,
    AUTH_CREDENTIAL_ATTR,
    AUTH_METHOD_ATTR,
    AUTH_PRINCIPAL_ATTR,
    PLANE_ATTR,
    Authenticator,
    ConventionDeviation,
    PlaneAuthenticationMiddleware,
)
from .rawbody import RAW_BODY_SCOPE_KEY, RawBodyBuffer, raw_body
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
    verify_operation_for,
    require_service_capability,
    require_service_scope,
)

__all__ = (
    "ACTOR_TYPES_ATTR",
    "AUTH_CREDENTIAL_ATTR",
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
    "register_falcon_auth_error_handler",
    "render_falcon_auth_error",
    "Registration",
    "RemoteJWKSAuthenticator",
    "jwt_authenticator",
    "mtls_authenticator",
    "render_svcplane_error",
    "render_svcplane_error_legacy",
    "require",
    "require_callback",
    "require_elevated",
    "verify_operation_for",
    "require_service_capability",
    "require_service_scope",
    "UnregisteredRoute",
    "verify_app",
    # falcon-auth#6, steps 1-2
    "Binding",
    "ConventionDeviation",
    "CustomAuthenticator",
    "JWTAuthenticator",
    "MTLSAuthenticator",
    "PlaneAuthenticator",
    "PROVEN_AT_PERIMETER",
    "ReferenceAuthenticator",
    "Selector",
    # issue #7 / C-058: the raw body, for the one-shot body binding
    "RAW_BODY_SCOPE_KEY",
    "RawBodyBuffer",
    "raw_body",
)

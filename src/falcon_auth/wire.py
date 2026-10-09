"""The JSON shape of the errors falcon-auth raises: C-001's, the same as the host's.

falcon-auth renders **only its own errors** -- the exceptions raised from inside the package. The
host's domain errors, Falcon's framework errors (router 404, 405) and anything unhandled are the
host's, rendered by the host's own serializer from its own register (C-001: each service keeps
one). What falcon-auth guarantees is that its errors come out in the **same shape** as the
host's, so a client cannot tell which layer answered::

    {"code": "PLAT0102", "message": "You do not have access to this.", "extras": {"capability": "kyc:read"}}

    code      ^[A-Z]{4}[0-9]{4}$. Every condition this package raises is a COMMON one, so its code
              is a PLAT code (C-008), and only a PLAT code (C-043)
    message   customer copy, from the register by code -- ⛔ never written at a raise site (C-048 §1)
    extras    optional: values the caller may see. Debug detail is a log-only `trace` (C-048 §2)

One consequence worth stating: the plane middleware's wrong-plane answer is NOT one of these. It
raises Falcon's own ``HTTPRouteNotFound``, so the host's router-miss handler renders it as
``PLAT0006`` -- which is exactly what makes it byte-identical to a real router miss (RUL-158).

WHY THE COPY IS IN THE PACKAGE. The register lives in platform-conventions (`registry/PLAT.md`);
the language package that would carry it is deferred (C-043, "for now"). So the rows this package
emits are copied below **verbatim** -- the same choice made for the Casbin model text. A host with
its own copy passes ``messages=`` and that wins.

Framework-free. The Falcon handler is :func:`falcon_auth.adapters.errors.register_falcon_auth_error_handler`.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

__all__ = (
    "PLAT_CODES",
    "MessageLookup",
    "PlatCode",
    "FalconAuthError",
    "envelope",
)


@dataclass(frozen=True)
class PlatCode:
    """One row of the platform register: what goes on the wire, and the name that stays off it."""

    code: str
    name: str
    status: int
    message: str


#: The PLAT rows falcon-auth's own errors use, copied VERBATIM from platform-conventions
#: `registry/PLAT.md` (C-008, C-043; RUL-086, RUL-133).
PLAT_CODES: Mapping[str, PlatCode] = {
    row.code: row
    for row in (
        PlatCode("PLAT0006", "route_not_found", 404, "The requested resource was not found."),
        PlatCode("PLAT0008", "resource_not_found", 404, "The requested item was not found."),
        PlatCode("PLAT0101", "unauthenticated", 401, "Please sign in again."),
        PlatCode("PLAT0102", "forbidden", 403, "You do not have access to this."),
        PlatCode("PLAT0103", "client_certificate_missing", 401,
                 "The request could not be authorised."),
        PlatCode("PLAT0104", "client_identity_unknown", 403,
                 "The request could not be authorised."),
        PlatCode("PLAT0106", "session_not_live", 403,
                 "Your session has ended. Please sign in again."),
        PlatCode("PLAT0108", "token_expired", 401,
                 "Your session needs refreshing. Please try again."),
        PlatCode("PLAT0109", "step_up_required", 401, "Please verify it's you to continue."),
        PlatCode("PLAT0301", "internal_error", 500, "Something went wrong. Please try again."),
        PlatCode("PLAT0302", "service_unavailable", 503,
                 "Service is temporarily unavailable. Please try again."),
    )
}

#: A host's own register: ``code -> message``, or ``None`` to fall back to :data:`PLAT_CODES`.
MessageLookup = Callable[[str], "str | None"]


class FalconAuthError(Exception):
    """The base every exception falcon-auth raises carries: which PLAT row it is.

    Subclasses set :attr:`plat_code`. What reaches the wire is the row's status and message, plus
    :meth:`wire_extras`. Everything else about the exception -- its text, its own attributes -- is
    the log-only ``trace`` (C-048 §2).

    A mixin, with no ``__init__``, so the two existing families keep their constructors:
    :class:`~falcon_auth.errors.AuthzError` and :class:`~falcon_auth.eastwest.errors.SvcPlaneError`.
    """

    #: The register row. A subclass that names none is an internal fault, PLAT0301.
    plat_code: ClassVar[str] = "PLAT0301"

    def wire_extras(self) -> dict[str, Any]:
        """The values the CALLER may see. Default: none -- a subclass opts each one in."""
        return {}

    def trace(self) -> str:
        """Operator detail for the log line. ⛔ Never serialized (C-048 §2)."""
        return str(self) or type(self).__name__


def envelope(
    code: str,
    extras: Mapping[str, Any] | None = None,
    *,
    messages: MessageLookup | None = None,
) -> tuple[int, dict[str, Any]]:
    """``(status, body)`` for a PLAT code, in C-001's shape.

    ``extras`` is omitted when empty: C-001 makes it optional, and an empty object says nothing.
    """
    row = PLAT_CODES[code]
    message = (messages(code) if messages is not None else None) or row.message
    body: dict[str, Any] = {"code": row.code, "message": message}
    if extras:
        body["extras"] = dict(extras)
    return row.status, body

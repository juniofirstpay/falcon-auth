"""The platform error envelope (C-001) for every failure this package raises.

C-001 fixes one error shape for every service, on every plane, for every error -- framework
ones included::

    {"code": "PLAT0102", "message": "You do not have access to this.", "extras": {...}}

    code      ^[A-Z]{4}[0-9]{4}$, estate-unique. Every condition this package raises is a COMMON
              one, so its code is a PLAT code (C-008), and only a PLAT code (C-043)
    message   customer copy, taken from the register by code -- ⛔ never written at a raise site
              (C-048 §1)
    extras    optional, dynamic: values the caller may see. Debug detail is NOT here: it rides a
              log-only `trace` (C-048 §2) and never reaches the wire

WHY THE COPY IS IN THE PACKAGE. The register lives in platform-conventions (`registry/PLAT.md`);
the language package that would carry it is deferred (C-043, "for now"). So the rows this package
emits are copied below **verbatim**, with the register as their source -- the same choice made for
the Casbin model text. A host with its own copy of the register passes ``messages=`` to the
handler mounting and that wins. A divergence from the register is a bug here, visible in review.

This module is framework-free. The Falcon handlers that serialize it are in
:mod:`falcon_auth.adapters.errors`.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

__all__ = (
    "PLAT_CODES",
    "MessageLookup",
    "PlatCode",
    "PlatformError",
    "envelope",
)


@dataclass(frozen=True)
class PlatCode:
    """One row of the platform register: what goes on the wire, and the name that stays off it."""

    code: str
    name: str
    status: int
    message: str


#: The PLAT rows this package can emit, copied VERBATIM from platform-conventions
#: `registry/PLAT.md` (C-008, C-043; RUL-086, RUL-133, RUL-158).
PLAT_CODES: Mapping[str, PlatCode] = {
    row.code: row
    for row in (
        PlatCode("PLAT0001", "invalid_request", 400, "The request could not be processed."),
        PlatCode("PLAT0004", "unsupported_media_type", 415, "The request could not be processed."),
        PlatCode("PLAT0005", "payload_too_large", 413, "The request is too large."),
        PlatCode("PLAT0006", "route_not_found", 404, "The requested resource was not found."),
        PlatCode("PLAT0007", "method_not_allowed", 405, "This action is not allowed."),
        PlatCode("PLAT0008", "resource_not_found", 404, "The requested item was not found."),
        PlatCode("PLAT0010", "conflict", 409,
                 "This action conflicts with the current state. Please refresh and try again."),
        PlatCode("PLAT0014", "precondition_failed", 412,
                 "This item changed since you last viewed it. Please refresh and try again."),
        PlatCode("PLAT0015", "precondition_required", 428,
                 "The request could not be processed. Please refresh and try again."),
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


class PlatformError(Exception):
    """The mixin every exception this package raises carries: which PLAT row it is.

    Subclasses set :attr:`plat_code`. What reaches the wire is the row's status and message, plus
    :meth:`wire_extras`. Everything else about the exception -- its text, its own attributes -- is
    the log-only ``trace`` (C-048 §2).

    A mixin, with no ``__init__``, so the two existing families keep their constructors:
    :class:`~falcon_auth.errors.AuthzError` and :class:`~falcon_auth.eastwest.errors.SvcPlaneError`.
    """

    #: The register row. Unhandled conditions are PLAT0301.
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

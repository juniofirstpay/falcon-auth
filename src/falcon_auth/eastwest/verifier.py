"""East-west identity enforcer.

The non-user auth planes: east-west SERVICE calls (mTLS CN → ``noun:verb``
allow-list) and rail/TSP CALLBACK identities (mTLS CN → known source,
payload-as-data). Both share one mechanism — extract the client-cert Common
Name from the terminated mTLS connection and look it up in a fail-closed
allow-list (unmapped CN → deny). SERVICE principals additionally carry
``noun:verb`` scopes enforced per route; CALLBACK principals carry none
(one-method-per-source, the body is a fact, not a command).

The CN is read from ``scope["extensions"]["tls"]["peer_cert_der"]``, which
:mod:`falcon_auth.eastwest.mtls` injects on the terminated mTLS connection. This
module trusts the CN — chain validation is TLS's job, delegated to the
handshake (``CERT_OPTIONAL``: an unverifiable cert never reaches the app).

Fail-closed: no client certificate →
:class:`~falcon_auth.eastwest.errors.MissingClientCertError` (401); CN not in
allow-list → :class:`~falcon_auth.eastwest.errors.UnknownCNError` (403); missing
scope on SERVICE route → :class:`~falcon_auth.eastwest.errors.MissingScopeError`
(403).

The :class:`Verifier` is deliberately framework-agnostic — it takes a raw
ASGI ``scope`` dict, not a Falcon :class:`~falcon.asgi.Request`. The Falcon
integration lives in :mod:`falcon_auth.adapters.hooks`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from cryptography import x509
from cryptography.x509.oid import NameOID

from .errors import (
    MissingClientCertError,
    MissingScopeError,
    SvcPlaneErrorCodes,
    UnknownCNError,
)


# ``Kind`` values are the string literals stored on :class:`Principal`
# consumers write in their allow-list config.
KIND_SERVICE = "SERVICE"
KIND_CALLBACK = "CALLBACK"


@dataclass(frozen=True)
class Principal:
    """A verified, cert-bound east-west identity."""

    cn: str
    kind: Literal["SERVICE", "CALLBACK"]
    source: str
    scopes: frozenset[str] = field(default_factory=frozenset)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


AllowList = dict[str, Principal]


def build_allow_list(entries: list[Any]) -> AllowList:
    """Build an :data:`AllowList` from settings-style rows.

    Each entry is expected to expose ``cn`` / ``kind`` / ``source`` / ``scopes``
    (via attribute or mapping access — dynaconf yields Box objects that
    support both). Rows with an unknown ``kind`` raise at boot rather than
    silently dropping — mis-typed config should not fail-open.
    """
    allow: AllowList = {}
    for entry in entries:
        cn = _get(entry, "cn")
        kind = _get(entry, "kind")
        source = _get(entry, "source")
        scopes_raw = _get(entry, "scopes", default=[]) or []
        if kind not in (KIND_SERVICE, KIND_CALLBACK):
            raise ValueError(
                f"svcplane allow_list entry cn={cn!r}: kind={kind!r} not in "
                f"{{{KIND_SERVICE}, {KIND_CALLBACK}}}"
            )
        allow[cn] = Principal(
            cn=cn,
            kind=kind,
            source=source,
            scopes=frozenset(scopes_raw),
        )
    return allow


def _get(entry: Any, key: str, *, default: Any = None) -> Any:
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def peer_cn(scope: dict[str, Any]) -> str | None:
    """Return the client-cert CN from the terminated mTLS connection, or None.

    Reads ``scope["extensions"]["tls"]["peer_cert_der"]`` (injected by
    :mod:`falcon_auth.eastwest.mtls`). Returns None when TLS is off, the client
    didn't present a cert (``CERT_OPTIONAL``), the DER is malformed, or the
    cert has no Common Name attribute.
    """
    extensions = scope.get("extensions") if scope else None
    tls_ext = extensions.get("tls") if extensions else None
    if not tls_ext:
        return None
    peer_cert_der = tls_ext.get("peer_cert_der")
    if not peer_cert_der:
        return None
    try:
        cert = x509.load_der_x509_certificate(peer_cert_der)
    except ValueError:
        return None
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    return str(attrs[0].value)


class Verifier:
    """Fail-closed east-west identity enforcer over an :data:`AllowList`.

    Construct once at boot from the consumer's settings::

        from falcon_auth.eastwest import Verifier, build_allow_list
        verifier = Verifier(build_allow_list(settings.svcplane.allow_list))

    Consumers whose 9xxx error codes are taken pass a fresh
    :class:`~falcon_auth.eastwest.errors.SvcPlaneErrorCodes`::

        verifier = Verifier(
            build_allow_list(settings.svcplane.allow_list),
            codes=SvcPlaneErrorCodes(missing_cert=5000, unknown_cn=5001, missing_scope=5002),
        )

    Framework-agnostic: both methods take a raw ASGI ``scope`` dict, so the
    Verifier can be driven by Falcon, Starlette, or any other ASGI framework.
    See :mod:`falcon_auth.adapters.hooks` for the Falcon adapter.
    """

    def __init__(
        self,
        allow: AllowList,
        codes: SvcPlaneErrorCodes | None = None,
    ):
        self._allow = allow
        self._codes = codes or SvcPlaneErrorCodes()

    @property
    def codes(self) -> SvcPlaneErrorCodes:
        """The numeric-code overrides in effect. Read-only."""
        return self._codes

    def authenticate(self, scope: dict[str, Any]) -> Principal:
        """Extract + look up the peer CN. Raises on fail-closed conditions.

        Returns the matched :class:`Principal` — the caller is responsible
        for stashing it wherever the framework's request context lives.
        """
        cn = peer_cn(scope)
        if cn is None:
            raise MissingClientCertError(code=self._codes.missing_cert)
        principal = self._allow.get(cn)
        if principal is None:
            raise UnknownCNError(cn=cn, code=self._codes.unknown_cn)
        return principal

    def require_scope(self, principal: Principal | None, scope: str) -> None:
        """Enforce that ``principal`` holds ``scope``.

        Pass ``None`` (or a scope-less CALLBACK principal) to fail-close a
        SERVICE route that lacks an authenticated identity — raises
        :class:`~falcon_auth.eastwest.errors.MissingScopeError`.
        """
        if principal is None or not principal.has_scope(scope):
            raise MissingScopeError(scope=scope, code=self._codes.missing_scope)


__all__ = (
    "AllowList",
    "KIND_CALLBACK",
    "KIND_SERVICE",
    "Principal",
    "Verifier",
    "build_allow_list",
    "peer_cn",
)

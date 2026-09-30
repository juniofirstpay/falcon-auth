"""East-west identity enforcer.

The non-user auth planes: east-west SERVICE calls (mTLS CN → ``noun:verb``
allow-list) and rail/TSP CALLBACK identities (mTLS CN → known source,
payload-as-data). Both share one mechanism — extract the client-cert Common
Name from the terminated mTLS connection and look it up in a fail-closed
allow-list (unmapped CN → deny). SERVICE principals are authorized per route on a
``noun:verb`` capability; CALLBACK principals carry none (one-method-per-source, the body is a
fact, not a command).

**Two ways a SERVICE peer holds capabilities**, and this module only establishes the first:

    allow-list mode   (C-018)  each row lists the capabilities its CN holds. Config, per
                               environment, checked against nothing.
    policy mode       (C-056, proposed)  a row says only which peer the CN IS -- ``cn`` ->
                               ``source`` -- and what that peer may do is ``g`` rows in the
                               service's Casbin policy, in code. Pass ``peers=`` to
                               :func:`build_allow_list` to turn it on.

Deciding against the policy is not this module's job -- east-west ESTABLISHES who called, and
``entitlement/`` decides (``tests/test_no_framework_leak.py`` holds that line). So policy mode
here is only the boot check that config and code agree on who the peers are.

The CN is read from ``scope["extensions"]["tls"]["peer_cert_der"]``, which
:mod:`falcon_auth.eastwest.mtls` injects on the terminated mTLS connection. This
module trusts the CN — chain validation is TLS's job, delegated to the
handshake (``CERT_OPTIONAL``: an unverifiable cert never reaches the app).

Fail-closed: no client certificate →
:class:`~falcon_auth.eastwest.errors.MissingClientCertError` (401); CN not in
allow-list → :class:`~falcon_auth.eastwest.errors.UnknownCNError` (403); missing
capability on SERVICE route → :class:`~falcon_auth.eastwest.errors.MissingCapabilityError`
(403).

The :class:`Verifier` is deliberately framework-agnostic — it takes a raw
ASGI ``scope`` dict, not a Falcon :class:`~falcon.asgi.Request`. The Falcon
integration lives in :mod:`falcon_auth.adapters.hooks`.
"""

from __future__ import annotations

import warnings
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any

from structlog import get_logger

from cryptography import x509
from cryptography.x509.oid import NameOID

from ..planes import (
    CALLBACK,
    EAST_WEST_KINDS,
    SERVICE,
    EastWestKind,
)
from .errors import (
    MissingCapabilityError,
    MissingClientCertError,
    SvcPlaneErrorCodes,
    UnknownCNError,
)

logger = get_logger(__name__)


# The ``kind`` on an allow-list row IS the plane the caller is on, so the values come from
# :mod:`falcon_auth.planes` rather than being spelled a second time here. Re-exported under
# their original names because consumers import them; the strings are unchanged, so no
# allow-list config changes.
KIND_SERVICE = SERVICE
KIND_CALLBACK = CALLBACK


@dataclass(frozen=True, init=False)
class Principal:
    """A verified, cert-bound east-west identity.

    ``source`` is the **logical peer name** -- the same in every environment, where the CN may
    not be. In policy mode (C-056) it is the subject the capability check runs against, and
    ``capabilities`` stays empty: what a peer may do is in the policy, not on the principal.

    ``scopes`` is the pre-C-055 name of ``capabilities``, accepted as a keyword and readable as a
    property, both with a ``DeprecationWarning``.
    """

    cn: str
    kind: EastWestKind
    source: str
    capabilities: frozenset[str] = field(default_factory=frozenset)

    def __init__(
        self,
        cn: str,
        kind: EastWestKind,
        source: str,
        capabilities: Collection[str] | None = None,
        *,
        scopes: Collection[str] | None = None,
    ) -> None:
        if scopes is not None:
            if capabilities is not None:
                raise TypeError("pass capabilities or its old name scopes, not both")
            warnings.warn(
                "Principal(scopes=...) is deprecated; use capabilities=",
                DeprecationWarning,
                stacklevel=2,
            )
            capabilities = scopes
        object.__setattr__(self, "cn", cn)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "capabilities", frozenset(capabilities or ()))

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    @property
    def scopes(self) -> frozenset[str]:
        """Deprecated: the pre-C-055 name of :attr:`capabilities`."""
        warnings.warn(
            "Principal.scopes is deprecated; read capabilities", DeprecationWarning, stacklevel=2
        )
        return self.capabilities

    def has_scope(self, scope: str) -> bool:
        """Deprecated: the pre-C-055 name of :meth:`has_capability`."""
        warnings.warn(
            "Principal.has_scope is deprecated; use has_capability",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.has_capability(scope)


AllowList = dict[str, Principal]


def build_allow_list(
    entries: list[Any], *, peers: Collection[str] | None = None
) -> AllowList:
    """Build an :data:`AllowList` from settings-style rows.

    Each entry is expected to expose ``cn`` / ``kind`` / ``source`` and, in allow-list mode,
    ``capabilities`` (via attribute or mapping access — dynaconf yields Box objects that
    support both). Rows with an unknown ``kind`` raise at boot rather than
    silently dropping — mis-typed config should not fail-open.

    **The old key.** ``scopes`` is the pre-C-055 name of ``capabilities`` and is still read, with
    ONE boot-time warning naming every CN that uses it. It is not optional polish: a missing key
    reads as an empty set, so a package that stopped reading ``scopes`` would give every peer
    nothing and every service route would 403 -- with no boot error, because an empty set is
    indistinguishable from a legitimately unprivileged peer (falcon-auth#8). A row carrying
    BOTH keys is refused: silently preferring one would make a half-finished config edit look
    like it worked.

    :param peers: the logical peer names the service declares in its policy (C-056, proposed) --
        pass the enforcer's ``peers``. ``None`` is allow-list mode, unchanged. Given, it turns on
        three boot checks, because the config now binds certificates to peers and the code says
        what peers may do, and the two are written in different repositories:

            a row still carrying capabilities      IGNORED, with one boot warning naming the
                                                   CNs -- the policy decides now, and nothing
                                                   reads them
            a SERVICE row naming an unknown peer   refused -- a typo'd ``source`` is a peer
                                                   holding nothing, silently
            a declared peer bound by no CN         a boot WARNING only -- a peer may simply
                                                   not exist in this environment

        Why the leftovers warn rather than refuse: the code and the Vault-rendered config ship
        separately, and both are read at boot. Refusing would force them into the SAME restart --
        old code with the capabilities already removed gives every peer nothing, and new code
        with them still present would not boot -- and an unrelated restart between the two
        (autoscaling, a crash) would hit one or the other. Ignoring them lets the order be: ship
        the code, then clean the config. A later release turns the warning into a refusal.
    """
    allow: AllowList = {}
    old_key_cns: list[str] = []
    leftover_cns: list[str] = []
    for entry in entries:
        cn = _get(entry, "cn")
        kind = _get(entry, "kind")
        source = _get(entry, "source")
        capabilities = _get(entry, "capabilities")
        old = _get(entry, "scopes")
        if kind not in EAST_WEST_KINDS:
            raise ValueError(
                f"svcplane allow_list entry cn={cn!r}: kind={kind!r} not in "
                f"{sorted(EAST_WEST_KINDS)}"
            )
        if capabilities is not None and old is not None:
            raise ValueError(
                f"svcplane allow_list entry cn={cn!r} carries both `capabilities` and its old "
                f"name `scopes`; keep one. Preferring either silently would hide a half-finished edit"
            )
        if old is not None:
            old_key_cns.append(cn)
            capabilities = old
        capabilities = list(capabilities or [])
        if cn in allow:
            # Last-row-wins silently changed a peer's capabilities, which is the shape of a config
            # merge going wrong: two rows for one CN, and only the second one is enforced. A
            # duplicate is a wiring bug and it fails where the wiring is written.
            raise ValueError(
                f"svcplane allow_list has two entries for cn={cn!r}; the second would silently "
                f"replace the first, so a capability could be granted or lost by row order"
            )
        if peers is not None:
            _check_policy_row(cn, kind, source, peers)
            if capabilities:
                leftover_cns.append(cn)
                # Dropped, not carried: in policy mode nothing may read them, so a principal
                # holding them would be a second, unreviewed source of truth waiting for a caller.
                capabilities = []
        allow[cn] = Principal(
            cn=cn,
            kind=kind,
            source=source,
            capabilities=frozenset(capabilities),
        )

    if old_key_cns:
        # Once, at boot, so it lands in the deploy log rather than in traffic.
        logger.warning(
            "svcplane_allow_list_old_key",
            key="scopes",
            use="capabilities",
            cns=sorted(old_key_cns),
        )
    if leftover_cns:
        logger.warning(
            "svcplane_allow_list_capabilities_ignored",
            reason="policy mode (C-056): the policy decides; remove them from the allow-list",
            cns=sorted(leftover_cns),
        )
    if peers is not None:
        bound = {p.source for p in allow.values() if p.kind == SERVICE}
        unbound = sorted(set(peers) - bound)
        if unbound:
            logger.warning("svcplane_peers_unbound", peers=unbound)
    return allow


def _check_policy_row(cn: str, kind: str, source: Any, peers: Collection[str]) -> None:
    if kind == SERVICE and source not in peers:
        raise ValueError(
            f"svcplane allow_list entry cn={cn!r} binds to peer source={source!r}, which this "
            f"service's policy does not declare (declared: {sorted(peers)}). Refusing boot: an "
            f"unknown peer would hold nothing, and a typo would look like a permissions problem"
        )


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
            codes=SvcPlaneErrorCodes(missing_cert=5000, unknown_cn=5001, missing_capability=5002),
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

    def require_capability(self, principal: Principal | None, capability: str) -> None:
        """Enforce that ``principal`` holds ``capability`` -- allow-list mode (C-018).

        Pass ``None`` (or a capability-less CALLBACK principal) to fail-close a
        SERVICE route that lacks an authenticated identity — raises
        :class:`~falcon_auth.eastwest.errors.MissingCapabilityError`.

        In policy mode (C-056) the check is the enforcer's, not this; see
        :func:`falcon_auth.adapters.hooks.require_service_capability`.
        """
        if principal is None or not principal.has_capability(capability):
            raise MissingCapabilityError(capability, code=self._codes.missing_capability)

    def require_scope(self, principal: Principal | None, scope: str) -> None:
        """Deprecated: the pre-C-055 name of :meth:`require_capability`."""
        warnings.warn(
            "Verifier.require_scope is deprecated; use require_capability",
            DeprecationWarning,
            stacklevel=2,
        )
        self.require_capability(principal, scope)


__all__ = (
    "AllowList",
    "KIND_CALLBACK",
    "KIND_SERVICE",
    "Principal",
    "Verifier",
    "build_allow_list",
    "peer_cn",
)

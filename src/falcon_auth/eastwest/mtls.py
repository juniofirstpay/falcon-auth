"""East-west mTLS termination for a Falcon service process (posture A).

The service terminates mTLS itself; there is no service-mesh sidecar in the
deployment topology. The east-west enforcer
(:class:`~falcon_auth.eastwest.verifier.Verifier`) reads the verified client-cert
Common Name from the terminated connection; this module is what makes that
connection mTLS.

**One listener, ``CERT_OPTIONAL``**: the U-plane (end-user, JWT, no client
cert) and the east-west S/K planes (client cert → the allow-list) share
the port. Python's :data:`ssl.CERT_OPTIONAL` is the equivalent of Go's
``tls.VerifyClientCertIfGiven`` — a presented-but-unverifiable client cert
fails the handshake (chain validation is TLS's job, which this package delegates
to); absence is fine at the TLS layer, the verifier fail-closes east-west routes
that lack a cert.

**Regression check**: :func:`build_uvicorn_ssl_kwargs` with ``cert_file=""``
returns an empty dict → uvicorn stays plaintext, existing dev+tests unchanged
in every consuming repo.

**uvicorn does not populate the ASGI scope with peer-cert info.** The protocol
subclasses in :mod:`falcon_auth.eastwest.uvicorn_protocols` capture the peer cert
on ``connection_made`` and intercept every ``self.scope = {...}`` assignment (both
httptools' per-request ``on_message_begin`` and h11's inline construction inside
``handle_events``) so ``scope["extensions"]["tls"]["peer_cert_der"]`` is present
before the ASGI task runs. Pipelined requests each get their own injection since
each triggers a fresh scope assignment.

**THIS MODULE IMPORTS NO UVICORN.** The subclasses live next door because a base
class cannot be a deferred import, and keeping them here made ``import
falcon_auth`` pull in an ASGI server -- paid for by every consumer that never
serves HTTP. Everything with behaviour is :class:`_PeerCertScopeInjector` below,
which needs no uvicorn and is tested without it; what moved is two class
statements. ``build_uvicorn_ssl_kwargs`` is uvicorn-SHAPED but uvicorn-free: it
touches only :mod:`ssl` and returns a dict of kwargs.

**Deferred-with-trigger**: (a) a mesh sidecar terminating mTLS → posture B
(trust a proxy-injected identity header via a a peer-CN adapter);
(b) server-cert hot-reload (today the cert loads at boot, so a rotation needs
a restart — acceptable for infrequently-rotated mTLS certs).
"""

from __future__ import annotations

import ssl
from typing import Any

def build_uvicorn_ssl_kwargs(
    cert_file: str,
    key_file: str,
    client_ca_file: str,
) -> dict[str, Any]:
    """Build uvicorn's ssl_* kwargs for posture A.

    ``cert_file == ""`` returns ``{}`` — uvicorn stays plaintext (dev /
    TLS-terminated-upstream). Non-empty ``client_ca_file`` enables client-cert
    verification with :data:`ssl.CERT_OPTIONAL` (Python's
    ``VerifyClientCertIfGiven``): if a client presents a cert it must chain to
    the CA bundle, else the handshake fails; if it presents none, TLS
    completes and the verifier fail-closes east-west routes.
    """
    if not cert_file:
        return {}
    kwargs: dict[str, Any] = {
        "ssl_certfile": cert_file,
        "ssl_keyfile": key_file or None,
        "ssl_version": ssl.PROTOCOL_TLS_SERVER,
    }
    if client_ca_file:
        kwargs["ssl_ca_certs"] = client_ca_file
        kwargs["ssl_cert_reqs"] = ssl.CERT_OPTIONAL
    return kwargs


def _capture_peer_cert(transport: Any) -> bytes | None:
    """Return the client-cert DER bytes from a TLS transport, or ``None``.

    Non-TLS transports and TLS transports where the peer didn't present a
    cert (permitted under ``CERT_OPTIONAL``) both return ``None`` — svcplane
    treats that as "no cert" and 401s east-west routes.
    """
    ssl_object = transport.get_extra_info("ssl_object") if transport else None
    if ssl_object is None:
        return None
    return ssl_object.getpeercert(binary_form=True) or None


def _inject_tls_extension(scope: dict[str, Any], peer_cert_der: bytes | None) -> None:
    if peer_cert_der is None:
        return
    extensions = scope.setdefault("extensions", {})
    extensions["tls"] = {"peer_cert_der": peer_cert_der}


class _PeerCertScopeInjector:
    """Mixin: intercept ``self.scope = {...}`` and stamp the peer cert.

    Both uvicorn HTTP protocols keep their per-request ``scope`` on ``self``
    and reassign it once per request (httptools in ``on_message_begin``, h11
    inline in ``handle_events``). Overriding ``__setattr__`` catches every
    fresh assignment and injects the ``tls`` extension before the ASGI task
    coroutine runs — including pipelined follow-ups on the same connection.
    """

    _peer_cert_der: bytes | None = None

    def connection_made(self, transport: Any) -> None:
        super().connection_made(transport)  # type: ignore[misc]
        self._peer_cert_der = _capture_peer_cert(transport)

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if name == "scope" and isinstance(value, dict) and value.get("type") == "http":
            _inject_tls_extension(value, self._peer_cert_der)


__all__ = ("build_uvicorn_ssl_kwargs",)

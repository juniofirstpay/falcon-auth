"""The two uvicorn protocol subclasses -- the only place in the package that imports uvicorn.

WHY THEY EXIST. uvicorn does not put peer-certificate information into the ASGI scope, so
without these there is nothing for :mod:`falcon_auth.eastwest.verifier` to read: no CN, no
allow-list check, no service plane at all. They capture the certificate on ``connection_made``
and stamp it into every scope uvicorn builds.

WHY THEY LIVE HERE RATHER THAN IN ``mtls.py``. They SUBCLASS uvicorn, and a base class cannot be
a deferred import -- the ``class`` statement needs it at definition time. Keeping them in
``mtls.py`` therefore meant ``import falcon_auth`` imported an ASGI server, which every consumer
paid for whether or not it served HTTP: a background worker resolving entitlements, a CLI, a
test suite, a service behind a mesh sidecar that terminates mTLS itself, anything running on
hypercorn or granian.

Everything with actual behaviour -- capturing the cert, injecting the extension, the
``__setattr__`` interception -- is in :class:`falcon_auth.eastwest.mtls._PeerCertScopeInjector`,
which needs no uvicorn and is tested without it. What is here is two class statements.

Reachable lazily as ``falcon_auth.PeerCertH11Protocol`` and via ``falcon_auth.eastwest``; that
access is what imports uvicorn. Install it with the extra::

    pip install falcon-auth[uvicorn]
"""

from __future__ import annotations

from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol

from .mtls import _PeerCertScopeInjector

# httptools is an optional uvicorn extra (``uvicorn[standard]``) and ``httptools_impl`` imports
# it unconditionally at module load. Guard the import so consumers shipping bare ``uvicorn``
# still work.
try:
    from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
except ImportError:  # pragma: no cover - depends on env
    HttpToolsProtocol = None  # type: ignore[misc,assignment]


class PeerCertH11Protocol(_PeerCertScopeInjector, H11Protocol):
    """H11 with peer-cert DER injected into the ASGI scope.

    uvicorn selects h11 when ``httptools`` is not installed (bare ``pip install uvicorn``, not
    ``uvicorn[standard]``). Only used when the serve listener is mTLS (``cert_file`` set);
    otherwise uvicorn's default protocol runs and the extension is absent.
    """


if HttpToolsProtocol is not None:  # pragma: no cover - depends on env

    class PeerCertHttpToolsProtocol(_PeerCertScopeInjector, HttpToolsProtocol):
        """httptools counterpart of :class:`PeerCertH11Protocol`.

        Only defined when the ``httptools`` extra is installed. Use it in place of
        :class:`PeerCertH11Protocol` when uvicorn would otherwise pick httptools as its default
        HTTP protocol.
        """

else:
    PeerCertHttpToolsProtocol = None  # type: ignore[misc]


__all__ = ("PeerCertH11Protocol", "PeerCertHttpToolsProtocol")

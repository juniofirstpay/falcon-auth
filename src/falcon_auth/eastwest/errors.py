"""Typed exceptions raised by :class:`~falcon_auth.eastwest.verifier.Verifier` for
the three fail-closed east-west conditions:

- **no client certificate** on an east-west route → 401
  :class:`MissingClientCertError`
- **client cert CN not in the allow-list** → 403 :class:`UnknownCNError`
- **SERVICE principal lacks the route's ``noun:verb`` scope** → 403
  :class:`MissingScopeError`

**Hardened by the package** (uniform across every consuming repo):

- ``title`` — the class name string, e.g. ``"UnknownCNError"``
- ``http_status`` — the HTTP status line, in Falcon's ``"401 Unauthorized"`` form
- ``description`` — a fixed string (interpolated with the scope name for
  :class:`MissingScopeError`)
- ``extras`` — the relevant identity/scope key

**Consumer-overridable**: the numeric ``code`` on the wire. Defaults are the
reserved band 9000/9001/9002; repos whose 9xxx band is already taken pass their
own :class:`SvcPlaneErrorCodes` to
:class:`~falcon_auth.eastwest.verifier.Verifier`.

The wire format is :func:`SvcPlaneError.json`:

.. code-block:: json

    {
      "code":        9001,
      "title":       "UnknownCNError",
      "description": "certificate CN is not in the allow-list",
      "extras":      {"cn": "stranger.svc"}
    }
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_DEFAULT_MISSING_CERT_CODE = 9000
_DEFAULT_UNKNOWN_CN_CODE = 9001
_DEFAULT_MISSING_SCOPE_CODE = 9002


@dataclass(frozen=True)
class SvcPlaneErrorCodes:
    """Numeric codes for the three east-west error conditions.

    Defaults are the reserved band 9000/9001/9002. Consumer repos whose
    9xxx band is taken pass a fresh instance to
    :class:`~falcon_auth.eastwest.verifier.Verifier`::

        codes = SvcPlaneErrorCodes(
            missing_cert=5000, unknown_cn=5001, missing_scope=5002,
        )
        verifier = Verifier(allow_list, codes=codes)
    """

    missing_cert: int = _DEFAULT_MISSING_CERT_CODE
    unknown_cn: int = _DEFAULT_UNKNOWN_CN_CODE
    missing_scope: int = _DEFAULT_MISSING_SCOPE_CODE


# Spelled out rather than imported as ``falcon.HTTP_401``. The constants are plain strings
# ("401 Unauthorized", "403 Forbidden"), so the import bought a name and nothing else -- and it
# was the only thing in the package outside ``adapters/`` that pulled Falcon in, which is a
# property the README states and ``tests/test_no_framework_leak.py`` now enforces.


class SvcPlaneError(Exception):
    """Base for the three fail-closed east-west errors.

    Subclasses set :attr:`title`, :attr:`http_status`, and :attr:`description`
    at class level (hardened by the package). Only :attr:`code` and
    :attr:`extras` are per-instance.
    """

    title: str
    http_status: str
    description: str

    def __init__(self, code: int, extras: dict[str, Any] | None = None):
        super().__init__()
        self.code = code
        self.extras = extras

    def json(self) -> dict[str, Any]:
        """Return the wire-format body.

        Uniform across every consuming repo: ``{code, title, description}``
        with an optional ``extras`` block (present for
        :class:`UnknownCNError` and :class:`MissingScopeError`).
        """
        body: dict[str, Any] = {
            "code": self.code,
            "title": self.title,
            "description": self.description,
        }
        if self.extras:
            body["extras"] = self.extras
        return body


class MissingClientCertError(SvcPlaneError):
    """East-west route reached without a verified client certificate.

    Emitted when :meth:`~falcon_auth.eastwest.verifier.Verifier.authenticate` finds
    no ``peer_cert_der`` in ``scope["extensions"]["tls"]`` — TLS is off, or
    the peer connected without presenting a cert under ``CERT_OPTIONAL``.
    """

    title = "MissingClientCertError"
    http_status = "401 Unauthorized"
    description = "east-west plane requires a client certificate (mTLS)"

    def __init__(self, code: int = _DEFAULT_MISSING_CERT_CODE):
        super().__init__(code=code)


class UnknownCNError(SvcPlaneError):
    """Client cert chain verified, but its Common Name is not in the allow-list.

    ``extras.cn`` carries the offending CN for logging / triage.
    """

    title = "UnknownCNError"
    http_status = "403 Forbidden"
    description = "certificate CN is not in the allow-list"

    def __init__(self, cn: str, code: int = _DEFAULT_UNKNOWN_CN_CODE):
        super().__init__(code=code, extras={"cn": cn})
        self.cn = cn


class MissingScopeError(SvcPlaneError):
    """Authenticated SERVICE principal lacks the route's ``noun:verb`` scope.

    ``description`` is interpolated with the requested scope; ``extras.scope``
    carries the same value for consumers that dispatch on structured fields.
    """

    title = "MissingScopeError"
    http_status = "403 Forbidden"
    # Description template — instance-level `description` is set at raise-time
    # with the scope name interpolated. Kept as a class attribute for
    # documentation / introspection.
    _description_template = "certificate identity is not granted {scope}"

    def __init__(self, scope: str, code: int = _DEFAULT_MISSING_SCOPE_CODE):
        super().__init__(code=code, extras={"scope": scope})
        self.scope = scope
        self.description = self._description_template.format(scope=scope)


__all__ = (
    "MissingClientCertError",
    "MissingScopeError",
    "SvcPlaneError",
    "SvcPlaneErrorCodes",
    "UnknownCNError",
)

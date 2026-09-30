"""Typed exceptions raised by :class:`~falcon_auth.eastwest.verifier.Verifier` for
the three fail-closed east-west conditions:

- **no client certificate** on an east-west route → 401
  :class:`MissingClientCertError`
- **client cert CN not in the allow-list** → 403 :class:`UnknownCNError`
- **SERVICE principal lacks the route's ``noun:verb`` capability** → 403
  :class:`MissingCapabilityError`

**One word, capability** (C-055, proposed; falcon-auth#8). What a route demands is a
capability on both planes. The old names -- ``MissingScopeError``, ``missing_scope`` -- still
work: the first IS the new class, the second is accepted and read back with a
``DeprecationWarning``. **The wire is unchanged** until C-055 is ratified and the envelope work
in falcon-auth#1 A8 lands: ``title`` stays ``"MissingScopeError"`` and ``extras`` keeps its
``scope`` key, because a consumer's client may already branch on them.

**Hardened by the package** (uniform across every consuming repo):

- ``title`` — the class name string, e.g. ``"UnknownCNError"``
- ``http_status`` — the HTTP status line, in Falcon's ``"401 Unauthorized"`` form
- ``description`` — a fixed string (interpolated with the capability for
  :class:`MissingCapabilityError`)
- ``extras`` — the relevant identity/capability key

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

import warnings
from dataclasses import dataclass
from typing import Any


_DEFAULT_MISSING_CERT_CODE = 9000
_DEFAULT_UNKNOWN_CN_CODE = 9001
_DEFAULT_MISSING_CAPABILITY_CODE = 9002


@dataclass(frozen=True, init=False)
class SvcPlaneErrorCodes:
    """Numeric codes for the three east-west error conditions.

    Defaults are the reserved band 9000/9001/9002. Consumer repos whose
    9xxx band is taken pass a fresh instance to
    :class:`~falcon_auth.eastwest.verifier.Verifier`::

        codes = SvcPlaneErrorCodes(
            missing_cert=5000, unknown_cn=5001, missing_capability=5002,
        )
        verifier = Verifier(allow_list, codes=codes)

    ``missing_scope=`` is the pre-C-055 spelling of ``missing_capability=``. It is still accepted,
    with a ``DeprecationWarning``; passing both is refused rather than resolved, because a
    half-finished rename that silently preferred one would look like it had worked.
    """

    missing_cert: int
    unknown_cn: int
    missing_capability: int

    def __init__(
        self,
        missing_cert: int = _DEFAULT_MISSING_CERT_CODE,
        unknown_cn: int = _DEFAULT_UNKNOWN_CN_CODE,
        missing_capability: int | None = None,
        *,
        missing_scope: int | None = None,
    ) -> None:
        if missing_scope is not None:
            if missing_capability is not None:
                raise TypeError(
                    "pass missing_capability or its old name missing_scope, not both"
                )
            warnings.warn(
                "SvcPlaneErrorCodes(missing_scope=...) is deprecated; use missing_capability=",
                DeprecationWarning,
                stacklevel=2,
            )
            missing_capability = missing_scope
        if missing_capability is None:
            missing_capability = _DEFAULT_MISSING_CAPABILITY_CODE
        object.__setattr__(self, "missing_cert", missing_cert)
        object.__setattr__(self, "unknown_cn", unknown_cn)
        object.__setattr__(self, "missing_capability", missing_capability)

    @property
    def missing_scope(self) -> int:
        """Deprecated: the pre-C-055 name of :attr:`missing_capability`."""
        warnings.warn(
            "SvcPlaneErrorCodes.missing_scope is deprecated; read missing_capability",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.missing_capability


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
        :class:`UnknownCNError` and :class:`MissingCapabilityError`).
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


class MissingCapabilityError(SvcPlaneError):
    """Authenticated SERVICE principal lacks the route's ``noun:verb`` capability.

    ``description`` is interpolated with the requested capability. ``extras.scope`` carries the
    same value -- the pre-C-055 key, kept until the wire changes (see the module docstring) --
    and :attr:`capability` holds it for code that catches this in-process.
    """

    # The wire title is the pre-C-055 class name, deliberately. Changing it is a wire change and
    # waits for C-055's ratification and falcon-auth#1 A8; the class name is not on the wire.
    title = "MissingScopeError"
    http_status = "403 Forbidden"
    # Description template — instance-level `description` is set at raise-time
    # with the capability interpolated. Kept as a class attribute for
    # documentation / introspection.
    _description_template = "certificate identity is not granted {capability}"

    def __init__(
        self,
        capability: str | None = None,
        code: int = _DEFAULT_MISSING_CAPABILITY_CODE,
        *,
        scope: str | None = None,
    ):
        # `scope=` is how every pre-C-055 raise site spells it, so it stays a keyword here.
        if (capability is None) == (scope is None):
            raise TypeError("pass exactly one of capability= or its old name scope=")
        capability = capability if capability is not None else scope
        assert capability is not None
        super().__init__(code=code, extras={"scope": capability})
        self.capability = capability
        self.description = self._description_template.format(capability=capability)

    @property
    def scope(self) -> str:
        """Deprecated: the pre-C-055 name of :attr:`capability`."""
        return self.capability


#: The pre-C-055 name. The SAME class, not a subclass, so an ``except MissingScopeError`` in a
#: consumer keeps catching everything it caught before.
MissingScopeError = MissingCapabilityError


__all__ = (
    "MissingCapabilityError",
    "MissingClientCertError",
    "MissingScopeError",
    "SvcPlaneError",
    "SvcPlaneErrorCodes",
    "UnknownCNError",
)

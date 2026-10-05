"""Falcon adapter for remote-JWKS token verification.

The verification itself lives in :mod:`falcon_auth.identity.jwks`, which never sees a
Falcon object. This module is the thin part: pull the header, match the
scheme, hand the token to a :class:`~falcon_auth.identity.jwks.JWKSVerifier`,
and stash the resulting user on the request context in the shape the consumer's
``Authentication`` expects.

Register it like any other authenticator::

    auth = Authentication(User)
    auth.add_authenticator("jwt", RemoteJWKSAuthenticator("Authorization", verifier))

**On the** ``scheme`` **argument.** It is the literal token that must precede the
credential in the header -- ``Authorization: <scheme> <token>`` -- matched
case-insensitively. Passing ``scheme="DPoP"`` means the string ``DPoP`` is what
this authenticator looks for. It does **not** implement RFC 9449: no proof
JWT is parsed, no ``cnf``/``jkt`` thumbprint is bound, nothing ties the token to
a client key. A token accepted here is a **bearer** credential, replayable by
whoever holds it until ``exp``. Stated plainly because the opposite assumption is
easy and expensive -- a reader who takes the scheme name at face value will
under-rate anything that leaks a token (a debug log, a crash dump, a proxied
header). If sender-constrained tokens are ever wanted, that is a change agreed
with the issuer (which must mint ``cnf``) and the client (which must produce
proofs) first, not a verification bolted on here.
"""

from __future__ import annotations

import asyncio
import warnings
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any, ClassVar, Optional, Protocol

import falcon.asgi
import structlog

from ..errors import AuthzUnavailable, Unauthenticated
from ..eastwest.verifier import Verifier, peer_cn
from ..identity.jwks import InvalidToken, JWKSVerifier
from ..planes import (
    JWT,
    MTLS,
    ONE_SHOT_TOKEN,
    PLANES,
    REFERENCE_TOKEN,
    SERVICE,
    USER,
    Method,
    Plane,
)

logger = structlog.get_logger("falcon_auth.adapters")


class RemoteJWKSAuthenticator:
    """Authenticate a request by verifying its JWT against a rotating JWKS.

    Matches the ``Authentication.add_authenticator`` call signature: returns
    ``True`` when the request is authenticated (having set ``req.context.user``)
    and ``False`` otherwise. It raises nothing -- ``Authentication`` decides what
    an unauthenticated request becomes.

    :param header_name: the header carrying the credential, e.g. ``Authorization``.
    :param verifier: the configured :class:`JWKSVerifier`.
    :param scheme: the scheme token expected before the credential. ``None``
        means the header value *is* the bare token. See the module docstring.
    :param user_type: the ``type`` stamped on the user object. Left as ``"user"``
        for the end-user plane; a consumer that authenticates non-human callers
        through this authenticator sets its own.
    """

    def __init__(
        self,
        header_name: str,
        verifier: JWKSVerifier,
        *,
        scheme: Optional[str] = None,
        user_type: str = "user",
        binding: "Binding | None" = None,
    ):
        # Only PROVEN_AT_PERIMETER is meaningful here: this boolean contract cannot raise, so it
        # cannot run a proof check. The argument exists so a `DPoP` scheme can be DECLARED.
        if binding is not None and binding is not PROVEN_AT_PERIMETER:
            raise TypeError(
                "RemoteJWKSAuthenticator accepts only binding=PROVEN_AT_PERIMETER; use "
                "JWTAuthenticator for a binding checked here"
            )
        _check_binding_declared(Selector(header_name, scheme), binding, "RemoteJWKSAuthenticator")
        self._header_name = header_name
        self._verifier = verifier
        self._scheme = scheme
        self._user_type = user_type

    def _extract_token(self, header_value: str) -> Optional[str]:
        """Pull the bare token out of the header value.

        With a ``scheme`` configured the header must be ``"<scheme> <token>"``,
        matched case-insensitively. Returns ``None`` when the header does not
        have that shape.
        """
        if not self._scheme:
            return header_value

        parts = header_value.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != self._scheme.lower():
            return None
        return parts[1].strip()

    async def __call__(
        self,
        user_cls: type[Any],
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        header_value = req.get_header(self._header_name)
        if not header_value:
            return False

        token = self._extract_token(header_value)
        if not token:
            await logger.awarning(
                "jwt rejected: header not in expected scheme",
                header=self._header_name,
                scheme=self._scheme,
            )
            return False

        try:
            claims = await self._verifier.verify(token)
        except InvalidToken as e:
            await logger.awarning("jwt rejected", reason=e.reason)
            return False
        except Exception as e:
            # Defensive: a fetcher or store fault must deny, not 500.
            await logger.aerror("jwt validation error", error=str(e))
            return False

        # Only the allowlisted claims reach the user object — see `JWKSVerifier`.
        forwarded = self._verifier.principal_claims(claims)
        req.context.user = user_cls(
            id=claims.get("sub"), type=self._user_type, **forwarded
        )
        return True




# ── tri-state adapters for the plane middleware ──────────────────────────────
#
# The two authenticators above and below answer to DIFFERENT contracts, and mixing them up is
# the failure issue #1 A4 records:
#
#   Authentication.add_authenticator   (user_cls, req, resp) -> bool, sets req.context.user
#   PlaneAuthenticationMiddleware      (req) -> principal | None, RAISES on an invalid credential
#
# `RemoteJWKSAuthenticator` satisfies the first and returns `False` for every failure, including
# a forged token. Wired into the middleware it reports "no credential present" for a token that
# was present and invalid -- so C-038 step 2 (401) is skipped, the step-3 search finds a valid
# credential for another plane, and a FORGED TOKEN gets a 404 instead of a 401.
#
# `Verifier.authenticate` has the opposite mismatch: it RAISES when no certificate was presented,
# which the middleware reads as "present but invalid" rather than "absent".
#
# These two adapters exist so neither has to be bent. Each maps its verifier onto the tri-state
# contract exactly, and each has a middleware test.


# ── step 1 of falcon-auth#6: an authenticator is a CONFIGURED CREDENTIAL ──────────────────
#
# Every credential is the same four parts, and auth's hand-written hooks are combinations of them:
#
#     carrier      where it is read           Selector(header, scheme)
#     check        how it is verified         JWT signature · store lookup · peer certificate
#     binding      proof of possession        a Binding, PROVEN_AT_PERIMETER, or none
#     single use   spent when used            checked here, CONSUMED in the handler's transaction
#
# An instance is one configured credential, attached to the plane(s) it authenticates on. The
# middleware decides which instances a route accepts; see `PlaneAuthenticationMiddleware`.


@dataclass(frozen=True)
class Selector:
    """Where a credential is read: a header, and the scheme that must open its value.

    ``Selector("Authorization", "Bearer")`` reads ``Authorization: Bearer <token>``; the scheme is
    matched case-insensitively. ``scheme=None`` means the whole header value IS the credential,
    as with ``X-Software-Statement``.

    A header in ANOTHER scheme reads as **absent**, not invalid. That is what lets two
    authenticators share a header -- ``Bearer`` and ``DPoP`` both on ``Authorization`` -- and
    still tell "no credential of my kind" (step 3) from "my kind, and forged" (step 2's 401).
    It is also why two authenticators reading the SAME header and scheme cannot both be accepted
    on one route: a valid credential of one kind would be an invalid one of the other.
    """

    header: str
    scheme: str | None = None

    #: The peer certificate, for :class:`MTLSAuthenticator`. Not a header; overlaps nothing.
    TLS: ClassVar["Selector"]

    def extract(self, req: Any) -> str | None:
        """The bare credential, or ``None`` if this request carries none of this kind."""
        value = req.get_header(self.header)
        if not value:
            return None
        return _token_from(value, self.scheme)

    def overlaps(self, other: "Selector") -> bool:
        """Whether a single request header could satisfy both selectors."""
        if self.header.lower() != other.header.lower():
            return False
        if self.scheme is None or other.scheme is None:
            return True
        return self.scheme.lower() == other.scheme.lower()

    def __str__(self) -> str:
        if self is Selector.TLS:
            return "<peer certificate>"
        return f"{self.header}: {self.scheme} ..." if self.scheme else f"{self.header}: ..."


Selector.TLS = Selector("<tls-peer-certificate>", None)


class Binding(Protocol):
    """Proof of possession, checked AFTER the credential and INSIDE the same authenticator.

    ``bind`` returns nothing when the caller proved they hold the key the credential is bound
    to, and raises :class:`~falcon_auth.errors.Unauthenticated` when they did not. A host may
    supply its own today (auth's DPoP check); the package's ``DPoPBinding`` is step 4.

    Inside, not beside: a binding in a separate hook can be skipped -- auth's client-session hook
    checks the client only IF a proof is present -- and a DPoP proof carries a single-use nonce,
    so it must be checked exactly once, in a mode the verified credential selects.
    """

    async def bind(self, req: Any, principal: Any, token: str) -> None: ...


class _ProvenAtPerimeter:
    """The binding was checked upstream -- by the gateway's forward-auth (RUL-048, auth's P4)."""

    async def bind(self, req: Any, principal: Any, token: str) -> None:
        return None

    def __repr__(self) -> str:
        return "PROVEN_AT_PERIMETER"


#: Declare that a ``DPoP``-scheme token's proof was checked before the request arrived. Every
#: service other than auth receives auth's tokens this way (ppi-backend-auth#246 P4): the
#: gateway's forward-auth validates the proof, and the service verifies the JWT alone.
#:
#: It changes nothing at request time. It exists so that "this token is sender-constrained, and
#: someone else checked" is a statement in the service's code rather than an assumption a reader
#: has to know -- a ``DPoP`` token configured with no binding at all looks exactly like a bearer
#: token, which is what a stolen one would be.
PROVEN_AT_PERIMETER: Binding = _ProvenAtPerimeter()


def _check_binding_declared(selector: Selector, binding: Any, owner: str) -> None:
    """A ``DPoP``-scheme token must say who checks its proof. Warn now; refuse in a later release.

    Warn first because every current consumer configures exactly this (``scheme="DPoP"``, no
    binding), and a package bump must not stop them booting. The fix is one argument:
    ``binding=PROVEN_AT_PERIMETER``.
    """
    if binding is None and (selector.scheme or "").lower() == "dpop":
        message = (
            f"{owner} reads `{selector.header}: DPoP` tokens but declares no binding. Pass "
            f"binding=PROVEN_AT_PERIMETER when the gateway checks the DPoP proof (RUL-048), or a "
            f"Binding that checks it here. Without one this is configured as a plain bearer "
            f"token; a later release refuses it"
        )
        warnings.warn(message, DeprecationWarning, stacklevel=3)
        logger.warning("dpop_binding_undeclared", authenticator=owner, header=selector.header)


def _planes(plane: Plane | Iterable[Plane]) -> frozenset[Plane]:
    found = frozenset([plane]) if isinstance(plane, str) else frozenset(plane)
    unknown = sorted(p for p in found if p not in PLANES)
    if not found or unknown:
        raise ValueError(f"plane must be one or more of {sorted(PLANES)}; got {sorted(found)}")
    return found


class PlaneAuthenticator:
    """What every configured credential shares: its plane(s), its method, and its carrier.

    Subclasses implement ``__call__`` with the middleware's tri-state contract:

        returns a principal   a credential of this kind is present and valid
        returns ``None``      none of this kind is present -- say nothing about others
        raises                present and INVALID (``Unauthenticated``, 401), or it could not
                              be checked (``AuthzUnavailable``, 503)
    """

    method: Method
    planes: frozenset[Plane]
    selector: Selector | None
    single_use: bool = False

    def __init__(
        self, *, plane: Plane | Iterable[Plane], method: Method, selector: Selector | None
    ) -> None:
        self.planes = _planes(plane)
        self.method = method
        self.selector = selector

    async def __call__(self, req: Any) -> Any | None:  # pragma: no cover - abstract
        raise NotImplementedError

    def __repr__(self) -> str:
        return (
            f"<{type(self).__name__} {self.method} on {'/'.join(sorted(self.planes))} "
            f"via {self.selector}>"
        )


class JWTAuthenticator(PlaneAuthenticator):
    """A credential checked by signature: an access token, or a signed statement.

    :param verifier: anything with an async ``verify(token) -> claims`` (a
        :class:`~falcon_auth.identity.jwks.JWKSVerifier`, or the host's own), or a bare async
        callable doing the same. ``InvalidToken`` or ``Unauthenticated`` from it is a 401; any
        other failure is "could not check", a 503 -- during a JWKS outage that is the difference
        between "retry" and "every user's token went bad at once".
    :param selector: where the token is read.
    :param plane: the plane, or planes, it authenticates on.
    :param user_cls: build ``user_cls(id=sub, type=user_type, **forwarded claims)`` -- today's
        ``jwt_authenticator`` behaviour. Needs the verifier's ``principal_claims``.
    :param principal: OR an async ``claims -> principal`` of the host's (auth loads the session
        here, ADR-091). May raise ``Unauthenticated`` / ``AuthzUnavailable``. With neither, the
        claims themselves are the principal.
    :param binding: proof of possession -- required to be DECLARED for a ``DPoP`` scheme; see
        :data:`PROVEN_AT_PERIMETER`.
    :param single_use: the token is spent when used -- a software statement. It is CHECKED here
        and never spent: the handler consumes it inside its own transaction, after idempotency
        (C-030), so a failed change or a retry does not burn it. The method becomes
        ``ONE_SHOT_TOKEN``.
    """

    def __init__(
        self,
        verifier: Any,
        selector: Selector,
        *,
        plane: Plane | Iterable[Plane] = USER,
        user_cls: type[Any] | None = None,
        principal: Callable[[dict[str, Any]], Awaitable[Any]] | None = None,
        binding: Binding | None = None,
        single_use: bool = False,
        user_type: str = "user",
    ) -> None:
        super().__init__(
            plane=plane, method=ONE_SHOT_TOKEN if single_use else JWT, selector=selector
        )
        if user_cls is not None and principal is not None:
            raise TypeError("pass user_cls or principal, not both")
        verify = getattr(verifier, "verify", verifier)
        if not callable(verify):
            raise TypeError(f"verifier needs an async verify(token); got {verifier!r}")
        if user_cls is not None and not callable(getattr(verifier, "principal_claims", None)):
            raise TypeError("user_cls needs a verifier with principal_claims(claims)")
        _check_binding_declared(selector, binding, type(self).__name__)
        self._verifier = verifier
        self._verify = verify
        self._user_cls = user_cls
        self._principal = principal
        self._user_type = user_type
        self.binding = binding
        self.single_use = single_use

    async def __call__(self, req: Any) -> Any | None:
        assert self.selector is not None
        token = self.selector.extract(req)
        if not token:
            return None
        try:
            claims = await self._verify(token)
        except InvalidToken as e:
            await logger.awarning("jwt rejected", reason=e.reason)
            raise Unauthenticated(f"invalid token: {e.reason}") from e
        except (Unauthenticated, AuthzUnavailable):
            raise
        except Exception as e:
            await logger.aerror("jwt validation error", error=str(e))
            raise AuthzUnavailable("token verification is unavailable") from e

        if self._principal is not None:
            principal = await self._principal(claims)
        elif self._user_cls is not None:
            forwarded = self._verifier.principal_claims(claims)
            principal = self._user_cls(id=claims.get("sub"), type=self._user_type, **forwarded)
        else:
            principal = claims
        await _bind(self.binding, req, principal, token)
        return principal


class ReferenceAuthenticator(PlaneAuthenticator):
    """A credential checked by store lookup: an opaque token, reusable until it expires.

    :param lookup: the host's async ``token -> principal``. A database read, or an HTTP call to
        a source outside the service -- the package does not care which. Its contract has THREE
        outcomes, and collapsing any two is a known failure (falcon-auth#1 A4):

            returns a principal              the token is known and live
            raises Unauthenticated           unknown, expired, revoked        -> 401
            raises AuthzUnavailable          the source could not be reached  -> 503

        Returning ``None`` for a token that WAS presented is read as unknown (401), never as
        absent: the selector already found it. Any other exception, or the timeout, is 503.
    :param timeout: seconds before the lookup counts as unreachable. ``None`` waits.

    **Never cached here.** Instant revocation is the one thing a reference token has over a JWT;
    a cache in the package would bring back the JWT's revocation lag without saying so. Caching
    is the host's decision, made in its lookup. Inside the platform, an HTTP lookup against the
    identity provider from another service would put it on that service's hot path (C-016).
    """

    def __init__(
        self,
        lookup: Callable[[str], Awaitable[Any]],
        selector: Selector,
        *,
        plane: Plane | Iterable[Plane] = USER,
        binding: Binding | None = None,
        single_use: bool = False,
        timeout: float | None = None,
    ) -> None:
        super().__init__(
            plane=plane,
            method=ONE_SHOT_TOKEN if single_use else REFERENCE_TOKEN,
            selector=selector,
        )
        if not callable(lookup):
            raise TypeError(f"lookup must be an async callable; got {lookup!r}")
        _check_binding_declared(selector, binding, type(self).__name__)
        self._lookup = lookup
        self._timeout = timeout
        self.binding = binding
        self.single_use = single_use

    async def __call__(self, req: Any) -> Any | None:
        assert self.selector is not None
        token = self.selector.extract(req)
        if not token:
            return None
        try:
            if self._timeout is None:
                principal = await self._lookup(token)
            else:
                principal = await asyncio.wait_for(self._lookup(token), self._timeout)
        except (Unauthenticated, AuthzUnavailable):
            raise
        except asyncio.TimeoutError as e:
            await logger.aerror("reference lookup timed out", timeout=self._timeout)
            raise AuthzUnavailable("token lookup timed out") from e
        except Exception as e:
            await logger.aerror("reference lookup failed", error=str(e))
            raise AuthzUnavailable("token lookup is unavailable") from e
        if principal is None:
            raise Unauthenticated("token is not known")
        await _bind(self.binding, req, principal, token)
        return principal


class MTLSAuthenticator(PlaneAuthenticator):
    """A peer certificate checked against the allow-list.

        no client certificate      ->  None   nothing was presented
        CN not in the allow-list   ->  raises UnknownCNError
        CN in the allow-list       ->  the east-west Principal

    :meth:`Verifier.authenticate` cannot be used directly here: it raises
    `MissingClientCertError` when no certificate was presented, and the middleware reads a raise
    as "present but invalid". A user-plane request -- which legitimately carries no client
    certificate of its own -- would then look like a broken service-plane credential.

    An unknown CN DOES raise, and that is deliberate. It is a real certificate this service does
    not recognise, so it is a present-and-invalid credential; on the wrong-plane search a raise
    ends the lookup at a 401 rather than confirming the endpoint exists with a 404. C-038 step 4
    needs a VALID credential for another plane, and an unknown CN is not one.
    """

    def __init__(self, verifier: Verifier, *, plane: Plane | Iterable[Plane] = SERVICE) -> None:
        super().__init__(plane=plane, method=MTLS, selector=Selector.TLS)
        self._verifier = verifier

    async def __call__(self, req: Any) -> Any | None:
        if peer_cn(req.scope) is None:
            return None
        return self._verifier.authenticate(req.scope)


class CustomAuthenticator(PlaneAuthenticator):
    """A host's own tri-state callable, given the plane, method and carrier the middleware needs.

    For a credential none of the classes above describes. ``selector`` is optional, but without
    it the middleware cannot prove the callable's carrier overlaps no other plane's.
    """

    def __init__(
        self,
        attempt: Callable[[Any], Awaitable[Any | None]],
        *,
        plane: Plane | Iterable[Plane],
        method: Method,
        selector: Selector | None = None,
        single_use: bool = False,
    ) -> None:
        super().__init__(plane=plane, method=method, selector=selector)
        self._attempt = attempt
        self.single_use = single_use

    async def __call__(self, req: Any) -> Any | None:
        return await self._attempt(req)


async def _bind(binding: Binding | None, req: Any, principal: Any, token: str) -> None:
    if binding is None:
        return
    try:
        await binding.bind(req, principal, token)
    except (Unauthenticated, AuthzUnavailable):
        raise
    except Exception as e:
        await logger.aerror("binding check failed", error=str(e))
        raise AuthzUnavailable("proof of possession could not be checked") from e


# ── the step-0 names, kept: they build the classes above ─────────────────────────────────


def jwt_authenticator(
    verifier: JWKSVerifier,
    user_cls: type[Any],
    *,
    header_name: str = "Authorization",
    scheme: str | None = "Bearer",
    user_type: str = "user",
    binding: Binding | None = None,
) -> JWTAuthenticator:
    """A tri-state JWT authenticator on the USER plane -- a :class:`JWTAuthenticator`.

        no header, or a header in another scheme  ->  None   no credential OF THIS KIND
        header present, token invalid             ->  raises Unauthenticated
        header present, token valid               ->  the user object

    A header in a different scheme reads as ABSENT, not invalid: ``Authorization: Basic ...`` on
    a JWT route is a caller who brought a credential this method cannot even parse, which is not
    evidence that their token was forged.

    A store or fetcher fault raises `AuthzUnavailable`, never `Unauthenticated`. The distinction
    matters on the wire: one says "your credential is bad", the other says "we could not check".

    ``scheme="DPoP"`` needs ``binding=PROVEN_AT_PERIMETER`` (or a real binding); without one it
    warns, and a later release refuses. See :data:`PROVEN_AT_PERIMETER`.
    """
    return JWTAuthenticator(
        verifier,
        Selector(header_name, scheme),
        plane=USER,
        user_cls=user_cls,
        user_type=user_type,
        binding=binding,
    )


def mtls_authenticator(verifier: Verifier) -> MTLSAuthenticator:
    """A tri-state mTLS authenticator on the SERVICE plane -- a :class:`MTLSAuthenticator`."""
    return MTLSAuthenticator(verifier)


def _token_from(header_value: str, scheme: str | None) -> str | None:
    if scheme is None:
        return header_value
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != scheme.lower():
        return None
    return parts[1].strip()


__all__ = (
    "PROVEN_AT_PERIMETER",
    "Binding",
    "CustomAuthenticator",
    "JWTAuthenticator",
    "MTLSAuthenticator",
    "PlaneAuthenticator",
    "ReferenceAuthenticator",
    "RemoteJWKSAuthenticator",
    "Selector",
    "jwt_authenticator",
    "mtls_authenticator",
)

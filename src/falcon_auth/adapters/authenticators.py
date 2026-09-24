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

from collections.abc import Awaitable, Callable
from typing import Any, Optional

import falcon.asgi
import structlog

from ..errors import AuthzUnavailable, Unauthenticated
from ..eastwest.verifier import Verifier, peer_cn
from ..identity.jwks import InvalidToken, JWKSVerifier

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
    ):
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


def jwt_authenticator(
    verifier: JWKSVerifier,
    user_cls: type[Any],
    *,
    header_name: str = "Authorization",
    scheme: str | None = "Bearer",
    user_type: str = "user",
) -> Callable[[falcon.asgi.Request], Awaitable[Any | None]]:
    """A tri-state JWT authenticator for :class:`PlaneAuthenticationMiddleware`.

        no header, or a header in another scheme  ->  None   no credential OF THIS KIND
        header present, token invalid             ->  raises Unauthenticated
        header present, token valid               ->  the user object

    A header in a different scheme reads as ABSENT, not invalid: ``Authorization: Basic ...`` on
    a JWT route is a caller who brought a credential this method cannot even parse, which is not
    evidence that their token was forged.

    A store or fetcher fault raises `AuthzUnavailable`, never `Unauthenticated`. The distinction
    matters on the wire: one says "your credential is bad", the other says "we could not check".
    The boolean adapter collapses both to a denial, which during a JWKS outage reads as every
    user's token going bad at once.
    """

    async def attempt(req: falcon.asgi.Request) -> Any | None:
        header_value = req.get_header(header_name)
        if not header_value:
            return None

        token = _token_from(header_value, scheme)
        if not token:
            # Present, but not in our scheme -- a credential for some other method.
            return None

        try:
            claims = await verifier.verify(token)
        except InvalidToken as e:
            await logger.awarning("jwt rejected", reason=e.reason)
            raise Unauthenticated(f"invalid token: {e.reason}") from e
        except Exception as e:
            await logger.aerror("jwt validation error", error=str(e))
            raise AuthzUnavailable("token verification is unavailable") from e

        forwarded = verifier.principal_claims(claims)
        return user_cls(id=claims.get("sub"), type=user_type, **forwarded)

    return attempt


def mtls_authenticator(
    verifier: Verifier,
) -> Callable[[falcon.asgi.Request], Awaitable[Any | None]]:
    """A tri-state mTLS authenticator for :class:`PlaneAuthenticationMiddleware`.

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

    async def attempt(req: falcon.asgi.Request) -> Any | None:
        if peer_cn(req.scope) is None:
            return None
        return verifier.authenticate(req.scope)

    return attempt


def _token_from(header_value: str, scheme: str | None) -> str | None:
    if scheme is None:
        return header_value
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != scheme.lower():
        return None
    return parts[1].strip()


__all__ = ("RemoteJWKSAuthenticator", "jwt_authenticator", "mtls_authenticator")

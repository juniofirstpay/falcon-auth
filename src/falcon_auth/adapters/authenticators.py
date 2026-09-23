"""Falcon adapter for remote-JWKS token verification.

The verification itself lives in :mod:`falcon_auth.identity.jwks`, which never sees a
Falcon object. This module is the thin part: pull the header, match the
scheme, hand the token to a :class:`~falcon_utils.auth_v2.jwks.JWKSVerifier`,
and stash the resulting user on the request context in the shape
:class:`~falcon_utils.auth_v2.authentication.Authentication` expects.

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

from typing import Any, Optional

import falcon.asgi
import structlog

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


__all__ = ("RemoteJWKSAuthenticator",)

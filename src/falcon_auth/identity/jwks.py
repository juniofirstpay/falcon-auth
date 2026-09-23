"""Remote-JWKS token verification — the framework-agnostic half.

Verifies RS256 (or any asymmetric) JWTs against a signing-key set fetched from a
remote JWKS endpoint, with the key selected by the token's ``kid`` header.

**Framework-agnostic on purpose.** :class:`JWKSVerifier` takes a bare token
*string* and returns claims; it never sees a Falcon ``Request``. The Falcon
integration lives in :mod:`falcon_utils.auth_v2.authenticators.jwks_authenticator`,
mirroring how ``falcon-svcplane`` splits its ``Verifier`` (raw ASGI scope) from
its ``hooks`` module (Falcon adapter).

**Ported from the copy running in two services** (`app/utils/jwks.py`, duplicated
byte-for-byte apart from two hardenings that had each landed in only one of them).
:class:`JWKSStore` is code-identical to that original; the merged decode policy in
:data:`DEFAULT_DECODE_OPTIONS` takes the stricter of the two.

**The fetch is injected.** :class:`JWKSStore` takes an async ``fetcher``
returning the parsed ``{"keys": [...]}`` document. The package performs no HTTP
of its own, so each consumer keeps its own transport — its mTLS session, its
timeouts, its cert-rotation story — and this module stays testable without a
network. It also reads no configuration: every value arrives as an argument.

Typical wiring (see the consuming repo's ``app/auth.py``)::

    store = JWKSStore(my_async_fetcher, ttl=300.0)
    verifier = JWKSVerifier(store, issuer=..., audience=...)
    await store.warm()
    store.start_polling(60.0)
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable, Optional, TypedDict, cast

import jwt
import structlog

logger = structlog.get_logger("falcon_auth.identity")


class JWTDecodeOptions(TypedDict):
    """PyJWT's ``options`` mapping, typed.

    Kept as a TypedDict rather than a loose ``dict`` so a consumer overriding
    :data:`DEFAULT_DECODE_OPTIONS` gets told at type-check time when it omits a flag,
    rather than silently inheriting PyJWT's default for it.
    """

    verify_signature: bool
    require: list[str]
    verify_aud: bool
    verify_iss: bool
    verify_exp: bool
    verify_iat: bool
    verify_nbf: bool
    strict_aud: bool


#: Decode options that fail closed. Consumers may pass their own, but these are the
#: defaults every claim check is on and the three registered claims that matter are
#: required.
#:
#: ``sub`` is REQUIRED, not optional metadata: it is the only thing that says who the
#: caller is, and routes turn it straight into an identifier. Without it here, a
#: validly-signed token carrying no ``sub`` authenticates and the failure lands in the
#: responder as an unhandled ``TypeError`` — a 500 where a 401 belongs.
#:
#: ``verify_nbf`` is on: a token without ``nbf`` stays valid (it is not in ``require``),
#: but a token that declares itself not-yet-valid is refused rather than ignored.
#: ``leeway`` on the verifier absorbs ordinary clock skew.
DEFAULT_DECODE_OPTIONS: JWTDecodeOptions = {
    "require": ["iat", "exp", "sub"],
    "verify_signature": True,
    "verify_aud": True,
    "verify_iss": True,
    "verify_exp": True,
    "verify_iat": True,
    "verify_nbf": True,
    "strict_aud": False,
}


class JWKSStore:
    """In-memory store of JWK signing keys fetched from a remote JWKS endpoint.

    Keys are loaded lazily on first use and indexed by their ``kid``. On a cache
    miss -- e.g. the issuer rotated its keys and signed a token with a ``kid`` we
    have not seen -- the store refetches the JWKS once and retries the lookup. A
    TTL also triggers a refresh so rotations are picked up even for ``kid``s that
    were previously cached.

    The asyncio lock collapses concurrent refreshes into a single outbound
    request (correctness, not throttling); rate limiting of the upstream endpoint
    is the gateway's job, so this store implements no cooldown of its own.

    The JWKS HTTP fetch is delegated to an injected ``fetcher`` coroutine
    returning the parsed ``{"keys": [...]}`` document, so the consumer keeps
    ownership of its transport.
    """

    def __init__(
        self, fetcher: Callable[[], Awaitable[dict[str, Any]]], *, ttl: float = 300.0
    ):
        self._fetcher = fetcher
        self._ttl = ttl
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()
        self._poll_task: Optional[asyncio.Task[None]] = None
        self._static = False

    def pin_keys(self, jwks: list[dict[str, Any]]) -> None:
        """Pin a static set of JWKs and stop fetching from the remote endpoint
        (warm-up and polling become no-ops).

        For tests and offline development. A pinned store never rotates, so a
        production deployment that reaches this has silently opted out of key
        rotation -- keep it behind an explicit dev-only branch.
        """
        keys: dict[str, jwt.PyJWK] = {}
        for jwk_dict in jwks:
            kid = jwk_dict.get("kid")
            if not kid:
                continue
            keys[kid] = jwt.PyJWK.from_dict(jwk_dict, jwk_dict.get("alg"))
        self._keys = keys
        self._static = True
        self._fetched_at = time.monotonic()

    @property
    def _stale(self) -> bool:
        if self._static:
            return False
        return (time.monotonic() - self._fetched_at) > self._ttl

    async def _refresh(self) -> None:
        if self._static:
            return
        data = await self._fetcher()

        keys: dict[str, jwt.PyJWK] = {}
        for jwk_dict in data.get("keys", []):
            kid = jwk_dict.get("kid")
            if not kid:
                continue
            keys[kid] = jwt.PyJWK.from_dict(jwk_dict, jwk_dict.get("alg"))

        self._keys = keys
        self._fetched_at = time.monotonic()
        await logger.ainfo("jwks refreshed", count=len(keys), kids=list(keys))

    async def _refresh_locked(self, context: str) -> None:
        """Refresh under the single-flight lock, logging (not raising) failures."""
        async with self._lock:
            try:
                await self._refresh()
            except Exception as e:
                await logger.aerror("jwks refresh failed", context=context, error=str(e))

    async def warm(self) -> None:
        """Eagerly load the JWKS, e.g. at server startup, so the first request
        doesn't pay the fetch latency. A failure is logged but not raised -- the
        server still starts and the lazy :meth:`get_key` path retries on the
        first request.
        """
        await self._refresh_locked("startup")

    async def _poll_loop(self, interval: float) -> None:
        """Refresh the JWKS every ``interval`` seconds until cancelled. Each tick
        is best-effort: a failed fetch is logged and the loop keeps running."""
        while True:
            await asyncio.sleep(interval)
            await self._refresh_locked("poll")

    def start_polling(self, interval: float = 60.0) -> None:
        """Start a background task that proactively refreshes the JWKS on an
        interval, so key rotations are picked up without waiting for a cache miss.
        Idempotent: a second call while a poller is already running is a no-op."""
        if self._poll_task and not self._poll_task.done():
            return
        self._poll_task = asyncio.create_task(self._poll_loop(interval))

    async def stop_polling(self) -> None:
        """Cancel the background poller, e.g. at server shutdown."""
        if self._poll_task is None:
            return
        self._poll_task.cancel()
        try:
            await self._poll_task
        except asyncio.CancelledError:
            pass
        self._poll_task = None

    async def get_key(self, kid: str) -> Optional[jwt.PyJWK]:
        """Return the signing key for ``kid``, refreshing from the remote
        endpoint on a cache miss or when the cached set is stale.

        Returns ``None`` if the key is unknown even after a refresh. If a refresh
        fails but a (possibly stale) key is already cached, that key is served
        rather than failing the request outright.
        """
        key = self._keys.get(kid)
        if key is not None and not self._stale:
            return key

        async with self._lock:
            # Re-check inside the lock: another coroutine may have just refreshed.
            key = self._keys.get(kid)
            if key is not None and not self._stale:
                return key
            try:
                await self._refresh()
            except Exception as e:
                # Network/endpoint failure: fall back to whatever is cached.
                await logger.aerror("jwks refresh failed", error=str(e))

        return self._keys.get(kid)


class InvalidToken(Exception):
    """A token failed verification. Carries a short machine-ish ``reason``.

    Deliberately one type for every failure. The reason is for the service's own
    log line; what goes back to the caller is a single 401 with no hint as to
    which check failed, because the difference between "expired", "wrong issuer"
    and "unknown key" is information an attacker can iterate against.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class JWKSVerifier:
    """Verify a JWT against a rotating remote JWKS. Framework-agnostic.

    The signing algorithm is pinned **server-side** (:paramref:`algorithms`,
    default RS256) so it can never be chosen by the token header -- that is the
    algorithm-confusion defence and it is the reason this class does not read
    ``alg`` from the token.

    What is verified: the ``kid`` header names a key in the store, the signature
    checks out under a pinned algorithm, and the registered claims required by
    :paramref:`options` are present and valid, including ``iss`` and ``aud``
    against the configured values.

    :param forwarded_claims: the allowlist of claim names permitted onto the principal.
        **Required, with no default**, and the reason is the whole point of it.

        The naive form is ``user_cls(id=claims.get("sub"), type="user", **claims)`` --
        every claim in the token, splatted onto the user. That object is then read to
        make authorization decisions, so a token carrying the right claim names would be
        proposing its own grants -- and grants that ride a token make revocation mean
        token lifetime.

        That is not hypothetical. The resolver this package was ported from branched on
        ``user.type``, and on one branch read a principal's entitlements straight out of
        ``user.get("entitlements")``. A token with ``type="service-account"`` and an
        ``entitlements`` claim would have walked that path. The branch has since been
        removed (see :mod:`falcon_auth.entitlement.resolver`), but the allowlist is not
        removed with it: it is what makes the next such branch unreachable rather than
        merely absent.

        The splat is not usually *reachable*, but only by luck: ``type`` collides with
        the hardcoded ``type="user"`` keyword and raises ``TypeError`` inside the
        authenticator's blanket ``except``, surfacing as a 401. An allowlist makes it
        unreachable **by construction** -- and stops a legitimate token that happens to
        carry an ``id`` or ``type`` claim from being silently rejected for the same
        reason.

        **No default here, deliberately.** The correct value is whatever the
        consumer's authorization layer looks sessions up by -- typically its own
        ``DEFAULT_SESSION_CLAIM``. Defaulting it would put an authorization fact inside
        this package and leave one constant defined on both sides of the seam, which
        must then silently agree.

        **Never source it from configuration.** A settings key for "which token
        claims may influence authorization" is one edit away from being no allowlist at
        all. It is a constructor argument -- code, reviewed in a pull request -- or
        nothing. Omitting it is a ``TypeError`` at construction, not a 401 storm in
        production.

        ``sub`` is not forwarded even when listed: it is read explicitly as ``id=``,
        so forwarding it too would collide with that keyword.
    """

    def __init__(
        self,
        store: JWKSStore,
        *,
        options: Optional[JWTDecodeOptions] = None,
        algorithms: Optional[list[str]] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        leeway: float = 0.0,
        forwarded_claims: frozenset[str],
    ):
        self._store = store
        self._options: JWTDecodeOptions = options or DEFAULT_DECODE_OPTIONS
        self._algorithms = algorithms or ["RS256"]
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway
        self._forwarded_claims = forwarded_claims

    @property
    def forwarded_claims(self) -> frozenset[str]:
        """The claim allowlist in effect. Read-only."""
        return self._forwarded_claims

    async def verify(self, token: str) -> dict[str, Any]:
        """Verify ``token`` and return its claims.

        :raises InvalidToken: on any failure -- malformed token, missing or
            unknown ``kid``, bad signature, failed claim check.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise InvalidToken("malformed_header") from e

        kid = header.get("kid")
        if not kid:
            raise InvalidToken("missing_kid")

        key = await self._store.get_key(kid)
        if key is None:
            raise InvalidToken("unknown_kid")

        decode_kwargs: dict[str, Any] = {}
        if self._audience and self._options.get("verify_aud"):
            decode_kwargs["audience"] = self._audience
        if self._issuer and self._options.get("verify_iss"):
            decode_kwargs["issuer"] = self._issuer
        if self._leeway:
            decode_kwargs["leeway"] = self._leeway

        try:
            return jwt.decode(
                token,
                key.key,
                algorithms=self._algorithms,
                options=cast(Any, self._options),
                **decode_kwargs,
            )
        except jwt.PyJWTError as e:
            raise InvalidToken(type(e).__name__) from e

    def principal_claims(self, claims: dict[str, Any]) -> dict[str, Any]:
        """The subset of ``claims`` permitted onto the authenticated user object.

        ``sub`` is excluded by design -- callers pass it explicitly as the user's
        id rather than forwarding it.
        """
        return {name: claims[name] for name in self._forwarded_claims if name in claims}


__all__ = (
    "DEFAULT_DECODE_OPTIONS",
    "JWTDecodeOptions",
    "InvalidToken",
    "JWKSStore",
    "JWKSVerifier",
)

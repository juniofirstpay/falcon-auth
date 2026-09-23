"""The trust source: `GET /internal/sessions/{session_ref}/trust-context` on the auth service.

One call, read by two parts. `assurance` takes `session_trust_level` and the elevation window;
`entitlement` takes the grants. They are not two lookups -- two separate clients would mean two
calls to one endpoint per request, and worse, two calls that can disagree if the session demotes
between them.

Keyed by **session, never by user**. A person holds several concurrent sessions at different tiers
(a BOUND+ELEVATED phone alongside an UNTRUSTED web onboarding), so there is no per-user answer to
ask for. `user_ref` goes along only as a guard: auth 404s if that subject does not own the session,
which turns a swapped session ref from "someone else's grants" into a denial.

**The package owns no connection.** `session_getter` returns the host's already-configured mTLS
`aiohttp.ClientSession` -- the same one it uses for its other east-west calls. Certificates, base
URL and lifecycle stay with the host, so this stays a library rather than a second HTTP stack.

Requires **mTLS + `require_service_scope("trust:read")`** on the calling service's certificate. A
`403` here therefore means *our own* certificate is missing that scope: a deployment fault, mapped
to `AuthzUnavailable`, never to a user denial.

**Caching is by field, not by response.** The two halves change on completely different timescales
-- grants rarely, trust on a timer *and* on device state -- so caching the payload as a unit
silently serves a stale trust level. They are stored under separate keys with separate TTLs, and a
trust miss forces a refetch even when the other half is still warm.

TWO KNOWN BREAKS, ported as-is rather than fixed here:

1. `TrustContext.entitlements` is typed REQUIRED and auth emits no such field at all. Wiring a real
   resolver against a live auth therefore fails validation on every call. This is the estate's
   X-09, it is open against a ratified convention, and closing it needs a build at auth plus a
   coordinated rename -- not a local edit.

2. The field is named `entitlements` in the source this was ported from. C-038 rules that what
   auth emits is a **grant**, never a service's entitlement, and that the field is renamed rather
   than accommodated. The rename is left for that coordinated change so this port stays auditable
   against the original.
"""

from collections.abc import Callable
from datetime import (
    datetime,
    UTC,
)
import json
from typing import (
    Any,
    Protocol,
    cast,
)

from pydantic import (
    ConfigDict,
    BaseModel,
    ValidationError,
)
from structlog import get_logger
import aiohttp

from .errors import (
    AuthzUnavailable,
    SessionMiss,
)

__all__ = (
    "Cache",
    "DEFAULT_ENTITLEMENTS_TTL",
    "DEFAULT_LAST_GOOD_TTL",
    "DEFAULT_TRUST_TTL",
    "DEVICE_TRUST_ATTESTED",
    "DEVICE_TRUST_BOUND",
    "DEVICE_TRUST_UNTRUSTED",
    "HttpTrustContextClient",
    "NullCache",
    "RedisCache",
    "SESSION_TRUST_AUTHENTICATED",
    "SESSION_TRUST_ELEVATED",
    "TrustContext",
    "TrustContextCache",
    "TrustContextClient",
)

logger = get_logger("falcon_auth.trustcontext")

# Trust tiers as the auth service reports them. Named here, beside the model whose fields carry
# them, so no service compares against a bare integer -- `session_trust_level == 2` is unreadable
# at the call site and unsearchable when the vocabulary changes.
SESSION_TRUST_AUTHENTICATED: int = 1
SESSION_TRUST_ELEVATED: int = 2

DEVICE_TRUST_UNTRUSTED: int = 1
DEVICE_TRUST_ATTESTED: int = 2
DEVICE_TRUST_BOUND: int = 3


# auth's numeric code for "session_ref does not resolve to a live session, or the user_ref guard does
# not own it". Per §5 that is a DENY, not an error -- see errors.py.
_AUTH_CODE_SESSION_MISS = 8200


class TrustContext(BaseModel):
    """One session's authorization posture, exactly as auth reports it.

    `extra="allow"` so auth may add fields without breaking us -- the same posture the sibling
    clients in `libs/auth` and `libs/wallet` take.
    """

    model_config = ConfigDict(extra="allow")

    session_ref: str
    user_ref: str
    # NOT in auth's published endpoint doc, but present in the response and load-bearing here.
    # Typed REQUIRED on purpose: were it optional and absent, every caller would resolve to "holds
    # nothing" and 403 -- a total outage wearing the costume of a permissions problem. Failing
    # validation instead makes that arrive as a loud 503 with a parse error in the logs.
    entitlements: list[str]
    session_state: int
    device_trust_level: int          # 1 UNTRUSTED · 2 ATTESTED · 3 BOUND
    session_trust_level: int         # 1 AUTHENTICATED · 2 ELEVATED
    trust_elevated_until: str | None = None
    client_ref: str | None = None
    device_ref: str | None = None    # null for a device-less web-onboarding session

    def project(self, now: datetime | None = None) -> "TrustContext":
        """Collapse an elevation window that has passed, matching auth's own read-path projection.

        Only needed for a **cached** copy: a fresh read is already projected by auth. §10 is explicit
        that this catches expiry *only* -- never a disabled device or a demoted session -- so it does
        not substitute for a fresh read on a privileged operation.
        """
        if self.session_trust_level != SESSION_TRUST_ELEVATED or self.trust_elevated_until is None:
            return self
        try:
            until = datetime.fromisoformat(self.trust_elevated_until)
        except ValueError:
            # An unparseable window is treated as expired: the safe direction is to under-report
            # trust, never to project an elevation we cannot bound.
            return self.model_copy(update={
                "session_trust_level": SESSION_TRUST_AUTHENTICATED, "trust_elevated_until": None,
            })
        if until.tzinfo is None:
            until = until.replace(tzinfo=UTC)
        if (now or datetime.now(UTC)) < until:
            return self
        return self.model_copy(update={
            "session_trust_level": SESSION_TRUST_AUTHENTICATED, "trust_elevated_until": None,
        })


class TrustContextClient(Protocol):
    async def fetch(self, session_ref: str, *, user_ref: str) -> TrustContext: ...


class HttpTrustContextClient:
    """Default `TrustContextClient` over the host's mTLS session."""

    def __init__(
        self,
        session_getter: Callable[[], aiohttp.ClientSession],
        *,
        api_version: str = "1",
        path_template: str = "/internal/sessions/{session_ref}/trust-context",
    ) -> None:
        self._session_getter = session_getter
        self._headers = {"X-API-Version": api_version}
        self._path_template = path_template

    async def fetch(self, session_ref: str, *, user_ref: str) -> TrustContext:
        path = self._path_template.format(session_ref=session_ref)
        try:
            session = self._session_getter()
            async with session.get(
                path, params={"user_ref": user_ref}, headers=self._headers
            ) as response:
                if response.status == 200:
                    return TrustContext.model_validate(await response.json())
                await self._raise_for(response)
        except (SessionMiss, AuthzUnavailable):
            raise
        except ValidationError as e:
            # The response shape changed under us -- most likely `entitlements` went missing. Loud,
            # not silent: see the field comment above.
            await logger.aerror("trust-context response failed validation", exc_info=e)
            raise AuthzUnavailable("trust-context response did not match the expected shape") from e
        except aiohttp.ClientError as e:
            await logger.aerror("trust-context transport failure", exc_info=e)
            raise AuthzUnavailable("trust source unreachable") from e
        except TimeoutError as e:
            await logger.aerror("trust-context timed out", exc_info=e)
            raise AuthzUnavailable("trust source timed out") from e
        raise AuthzUnavailable("trust-context returned no usable response")  # pragma: no cover

    async def _raise_for(self, response: aiohttp.ClientResponse) -> None:
        body: Any = None
        try:
            body = await response.json()
        except Exception:  # noqa: BLE001 -- an unparseable error body must not mask the status
            body = None
        code = _error_code(body)

        if response.status == 404 or code == _AUTH_CODE_SESSION_MISS:
            # A logged-out or foreign session. DENY -- the client must re-authenticate, not retry.
            raise SessionMiss("session is not live, or is not owned by this subject")
        if response.status == 403:
            # OUR certificate lacks `trust:read`. A deployment fault; reporting it as a user denial
            # would read as "every user lost their permissions" during a bad rollout.
            await logger.aerror(
                "trust-context refused our certificate -- is `trust:read` granted to this service?",
                status=response.status,
            )
            raise AuthzUnavailable("this service is not entitled to read trust context")
        await logger.aerror("trust-context error response", status=response.status, code=code, body=body)
        raise AuthzUnavailable(f"trust source returned {response.status}")


def _error_code(body: Any) -> int | None:
    """auth's error envelope is `{"code": n}` or `{"error": {"code": n}}` -- accept both."""
    if not isinstance(body, dict):
        return None
    raw = body.get("code")
    if raw is None:
        nested = body.get("error")
        raw = nested.get("code") if isinstance(nested, dict) else None
    return raw if isinstance(raw, int) else None


DEFAULT_ENTITLEMENTS_TTL = 300  # entitlements change rarely
DEFAULT_TRUST_TTL = 60          # trust demotes on a timer and on device state -- keep it short
DEFAULT_LAST_GOOD_TTL = 900     # only ever read when the source is down


class Cache(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl: int) -> None: ...


class NullCache:
    """No caching. Every resolve hits the source -- correct, and the right default for tests."""

    async def get(self, key: str) -> str | None:
        return None

    async def set(self, key: str, value: str, ttl: int) -> None:
        return None


class RedisCache:
    """`Cache` over a redis-asyncio client configured with `decode_responses=True`.

    Every failure is swallowed to a miss. A cache is an optimisation; if redis is down the service
    should get slower and keep authorizing, not start refusing people.
    """

    def __init__(self, client: Any, *, prefix: str = "authz") -> None:
        self._client = client
        self._prefix = prefix

    def _key(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    async def get(self, key: str) -> str | None:
        try:
            # `cast` only: the client is typed `Any` because the host supplies it (redis-asyncio
            # or a stand-in). Behaviour is unchanged from the ported original.
            return cast("str | None", await self._client.get(self._key(key)))
        except Exception:  # noqa: BLE001 -- see the class docstring
            return None

    async def set(self, key: str, value: str, ttl: int) -> None:
        try:
            await self._client.set(self._key(key), value, ex=ttl)
        except Exception:  # noqa: BLE001
            return None


class TrustContextCache:
    """The §10 field split over any `Cache`.

    `read` returns a context only when **both** halves are warm, so a demoted trust level can never
    be masked by a still-valid entitlement entry.
    """

    def __init__(
        self,
        cache: Cache,
        *,
        entitlements_ttl: int = DEFAULT_ENTITLEMENTS_TTL,
        trust_ttl: int = DEFAULT_TRUST_TTL,
        last_good_ttl: int = DEFAULT_LAST_GOOD_TTL,
    ) -> None:
        self._cache = cache
        self._entitlements_ttl = entitlements_ttl
        self._trust_ttl = trust_ttl
        self._last_good_ttl = last_good_ttl

    async def read(self, session_ref: str) -> TrustContext | None:
        entitlements_raw = await self._cache.get(f"ent:{session_ref}")
        if entitlements_raw is None:
            return None
        trust_raw = await self._cache.get(f"trust:{session_ref}")
        if trust_raw is None:
            return None  # trust expired -> refetch, even though entitlements are still warm
        return _merge(entitlements_raw, trust_raw)

    async def write(self, context: TrustContext) -> None:
        entitlements = json.dumps({
            "session_ref": context.session_ref,
            "user_ref": context.user_ref,
            "entitlements": context.entitlements,
        })
        trust = json.dumps({
            "session_state": context.session_state,
            "device_trust_level": context.device_trust_level,
            "session_trust_level": context.session_trust_level,
            "trust_elevated_until": context.trust_elevated_until,
            "client_ref": context.client_ref,
            "device_ref": context.device_ref,
        })
        await self._cache.set(f"ent:{context.session_ref}", entitlements, self._entitlements_ttl)
        await self._cache.set(f"trust:{context.session_ref}", trust, self._trust_ttl)
        await self._cache.set(
            f"lastgood:{context.session_ref}", context.model_dump_json(), self._last_good_ttl
        )

    async def read_last_good(self, session_ref: str) -> TrustContext | None:
        """The stale copy served when the source is unreachable -- routine operations only (§10)."""
        raw = await self._cache.get(f"lastgood:{session_ref}")
        if raw is None:
            return None
        try:
            return TrustContext.model_validate_json(raw)
        except Exception:  # noqa: BLE001 -- a corrupt entry is a miss, never a crash
            return None


def _merge(entitlements_raw: str, trust_raw: str) -> TrustContext | None:
    try:
        merged: dict[str, Any] = {**json.loads(entitlements_raw), **json.loads(trust_raw)}
        return TrustContext.model_validate(merged)
    except Exception:  # noqa: BLE001 -- a corrupt half is a miss; the source is one call away
        return None

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

**Assurance is never cached.** C-038/RUL-072 rules the feed's two concerns apart: grants may be
revalidated cheaply, but assurance is LIVE -- "no blanket TTL over the whole response: a demoted
device must not keep transacting for the length of a cache window". This module previously held
the trust half for 60 seconds, which is precisely that window.

The convention's replacement for a TTL is revalidation -- `grant_epoch` on the grants and an
`ETag` on the response -- and auth emits NEITHER today; the wire shape is an unratified proposal
(Q121). With no way to revalidate cheaply, the only conformant option left is to not serve
assurance from cache, so there is no warm read path here at all. Every resolve reaches the source.

THE COST, recorded rather than hidden: routine reads that previously served from a warm cache
now call auth on every request. That is a real load increase on the trust source, and it is what
the convention asks for. The field-split cache returns the day auth ships `grant_epoch` + `ETag`,
at which point the warm path becomes a conditional request rather than a timer.

`read_last_good` is NOT that cache and stays. It serves only when the source is UNREACHABLE, only
for routine operations, and logs a warning each time -- the degradation path (C-011), not a cache
window a demoted device can hide inside.

KNOWN BREAK, recorded rather than worked around: auth emits **no grants at all** today, under any
name, so `TrustContext.grants` fails validation against a live auth on every call. That is the
estate's X-09, it is open against a ratified convention, and closing it is a build at auth plus the
first allocation into the platform grant register -- not a local edit.

The field is typed REQUIRED deliberately in the face of that. Making it optional would turn a
service that cannot resolve anybody into one that silently resolves everybody to "holds nothing"
and 403s -- the original called that "a total outage wearing the costume of a permissions
problem". Failing loudly is the honest state of the layer until auth ships.

RENAMED from `entitlements`, which is what the two services this was ported from call it. C-038
(RUL-074) rules that what auth emits is a coarse **grant**, never a service's entitlement, and
X-09 rules the field is renamed rather than accommodated. The name `grants` follows the thread's
proposed wire shape; the `grant_epoch` and `ETag` it also proposes are left out, being explicitly
unconfirmed.
"""

from collections.abc import Callable
from datetime import (
    datetime,
    UTC,
)
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
    "DEFAULT_LAST_GOOD_TTL",
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
    # The COARSE grants auth confers on this session -- never this service's entitlements.
    # C-038/RUL-074: "a service taking layer-3 output from the identity provider is the collapse
    # C-033 §4 forbids". The service expands these into its own entitlements through its `g` rows.
    #
    # A LIST because many grants compose as a UNION (RUL-076): a principal holding several holds
    # the union of their expansions, overlaps collapsing. Not an intersection, not a precedence
    # order. Grants are additive only -- the model has no deny effect, so a suspension can never be
    # expressed as one; the local veto is the only subtractive lever.
    #
    # Typed REQUIRED on purpose: were it optional and absent, every caller would resolve to "holds
    # nothing" and 403 -- a total outage wearing the costume of a permissions problem. Failing
    # validation instead makes that arrive as a loud 503 with a parse error in the logs.
    grants: list[str]
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
        path_template: str,
        api_version: str | None,
    ) -> None:
        """
        :param session_getter: returns the host's already-configured mTLS session.
        :param path_template: auth's trust-context path, with a `{session_ref}` placeholder.
            Required, with no default. The path is a deployment fact -- where auth is
            mounted, and under which API version -- and a default here would be a guess
            baked into a library, wrong for the first consumer that mounts it elsewhere.
            C-039 puts the version in the first path segment, so this is where it goes.
        :param api_version: value for the ``X-API-Version`` header, or ``None`` to send none.
            **Required, with no default.**

            C-039 drops this header -- the version is the first path segment -- but auth has not
            adopted C-039 and gates every endpoint on it (`validate_api_version`, 400/E1004 when
            missing or unknown). So the correct value depends on which auth you are talking to,
            and both plausible defaults are wrong somewhere: defaulting to ``"1"`` keeps sending
            a header the convention retired, and defaulting to ``None`` 400s against auth as
            deployed today. Neither failure is loud, so the host states it.

            **TEMPORARY — tracked as falcon-auth#2.** When auth adopts C-039 this argument is
            deleted rather than given a default, and the version rides in ``path_template``
            alone (``/v1/internal/...``). ``None`` already means "send nothing", so a consumer
            whose auth has moved can stop sending the header without waiting for that cleanup.
        """
        self._session_getter = session_getter
        self._path_template = path_template
        self._headers = {"X-API-Version": api_version} if api_version is not None else {}

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
            # The response shape changed under us -- most likely `grants` went missing. Loud,
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


DEFAULT_LAST_GOOD_TTL = 900     # only ever read when the source is down

# There is deliberately no trust TTL and no grants TTL. Assurance is live (C-038/RUL-072), and
# with assurance uncacheable a grants-only entry can never be assembled into a context, so
# holding one would be dead weight that reads like a working cache.


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

    def __init__(self, client: Any, *, prefix: str) -> None:
        """
        :param prefix: the key namespace. Required: a shared redis is shared, and a
            default would collide two services' entries the first time both used it.
        """
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
    """The degradation store. **Not a read-through cache** -- see the module docstring.

    It holds one thing: the last context the source successfully returned, for the case where the
    source later becomes unreachable. Nothing here is consulted while auth is answering.

    There is no `read`. Assurance is live (C-038/RUL-072), so a context cannot be assembled from
    cache without serving a trust level that may already have been demoted -- which is the exact
    hazard the rule names.
    """

    def __init__(
        self,
        cache: Cache,
        *,
        last_good_ttl: int = DEFAULT_LAST_GOOD_TTL,
    ) -> None:
        self._cache = cache
        self._last_good_ttl = last_good_ttl

    async def write(self, context: TrustContext) -> None:
        """Record this as the last good answer. Called after every successful fetch."""
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


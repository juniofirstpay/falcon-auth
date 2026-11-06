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

Requires **mTLS + `require_service_capability("trust:read")`** on the calling service's certificate. A
`403` here therefore means *our own* certificate is missing that capability: a deployment fault, mapped
to `AuthzUnavailable`, never to a user denial.

**Freshness follows the consequence class (C-079 §6, C-017).** A consequential operation reads
the trust context FRESH at the point of use. A routine one may be served a cached copy within a
tunable TTL (`routine_ttl`, default :data:`DEFAULT_ROUTINE_TTL` = 60 s), and a consumer may
always force a fresh read for any operation (RUL-267 Q-F5). With JWT, auth stays off the hot path
as much as possible: the routine read is what keeps it there.

What this trades, recorded rather than hidden: the routine copy is the WHOLE context, assurance
included, so a session demoted or revoked at auth may keep passing ROUTINE gates for up to
`routine_ttl` on a worker holding a copy. C-038/RUL-072 named that window as the hazard of a
blanket TTL; C-079 (v59, RUL-267/268) accepted it for routine operations only, and closes it for
consequential ones by reading fresh. Step-up (`assurance/stepup.py`) is unaffected -- it reads
auth directly and never through this cache, because a stale elevation refuses the user again.

`grant_epoch` + `ETag` revalidation (RUL-072) would make the routine read a conditional request
rather than a timer; auth emits no `grant_epoch` (RUL-134), so the timer is what there is.

ONE stored copy per session, written after every successful ENABLED fetch, with its fetch time.
It is read two ways: as the **routine** copy (served only while younger than `routine_ttl`, and
younger than any tighter ``max_age`` the caller passes), and as the **last-good** copy when auth
is UNREACHABLE (routine operations only, any age up to `last_good_ttl`, logged loudly -- the
degradation path, C-011/C-079 §8/RUL-212). A session auth DENIES -- 404/410, or a state other
than ENABLED -- has its copy destroyed, so it is served by neither (falcon-auth#30).

THE SCHEMA IS THE PLATFORM'S: `registry/TRUST-CONTEXT.md` (normative, RUL-162-165). Besides the
session and trust fields it requires `grants`, `actor_type` (C-052), `actor_kind` iff OPERATOR,
`session_kind` and `delegations` (C-053). A missing required field is never defaulted (S4).
The one recorded deviation -- an absent `actor_type` read as CUSTOMER (C-052 §3, RUL-162) -- has
ENDED (RUL-188 6): auth's feed emits `actor_type`, `session_kind` and `delegations` (`fedda23`).

The field is typed REQUIRED deliberately in the face of that. Making it optional would turn a
service that cannot resolve anybody into one that silently resolves everybody to "holds nothing"
and 403s -- the original called that "a total outage wearing the costume of a permissions
problem". Failing loudly is the honest state of the layer until auth ships.

RENAMED from `entitlements`, which is what the two services this was ported from call it. C-038
(RUL-074) rules that what auth emits is a coarse **grant**, never a service's entitlement, and
X-09 rules the field is renamed rather than accommodated. `grants` is a plain list, and there is
⛔ no `grant_epoch` (RUL-134); the feed carries a strong `ETag` (S2), which this package does not
use yet: the routine copy expires on its TTL rather than revalidating.
"""

from collections.abc import Callable
from datetime import (
    datetime,
    UTC,
)
from typing import (
    Any,
    Literal,
    Protocol,
    cast,
)

from pydantic import (
    ConfigDict,
    BaseModel,
    ValidationError,
    field_validator,
    model_validator,
)
from structlog import get_logger
import json
import math
import time
import warnings

import aiohttp

from . import outbound

from .errors import (
    AuthzError,
    AuthzMisconfigured,
    AuthzUnavailable,
    SessionMiss,
    UpstreamBadResponse,
)

__all__ = (
    "ActorKind",
    "ActorType",
    "Cache",
    "DEFAULT_LAST_GOOD_TTL",
    "DEFAULT_ROUTINE_TTL",
    "DEVICE_TRUST_ATTESTED",
    "DEVICE_TRUST_RECOGNIZED",
    "DEVICE_TRUST_BOUND",
    "DEVICE_TRUST_UNTRUSTED",
    "Delegation",
    "HttpTrustContextClient",
    "NullCache",
    "RedisCache",
    "SESSION_STATE_ENABLED",
    "SESSION_STATE_REVOKED",
    "SESSION_TRUST_AUTHENTICATED",
    "SESSION_TRUST_ELEVATED",
    "SessionKind",
    "TrustContext",
    "TrustContextCache",
    "TrustContextClient",
)

logger = get_logger("falcon_auth.trustcontext")

# Trust tiers as the auth service reports them. Named here, beside the model whose fields carry
# them, so no service compares against a bare integer -- `session_trust_level == 2` is unreadable
# at the call site and unsearchable when the vocabulary changes.
#: `Session.state` values. A session that is not ENABLED is not a session anybody may act on.
#:
#: Read by the resolver and by step-up, because auth does NOT 404 a revoked session: revoke sets
#: `state = REVOKED`, while the trust-context read filters on `is_active` only and answers 200
#: with `session_state = 2`. Without this check a revoked session resolves as live and keeps
#: transacting -- revocation would not take effect for any consumer of this package.
SESSION_STATE_ENABLED: int = 1
SESSION_STATE_REVOKED: int = 2

SESSION_TRUST_AUTHENTICATED: int = 1
SESSION_TRUST_ELEVATED: int = 2

#: `device_trust_level` carries the COMBINED standing (registry/TRUST-CONTEXT.md, RUL-164):
#: device trust gated by integrity, fail-closed to UNTRUSTED unless integrity is VERIFIED.
DEVICE_TRUST_UNTRUSTED: int = 1
DEVICE_TRUST_RECOGNIZED: int = 2
DEVICE_TRUST_BOUND: int = 3
#: The pre-RUL-164 name of `DEVICE_TRUST_RECOGNIZED` (AUTH-ADR-137 §2 renamed it). Same ordinal.
DEVICE_TRUST_ATTESTED: int = DEVICE_TRUST_RECOGNIZED


# auth's numeric code for "session_ref does not resolve to a live session, or the user_ref guard does
# not own it". Per §5 that is a DENY, not an error -- see errors.py.
_AUTH_CODE_SESSION_MISS = 8200


#: C-052 §2: who the caller is, carried identity -> session -> feed, ⛔ never inferred from grants.
ActorType = Literal["CUSTOMER", "OPERATOR", "SERVICE", "SYSTEM"]
#: C-052 §2: an operator's kind. Present iff `actor_type` is OPERATOR.
ActorKind = Literal["AGENT", "ADMIN", "EXTERNAL"]
#: C-053 §8: a SHADOW session is an operator impersonating a customer, on the customer's routes.
SessionKind = Literal["NORMAL", "SHADOW"]


class Delegation(BaseModel):
    """One subject-bound grant (C-053 §2): the holder may act for ``subject_ref`` until
    ``valid_until``. ⛔ Never inside ``grants`` -- a subject-bound grant matched as a plain grant
    would reach every subject at once.

    ``valid_until`` is required but NULLABLE (RUL-193 D1): ``null`` is no time bound -- the
    delegation ends only when auth stops emitting it (an explicit revocation), ⛔ never by a
    timer here. Whether a ``null`` is ALLOWED is the grant's to say, not the value's (D2): see
    `falcon_auth.entitlement.grants.GrantRow.time_bound`, which the guard checks (D3)."""

    model_config = ConfigDict(extra="allow")

    ref: str
    grant: str
    subject_ref: str
    #: RFC 3339 UTC ``Z``, milliseconds (C-009), or ``None`` for no time bound (RUL-193 D1).
    valid_until: str | None
    #: The operator's case. Present iff the session is SHADOW (C-053 §8).
    case_ref: str | None = None

    @field_validator("valid_until")
    @classmethod
    def _rfc3339_z(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.endswith("Z"):
            raise ValueError("valid_until must be RFC 3339 UTC with a 'Z' (C-009)")
        datetime.fromisoformat(value[:-1] + "+00:00")
        return value

    def live(self, now: datetime | None = None) -> bool:
        """Whether the bound has not passed. ``None`` -- no bound -- is live: only auth ending
        it ends it (RUL-193 D1). Whether this GRANT may go unbounded is checked by the guard."""
        if self.valid_until is None:
            return True
        until = datetime.fromisoformat(self.valid_until[:-1] + "+00:00")
        return (now or datetime.now(UTC)) < until


class TrustContext(BaseModel):
    """One session's authorization posture -- `registry/TRUST-CONTEXT.md`, the normative schema
    (RUL-162-165).

    ``extra="allow"``: auth may add fields without breaking us (S4: additive only, by ruling).
    ⛔ A missing REQUIRED field is never defaulted (S4) -- it fails validation, which the client
    turns into a loud 503. The C-052 §3 deviation that once filled ``actor_type`` has ended
    (RUL-188 6).
    """

    model_config = ConfigDict(extra="allow")

    session_ref: str
    user_ref: str
    client_ref: str
    device_ref: str | None           # required, nullable: null for a device-less web session
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
    device_trust_level: int          # the combined standing: 1 UNTRUSTED · 2 RECOGNIZED · 3 BOUND
    session_trust_level: int         # 1 AUTHENTICATED · 2 ELEVATED
    trust_elevated_until: str | None # required, nullable
    actor_type: ActorType
    actor_kind: ActorKind | None = None
    session_kind: SessionKind
    delegations: list[Delegation]

    @model_validator(mode="after")
    def _schema_rules(self) -> "TrustContext":
        # actor_kind iff OPERATOR (C-052 §2).
        if (self.actor_type == "OPERATOR") != (self.actor_kind is not None):
            raise ValueError("actor_kind is present iff actor_type is OPERATOR")
        # S3: a SHADOW session is an operator, holds no grants, and carries exactly one
        # delegation, with its case_ref (C-053 §8). case_ref appears on no other session.
        if self.session_kind == "SHADOW":
            if self.actor_type != "OPERATOR" or self.grants or len(self.delegations) != 1 \
                    or self.delegations[0].case_ref is None:
                raise ValueError(
                    "a SHADOW session is OPERATOR, with grants = [] and exactly one delegation "
                    "carrying case_ref (S3)"
                )
        elif any(d.case_ref is not None for d in self.delegations):
            raise ValueError("case_ref appears only on a SHADOW session's delegation")
        return self

    @classmethod
    def from_feed(cls, data: Any) -> "TrustContext":
        """Parse a trust-context response, strictly (S4): a missing required field is an error.

        The C-052 §3 deviation (``assume_customer_actor_type``) has ended: auth emits
        ``actor_type``, ``session_kind`` and ``delegations`` (RUL-188 6, ``fedda23``).
        """
        return cls.model_validate(data)

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
        session_getter: Callable[[], "aiohttp.ClientSession | outbound.OutboundSession"],
        *,
        path_template: str,
        api_version: str | None = None,
        assume_customer_actor_type: bool | None = None,
    ) -> None:
        """
        :param session_getter: returns the host's already-configured mTLS session -- a plain
            ``aiohttp.ClientSession``, or the host's own wrapper exposing ``get(url, params=,
            headers=)``. Either way the call follows no redirect (C-064); see
            :mod:`falcon_auth.outbound`.
        :param path_template: auth's trust-context path, with a `{session_ref}` placeholder.
            Required, with no default. The path is a deployment fact -- where auth is
            mounted, and under which API version -- and a default here would be a guess
            baked into a library, wrong for the first consumer that mounts it elsewhere.
            C-039 puts the version in the first path segment, so this is where it goes.
        :param api_version: DEPRECATED and ignored (falcon-auth#2). C-039 drops the
            ``X-API-Version`` header altogether (RUL-050), and auth retired it when it moved to
            ``/v1`` (ppi-backend-auth#317, ``e8c4a13``). The version rides in ``path_template``
            alone (``/v1/internal/...``). Passing a value warns and sends nothing; a later release
            removes the argument.
        :param assume_customer_actor_type: REMOVED. The C-052 §3 deviation ended (RUL-188 6).
            Passing ``True`` refuses rather than being ignored, so a service that relied on it
            learns the feed is now read strictly.
        """
        if assume_customer_actor_type:
            raise ValueError(
                "assume_customer_actor_type has ended (RUL-188 6): auth emits actor_type, "
                "session_kind and delegations, and a missing required field is an error again "
                "(registry/TRUST-CONTEXT.md S4). Drop the argument"
            )
        if api_version is not None:
            warnings.warn(
                "api_version is deprecated and ignored: C-039 drops X-API-Version (RUL-050) and "
                "auth retired it (ppi-backend-auth#317). The version is in path_template "
                "(/v1/...); drop the argument -- a later release removes it",
                DeprecationWarning,
                stacklevel=2,
            )
        self._session_getter = session_getter
        self._path_template = path_template
        self._headers: dict[str, str] = {}

    async def fetch(self, session_ref: str, *, user_ref: str) -> TrustContext:
        path = self._path_template.format(session_ref=session_ref)
        try:
            session = self._session_getter()
            async with outbound.get(
                session, path, params={"user_ref": user_ref}, headers=self._headers
            ) as response:
                await outbound.refuse_redirect(response, call="trust-context")
                if response.status == 200:
                    try:
                        data = await response.json()
                    except (aiohttp.ContentTypeError, ValueError) as e:
                        raise UpstreamBadResponse("trust-context answered 200 without JSON") from e
                    return TrustContext.from_feed(data)
                await self._raise_for(response)
        except AuthzError:
            raise
        except ValidationError as e:
            # The response shape changed under us -- most likely `grants` went missing. Loud,
            # not silent: see the field comment above. Unusable, so 502 (C-066 §3).
            await logger.aerror("trust-context response failed validation", exc_info=e)
            raise UpstreamBadResponse(
                "trust-context response did not match the expected shape"
            ) from e
        except (aiohttp.ClientError, TimeoutError) as e:
            await logger.aerror("trust-context transport failure", exc_info=e)
            raise outbound.transport_failure(e, call="trust-context") from e
        raise AuthzUnavailable("trust-context returned no usable response")  # pragma: no cover

    async def _raise_for(self, response: aiohttp.ClientResponse) -> None:
        body: Any = None
        try:
            body = await response.json()
        except Exception:  # noqa: BLE001 -- an unparseable error body must not mask the status
            body = None
        code = _error_code(body)

        if response.status in (404, 410) or code == _AUTH_CODE_SESSION_MISS:
            # A logged-out, revoked or foreign session. DENY -- the client must re-authenticate,
            # not retry.
            #
            # 410 GONE is the status auth's owner expects for a session that ended, and it is
            # emphatically not an outage: falling through to the generic branch below would
            # answer AuthzUnavailable and tell the client to retry with backoff a request that
            # can never succeed. 404 and 410 differ only in whether the session ever existed,
            # which is not a distinction the caller can act on -- both mean re-authenticate.
            raise SessionMiss("session is not live, or is not owned by this subject")
        if response.status == 403:
            # OUR certificate lacks `trust:read`. A deployment fault; reporting it as a user denial
            # would read as "every user lost their permissions" during a bad rollout.
            await logger.aerror(
                "trust-context refused our certificate -- is `trust:read` granted to this service?",
                status=response.status,
            )
            raise AuthzMisconfigured("this service is not entitled to read trust context")
        await logger.aerror("trust-context error response", status=response.status, code=code, body=body)
        raise outbound.status_failure(response.status, call="trust-context")


def _error_code(body: Any) -> int | None:
    """auth's error envelope is `{"code": n}` or `{"error": {"code": n}}` -- accept both."""
    if not isinstance(body, dict):
        return None
    raw = body.get("code")
    if raw is None:
        nested = body.get("error")
        raw = nested.get("code") if isinstance(nested, dict) else None
    return raw if isinstance(raw, int) else None


DEFAULT_LAST_GOOD_TTL = 900     # the outage fallback: read only when the source is down

#: How long a ROUTINE operation may be served a cached trust context (C-079 §6, RUL-072 Q117).
#: Neither the convention nor its rulings name a number; 60 s is the conservative choice -- the
#: window this package held before C6, and C-078 §5's `jti_staleness` default, so a default
#: configuration never serves a routine copy the current-token check could not also rely on.
#: ``0`` turns the routine cache off (every read fresh, as in 0.9.x).
DEFAULT_ROUTINE_TTL = 60

#: The key the fetch time is stored under, beside the context's own fields. Inside the context's
#: JSON rather than wrapped around it, so a 0.9.x worker sharing the cache during a rolling deploy
#: still parses a new entry (``extra="allow"``) and keeps its outage fallback. Popped before
#: validation, so it never reaches a :class:`TrustContext`.
_FETCHED_AT = "falcon_auth_fetched_at"

#: What :meth:`TrustContextCache.forget` writes over a session's last-good copy. The two-method
#: :class:`Cache` has no delete, so an ended session's copy is OVERWRITTEN, never left to expire.
_TOMBSTONE = "ended"

# There is no separate grants TTL: the copy is the whole context, served whole for a routine
# operation or not at all (C-079 §6). A grants-only entry could never be assembled into one.


class Cache(Protocol):
    """The only contract. The consumer injects one; the package never constructs a client.

    Two async methods, and ``ttl`` in **seconds**::

        async def get(key)              -> the stored string, or None
        async def set(key, value, ttl)  -> None

    **An aiocache client satisfies this directly** -- verified against `aiocache` 0.12.3, whose
    ``SimpleMemoryCache.set(key, value, ttl=..., ...)`` and ``get(key, default=None, ...)``
    both bind positionally. So a consumer on the platform's Redis stack passes its own client
    straight in::

        TrustContextCache(aiocache.Cache(aiocache.Cache.REDIS, ...))

    No adapter, no wrapper. :class:`RedisCache` below exists only for a **redis-asyncio**
    client, whose ``set`` spells the expiry ``ex=`` rather than ``ttl=``; if your client already
    matches this protocol you do not need it.
    """

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
        """Write with a TTL, using redis-asyncio's ``ex=`` spelling.

        A TRANSPORT failure is swallowed to a miss, which is right: a cache is an optimisation,
        and if redis is down the service should get slower rather than start refusing people.

        A **signature** mismatch is not swallowed. Passing a client whose ``set`` does not take
        ``ex=`` -- an aiocache client, which spells it ``ttl=`` -- used to raise `TypeError`
        inside the blanket except, so the write was silently lost and the cache quietly stopped
        being one. Nothing failed, because a cache that always misses still authorizes
        correctly; it just never served a single last-good answer during an outage, which is the
        one moment it exists for.

        That is a wiring error, and it now says so. Note the fix is not to teach this class a
        second dialect: an aiocache client already satisfies :class:`Cache` directly, so it
        should be passed straight to :class:`TrustContextCache` rather than wrapped in this.
        """
        try:
            await self._client.set(self._key(key), value, ex=ttl)
        except TypeError as e:
            raise TypeError(
                f"{type(self._client).__name__}.set() does not accept `ex=` -- RedisCache is "
                f"for a redis-asyncio client. A client that spells the expiry `ttl=` (aiocache) "
                f"already satisfies the Cache protocol: pass it to TrustContextCache directly "
                f"instead of wrapping it in RedisCache"
            ) from e
        except Exception:  # noqa: BLE001 -- a transport failure is a miss; see the class docstring
            return None


class TrustContextCache:
    """One copy per session, stamped with its fetch time, read two ways -- see the module docstring.

    - :meth:`read` -- the copy and its **age** in seconds. The resolver serves it to a ROUTINE
      operation while ``age < routine_ttl`` (C-079 §6), and to a routine operation of any age
      when auth is unreachable (the last-good path, C-017/RUL-212).
    - :meth:`read_last_good` -- the same copy without its age, kept for callers of 0.9.x.

    The age is real: the fetch time travels with the copy, so every worker sharing the cache
    agrees on it. A copy with no fetch time -- written by 0.9.x -- is of **unknown** age,
    ``math.inf``: never fresh, still a last-good copy. So is one stamped in the future (another
    worker's clock ahead of ours): unknown, never fresh.
    """

    def __init__(
        self,
        cache: Cache,
        *,
        last_good_ttl: int = DEFAULT_LAST_GOOD_TTL,
        routine_ttl: float = DEFAULT_ROUTINE_TTL,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """
        :param routine_ttl: seconds a routine operation may be served a cached copy; ``0`` turns
            the routine cache off. Not a storage TTL: the entry lives for the longer of the two.
        :param clock: wall-clock seconds -- shared across workers through the stored stamp, so
            it must be wall time, not a monotonic clock. Injectable for tests.
        """
        if not (math.isfinite(routine_ttl) and routine_ttl >= 0):
            raise ValueError(f"routine_ttl is a finite number of seconds >= 0, not {routine_ttl!r}")
        self._cache = cache
        self._last_good_ttl = last_good_ttl
        self._routine_ttl = float(routine_ttl)
        self._clock = clock
        # The entry must outlive BOTH readings of it, and so must the tombstone that ends it.
        self._storage_ttl = max(int(last_good_ttl), math.ceil(routine_ttl))

    @property
    def routine_ttl(self) -> float:
        return self._routine_ttl

    async def write(self, context: TrustContext) -> None:
        """Record this as the session's current copy. Called after every successful ENABLED fetch."""
        payload = context.model_dump(mode="json")
        payload[_FETCHED_AT] = self._clock()
        await self._cache.set(
            f"lastgood:{context.session_ref}", json.dumps(payload), self._storage_ttl
        )

    async def forget(self, session_ref: str) -> None:
        """Destroy the copy of a session auth has said is over (falcon-auth#30).

        Called when auth DENIES the session -- 404/410, or a state other than ENABLED. Without
        it, the copy written before the denial is served again: to the next routine operation
        (for up to ``routine_ttl``) and the moment auth becomes unreachable (for up to
        ``last_good_ttl``), on every worker sharing the cache -- a revoked session transacting
        again, against C-038's live revocation.

        It overwrites rather than deletes (the protocol has no delete), for as long as a copy
        could have lived. ⚠ It cannot stop a fetch that succeeded on another worker just BEFORE
        the revocation from writing its copy just AFTER this. That copy is then served to routine
        operations for up to ``routine_ttl`` (C-079 §6 accepts that window for routine reads),
        and the next fresh read's denial -- any consequential operation -- closes it.
        """
        await self._cache.set(f"lastgood:{session_ref}", _TOMBSTONE, self._storage_ttl)

    async def read(self, session_ref: str) -> tuple[TrustContext, float] | None:
        """The session's copy and its age in seconds (``math.inf`` if unknown), or None.

        Unprojected: the caller projects the elevation window (:meth:`TrustContext.project`).
        """
        raw = await self._cache.get(f"lastgood:{session_ref}")
        if raw is None or raw == _TOMBSTONE:
            return None
        try:
            data = json.loads(raw)
            fetched_at = data.pop(_FETCHED_AT, None) if isinstance(data, dict) else None
            context = TrustContext.model_validate(data)
        except Exception:  # noqa: BLE001 -- a corrupt entry is a miss, never a crash
            return None
        return context, self._age(fetched_at)

    def _age(self, fetched_at: Any) -> float:
        # bool is an int; a stamp is never one.
        if not isinstance(fetched_at, (int, float)) or isinstance(fetched_at, bool):
            return math.inf                      # a 0.9.x entry, or a mangled stamp
        age = self._clock() - float(fetched_at)
        if not math.isfinite(age) or age < 0:
            return math.inf                      # stamped in our future: unknown, never fresh
        return age

    async def read_last_good(self, session_ref: str) -> TrustContext | None:
        """The stale copy served when the source is unreachable -- routine operations only (§10)."""
        found = await self.read(session_ref)
        return found[0] if found is not None else None

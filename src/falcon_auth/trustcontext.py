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

THE SCHEMA IS THE PLATFORM'S: `registry/TRUST-CONTEXT.md` (normative, RUL-162-165). Besides the
session and trust fields it requires `grants`, `actor_type` (C-052), `actor_kind` iff OPERATOR,
`session_kind` and `delegations` (C-053). A missing required field is never defaulted (S4) --
except under the one recorded deviation, `assume_customer_actor_type` (C-052 §3, RUL-162).

KNOWN BREAK, recorded rather than worked around: auth's feed (`05ebd8c`) carries **no `grants`**
and none of the C-052/C-053 fields yet, so `TrustContext` fails validation against a live auth on
every call. Closing it is a build at auth, owed under the schema -- not a local edit. The
deviation covers `actor_type` (and the C-053 fields that ship with it); it never covers `grants`.

The field is typed REQUIRED deliberately in the face of that. Making it optional would turn a
service that cannot resolve anybody into one that silently resolves everybody to "holds nothing"
and 403s -- the original called that "a total outage wearing the costume of a permissions
problem". Failing loudly is the honest state of the layer until auth ships.

RENAMED from `entitlements`, which is what the two services this was ported from call it. C-038
(RUL-074) rules that what auth emits is a coarse **grant**, never a service's entitlement, and
X-09 rules the field is renamed rather than accommodated. `grants` is a plain list, and there is
⛔ no `grant_epoch` (RUL-134); the feed carries a strong `ETag` (S2), which this package does not
use because it keeps no trust-context cache to revalidate.
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
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from structlog import get_logger
import aiohttp

from .errors import (
    AuthzUnavailable,
    SessionMiss,
)

__all__ = (
    "ActorKind",
    "ActorType",
    "Cache",
    "DEFAULT_LAST_GOOD_TTL",
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
    would reach every subject at once."""

    model_config = ConfigDict(extra="allow")

    ref: str
    grant: str
    subject_ref: str
    #: RFC 3339 UTC ``Z``, milliseconds (C-009).
    valid_until: str
    #: The operator's case. Present iff the session is SHADOW (C-053 §8).
    case_ref: str | None = None

    @field_validator("valid_until")
    @classmethod
    def _rfc3339_z(cls, value: str) -> str:
        if not value.endswith("Z"):
            raise ValueError("valid_until must be RFC 3339 UTC with a 'Z' (C-009)")
        datetime.fromisoformat(value[:-1] + "+00:00")
        return value

    def live(self, now: datetime | None = None) -> bool:
        until = datetime.fromisoformat(self.valid_until[:-1] + "+00:00")
        return (now or datetime.now(UTC)) < until


class TrustContext(BaseModel):
    """One session's authorization posture -- `registry/TRUST-CONTEXT.md`, the normative schema
    (RUL-162-165).

    ``extra="allow"``: auth may add fields without breaking us (S4: additive only, by ruling).
    ⛔ A missing REQUIRED field is never defaulted (S4) -- it fails validation, which the client
    turns into a loud 503 -- except under the one recorded deviation, see
    :meth:`from_feed`'s ``assume_customer_actor_type``.
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
    #: True only when ``actor_type`` was ABSENT and assumed CUSTOMER under the recorded C-052 §3
    #: deviation (RUL-162). Never set from the wire.
    actor_type_assumed: bool = Field(default=False, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def _never_from_the_wire(cls, data: Any) -> Any:
        # `actor_type_assumed` is set by `from_feed` alone. A response carrying it is ignored,
        # so nothing upstream can mark a session as "assumed" -- or un-mark one.
        if isinstance(data, dict) and "actor_type_assumed" in data:
            data = {k: v for k, v in data.items() if k != "actor_type_assumed"}
        return data

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
    def from_feed(cls, data: Any, *, assume_customer_actor_type: bool = False) -> "TrustContext":
        """Parse a trust-context response, strictly -- with the one recorded deviation.

        :param assume_customer_actor_type: the C-052 §3 deviation (RUL-162, platform-conventions
            #23): while auth's feed does not yet carry ``actor_type``, its absence is read as
            ``CUSTOMER``. **Off by default.** A service that turns it on records a C-052
            exception in its ``exceptions/<service>.md``, and it **expires at whichever comes
            first: auth emitting ``actor_type``, or auth enabling any non-customer identity**.

            It covers only what auth has not shipped alongside ``actor_type``: an absent
            ``session_kind`` is read as ``NORMAL`` and absent ``delegations`` as ``[]`` -- the
            deny direction (no shadow session, no subject reached). ⚠ That extension is this
            package's reading of RUL-162, put to the platform. ``grants`` is never defaulted.
            The route rule -- an assumed CUSTOMER never opens an OPERATOR-only route -- follows
            from the actor-type guard, since the assumed type IS customer. Logged every time.
        """
        if not assume_customer_actor_type or not isinstance(data, dict) or "actor_type" in data:
            return cls.model_validate(data)
        filled = {"session_kind": "NORMAL", "delegations": [], **data, "actor_type": "CUSTOMER"}
        logger.warning(
            "trust_context_actor_type_assumed",
            session_ref=data.get("session_ref"),
            deviation="C-052 §3 (RUL-162): absent actor_type read as CUSTOMER",
        )
        context = cls.model_validate(filled)
        object.__setattr__(context, "actor_type_assumed", True)
        return context

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
        assume_customer_actor_type: bool = False,
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
        # The recorded C-052 §3 deviation -- see TrustContext.from_feed. Off by default.
        self._assume_customer = assume_customer_actor_type
        self._headers = {"X-API-Version": api_version} if api_version is not None else {}

    async def fetch(self, session_ref: str, *, user_ref: str) -> TrustContext:
        path = self._path_template.format(session_ref=session_ref)
        try:
            session = self._session_getter()
            async with session.get(
                path, params={"user_ref": user_ref}, headers=self._headers
            ) as response:
                if response.status == 200:
                    return TrustContext.from_feed(
                        await response.json(),
                        assume_customer_actor_type=self._assume_customer,
                    )
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


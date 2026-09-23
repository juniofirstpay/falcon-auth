"""Layer 3: turn an authenticated identity into the entitlements it holds.

Three levels, per C-038, and this module is where the first becomes the second:

    grant         auth's word    coarse, estate-wide, the slowest-moving
    entitlement   this service   fine-grained, what a principal holds HERE
    capability    the route      what an endpoint demands -- enforcer.py's business

The feed carries GRANTS. `_compose` expands them into this service's entitlements and
intersects the result with local state. A service adding or retiring routes changes its own
entitlements and capabilities and never the grant vocabulary at auth -- that separation is
the whole reason the middle level exists.

Entitlements are resolved **server-side**, never read off the token. §4 gives two reasons and the
second is decisive: a claim the service acts on is authorization data whatever it is named, and if it
rides the token then **revocation becomes token lifetime** -- suspend a compromised user and they
keep transacting until it expires. For a service that moves money that is the wrong failure mode.

Two principal kinds arrive here and only one of them has a session:

    JWT user          -> look up the session's grants at the trust source, keyed by `sid`
    api-key service   -> its grants are its own configuration; there is no session to look up

The composition §5 specifies is `expand(granted_roles) ∩ permitted_by(local_subject_state)`. Both
halves are injected because both are the *host's* knowledge:

- **`expand`** maps the identity provider's coarse vocabulary to the service's fine-grained
  entitlements. It defaults to pass-through, which is what both services run today.

  C-038 OWES A CHANGE HERE (Phase C): the expansion must stop being a hand-written callable
  and become `g, <grant>, <entitlement>` rows in the SAME casbin policy set as the capability
  gate -- "no longer hand-written code" (RUL-075). The injection point stays useful for the
  local veto below; it is the expansion half that moves into the policy.
- **`veto`** is the local-state intersection -- whether *this service's* record for the subject is
  active, suspended or closed. A host with no subject aggregate of its own supplies none, and should
  say so in its build status rather than pretend the layer is enforced.
"""
from collections.abc import Callable
from typing import (
    Any,
    Protocol,
)

from structlog import get_logger

from ..errors import (
    AuthzUnavailable,
    CapabilityDenied,
)
from ..principal import Principal
from ..trustcontext import (
    TrustContext,
    TrustContextCache,
    TrustContextClient,
)

__all__ = ("AuthenticatedUser", "AuthServiceResolver", "GrantAllResolver", "Resolver")

logger = get_logger("authz")

DEFAULT_SESSION_CLAIM = "sid"
DEFAULT_SERVICE_ACCOUNT_TYPE = "service-account"


class AuthenticatedUser(Protocol):
    """Structural view of whatever the host's authn hook puts on the request.

    Matched by `falcon_utils.auth_v2.UserAPIProto` without the package depending on it, so a host
    with a different authn library needs no adapter.
    """

    @property
    def id(self) -> Any: ...
    @property
    def type(self) -> Any: ...
    def get(self, key: str) -> Any: ...


class Resolver(Protocol):
    async def resolve(self, user: AuthenticatedUser, *, consequential: bool = False) -> Principal: ...


class AuthServiceResolver:
    """Resolves against the trust source, with the §10 caching and availability posture."""

    def __init__(
        self,
        client: TrustContextClient,
        cache: TrustContextCache,
        *,
        expand: Callable[[list[str]], list[str]] | None = None,
        veto: Callable[[str, list[str]], list[str]] | None = None,
        session_claim: str = DEFAULT_SESSION_CLAIM,
        service_account_type: str = DEFAULT_SERVICE_ACCOUNT_TYPE,
    ) -> None:
        self._client = client
        self._cache = cache
        self._expand = expand
        self._veto = veto
        self._session_claim = session_claim
        self._service_account_type = service_account_type

    async def resolve(self, user: AuthenticatedUser, *, consequential: bool = False) -> Principal:
        """Resolve `user` to a `Principal`.

        `consequential` marks an operation for which the entitlement *is* the control (§10): it takes
        a fresh read rather than the cache, and fails closed rather than serving last-good grants.
        The flag is plumbed but nothing sets it until a service fills in its §9.2 registry.
        """
        if str(user.type) == self._service_account_type:
            return self._service_account(user)

        session_ref = user.get(self._session_claim)
        if not session_ref:
            # No session claim: an identity we cannot ask about. §7 -- fail closed rather than guess.
            await logger.awarning("no session claim on the token; denying", claim=self._session_claim)
            raise CapabilityDenied("token carries no session reference")

        context = await self._context(str(session_ref), str(user.id), consequential=consequential)
        return self._principal(context)

    # ── principal kinds ──────────────────────────────────────────────────────────

    def _service_account(self, user: AuthenticatedUser) -> Principal:
        """An api-key caller. Its grants are its config entry -- it holds no session to resolve.

        The trust fields stay `None`: this principal has no assurance posture, and reporting one
        would let an assurance rule read a service account as merely "not elevated" rather than
        "not applicable".
        """
        entitlements = list(user.get("entitlements") or [])
        return Principal(user_ref=str(user.id), entitlements=self._compose(str(user.id), entitlements))

    def _principal(self, context: TrustContext) -> Principal:
        return Principal(
            user_ref=context.user_ref,
            entitlements=self._compose(context.user_ref, list(context.grants)),
            session_ref=context.session_ref,
            session_trust_level=context.session_trust_level,
            device_trust_level=context.device_trust_level,
            trust_elevated_until=context.trust_elevated_until,
        )

    # ── the §5 composition ───────────────────────────────────────────────────────

    def _compose(self, user_ref: str, granted: list[str]) -> list[str]:
        expanded = self._expand(granted) if self._expand is not None else granted
        return self._veto(user_ref, expanded) if self._veto is not None else expanded

    # ── §10: freshness, and what happens when the source is down ─────────────────

    async def _context(self, session_ref: str, user_ref: str, *, consequential: bool) -> TrustContext:
        if not consequential:
            cached = await self._cache.read(session_ref)
            if cached is not None:
                # Locally project the elevation window forward. §10: this catches expiry ONLY --
                # never a disabled device or a demoted session -- which is exactly why a
                # consequential operation skips the cache entirely rather than trusting this.
                return cached.project()

        try:
            context = await self._client.fetch(session_ref, user_ref=user_ref)
        except AuthzUnavailable:
            if consequential:
                # The entitlement IS the control here. Fail closed.
                raise
            last_good = await self._cache.read_last_good(session_ref)
            if last_good is None:
                raise
            await logger.awarning(
                "trust source unreachable; serving last-good grants for a routine operation",
                session_ref=session_ref,
            )
            return last_good.project()

        await self._cache.write(context)
        return context


class GrantAllResolver:
    """Grants a FIXED entitlement set to EVERY caller, without contacting the trust source.

    **DEV/TEST ONLY. Wiring this in production makes every authenticated caller a superuser.**
    It must be gated behind an explicit, default-off flag at the composition root, and the host must
    log loudly at startup when it is on.

    **What it exists for.** Entitlements resolve from the auth service, so a developer with no auth
    service reachable — or, more commonly, whose certificate has not yet been granted the read scope
    — gets `503 authz_unavailable` on every gated route. That is the correct production behaviour and
    a useless local one. This short-circuits layer 3 so the rest of the stack stays exercisable.

    **What it deliberately does NOT do — and this is the important part.** It keeps each caller's own
    `user_ref`. It would be simpler to resolve every request to one fixed dev subject, and that is a
    trap: object ownership (§7) compares the *caller's* ref to the object's owner, so a single-subject
    resolver silently makes every object look like it belongs to the same person. Ownership bugs then
    become invisible in dev and appear in production. Grant-all is about **entitlements only**;
    identity, and therefore layer 4, stays real and stays testable across several people.

    The trust fields stay `None`: this resolver knows nothing about assurance, and reporting a
    fabricated trust level would let an assurance rule silently pass in dev on evidence that does not
    exist.
    """

    def __init__(self, entitlements: list[str]) -> None:
        self._entitlements = list(entitlements)

    async def resolve(self, user: AuthenticatedUser, *, consequential: bool = False) -> Principal:
        return Principal(user_ref=str(user.id), entitlements=list(self._entitlements))

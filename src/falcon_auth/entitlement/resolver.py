"""Layer 3: turn an authenticated identity into the entitlements it holds.

Three levels, per C-038, and this module is where the first becomes the second:

    grant         auth's word    coarse, estate-wide, the slowest-moving
    entitlement   this service   fine-grained, what a principal holds HERE
    capability    the route      what an endpoint demands -- enforcer.py's business

The feed carries GRANTS, and they travel to the gate as-is. The grant -> entitlement expansion
is NOT performed here any more: it is `g` rows in the same casbin policy set as the capability
gate, so one `Enforce(grant, capability)` walks both hops (RUL-075, Q119). A service adding or
retiring routes changes its own entitlements and capabilities and never the grant vocabulary at
auth -- that separation is the whole reason the middle level exists.

Entitlements are resolved **server-side**, never read off the token. §4 gives two reasons and the
second is decisive: a claim the service acts on is authorization data whatever it is named, and if it
rides the token then **revocation becomes token lifetime** -- suspend a compromised user and they
keep transacting until it expires. For a service that moves money that is the wrong failure mode.

ONE principal kind arrives here: a JWT user, whose grants are looked up at the trust source
by `sid`.

REMOVED: a second branch resolved an "api-key service account" whose entitlements came from
its own configuration. It served an authentication method that does not exist. C-038's set of
per-plane methods is closed -- JWT on the user plane, mTLS on the service plane, HMAC or a
one-shot token on callbacks, nothing on public -- and api-key is not among them. Neither
consuming service registers an api-key authenticator, and orders removed its own: the key
lived in a committed settings file, so it was baked into the image and present in git history,
and its single entry held the one entitlement that switches the ownership layer off.

The capability it provided is real and has moved rather than gone. A peer backend reading
across parties now authenticates by certificate on the SERVICE plane, where the CN allow-list
carries its capabilities directly (C-018, C-038 Q93). The two vocabularies never meet, which
is the point: a service account resolving entitlements through the USER-plane resolver is the
collapse C-033 forbids.

The composition was `expand(granted) ∩ permitted_by(local_subject_state)`. The first half has
moved; the second stays, and the reason they part company is that only one of them is policy:

- **`expand` is gone from here.** It is `g` rows now -- reviewable data in the policy set, not a
  hand-written callable (RUL-075). The parameter is still accepted and REFUSES a callable rather
  than ignoring one, so a host that supplies an expansion is told where it went instead of
  watching it silently stop applying. Pass the mapping to `build_enforcer(expansion=...)`.

- **`veto` stays, and is now the ONLY subtractive lever in the whole model.** Grants compose as
  a union and are additive-only -- there is no deny effect anywhere in the policy -- so a
  suspension can never be expressed as a grant or as the absence of one. It is this service's
  own record of whether the subject is active, suspended or closed. A host with no subject
  aggregate supplies none, and should say so in its build status rather than pretend the layer
  is enforced.
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

    # `type` is part of the object the authenticator builds and is kept here so the Protocol
    # still describes it -- but NOTHING in this module reads it. The branch that did resolved
    # an api-key service account, and it is gone; see the module docstring.


class Resolver(Protocol):
    async def resolve(self, user: AuthenticatedUser, *, consequential: bool = False) -> Principal: ...


class AuthServiceResolver:
    """Resolves against the trust source, with the §10 caching and availability posture."""

    def __init__(
        self,
        client: TrustContextClient,
        cache: TrustContextCache,
        *,
        expand: None = None,
        veto: Callable[[str, list[str]], list[str]] | None = None,
        session_claim: str = DEFAULT_SESSION_CLAIM,
    ) -> None:
        if expand is not None:
            raise ValueError(
                "the grant -> entitlement expansion is no longer a callable (C-038/RUL-075): "
                "it is `g` rows in the same policy set as the capability gate. Pass the mapping "
                "to build_enforcer(expansion={grant: [entitlement, ...]}) instead. Refusing "
                "rather than ignoring, so an expansion that stops applying is not silent"
            )
        self._client = client
        self._cache = cache
        self._veto = veto
        self._session_claim = session_claim

    async def resolve(self, user: AuthenticatedUser, *, consequential: bool = False) -> Principal:
        """Resolve `user` to a `Principal`.

        `consequential` marks an operation for which the entitlement *is* the control (§10): it takes
        a fresh read rather than the cache, and fails closed rather than serving last-good grants.
        The flag is plumbed but nothing sets it until a service fills in its §9.2 registry.
        """
        session_ref = user.get(self._session_claim)
        if not session_ref:
            # No session claim: an identity we cannot ask about. §7 -- fail closed rather than guess.
            await logger.awarning("no session claim on the token; denying", claim=self._session_claim)
            raise CapabilityDenied("token carries no session reference")

        context = await self._context(str(session_ref), str(user.id), consequential=consequential)
        return self._principal(context)

    def _principal(self, context: TrustContext) -> Principal:
        return Principal(
            user_ref=context.user_ref,
            entitlements=self._compose(context.user_ref, list(context.grants)),
            session_ref=context.session_ref,
            session_trust_level=context.session_trust_level,
            device_trust_level=context.device_trust_level,
            trust_elevated_until=context.trust_elevated_until,
        )

    # ── the composition, now one half ────────────────────────────────────────────

    def _compose(self, user_ref: str, granted: list[str]) -> list[str]:
        """The grants, minus whatever this service's own record of the subject removes.

        The expansion half is gone -- it is `g` rows in the policy -- so what the principal
        carries is the grants themselves, and the gate resolves them. The veto is all that is
        left to apply here, and it is the only subtractive lever in the model.
        """
        return self._veto(user_ref, granted) if self._veto is not None else granted

    # ── §10: freshness, and what happens when the source is down ─────────────────

    async def _context(self, session_ref: str, user_ref: str, *, consequential: bool) -> TrustContext:
        # No warm path. Assurance is live (C-038/RUL-072): a cached trust level is one a demoted
        # device can keep transacting behind for the length of the window. `consequential` still
        # governs what happens when the source is DOWN, below -- it no longer selects between a
        # cached read and a fresh one, because there is no cached read to select.
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

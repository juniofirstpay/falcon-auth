"""C-078 (falcon-auth#41): the verifier's floor, three tunables, and the current-token check.

One section per row of the issue. Every refusal has a positive control beside it -- the same
token or context with only the defect removed -- so a test cannot pass because something else
refused first.
"""

from __future__ import annotations

import asyncio
import math
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from falcon_auth.adapters.authenticators import JWTAuthenticator, Selector
from falcon_auth.entitlement.resolver import (
    DEFAULT_JTI_STALENESS,
    AuthServiceResolver,
    check_current_jti,
)
from falcon_auth.errors import (
    AuthzUnavailable,
    CapabilityDenied,
    TokenExpired,
    TokenSuperseded,
    Unauthenticated,
)
from falcon_auth.identity.jwks import (
    DEFAULT_LEEWAY,
    DEFAULT_MAX_TOKEN_LIFETIME,
    EXPIRED,
    InvalidToken,
    JWKSStore,
    JWKSVerifier,
    REQUIRED_CLAIMS,
)
from falcon_auth.trustcontext import SESSION_STATE_ENABLED, TrustContext, TrustContextCache

ISSUER = "https://auth.test"
AUDIENCE = "https://api.test"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_JWK = jwt.algorithms.RSAAlgorithm.to_jwk(_KEY.public_key(), as_dict=True)
_JWK.update(kid="k1", alg="RS256", use="sig")


def _token(**overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "sid": "sess-1", "jti": "jti-1",
        "iat": now, "exp": now + 300,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, _KEY, algorithm="RS256", headers={"kid": "k1"})


def _verifier(**kwargs):
    store = JWKSStore(lambda: None)  # type: ignore[arg-type,return-value]
    store.pin_keys([_JWK])
    kwargs.setdefault("issuer", ISSUER)
    kwargs.setdefault("audience", AUDIENCE)
    kwargs.setdefault("forwarded_claims", frozenset({"sid"}))
    return JWKSVerifier(store, **kwargs)


def _verify(token, **kwargs):
    return asyncio.run(_verifier(**kwargs).verify(token))


def _reason(token, **kwargs):
    with pytest.raises(InvalidToken) as e:
        _verify(token, **kwargs)
    return e.value.reason


# ── row 1: `require` is a floor ─────────────────────────────────────────────────────────────


def test_the_floor_is_the_five_claims():
    assert set(REQUIRED_CLAIMS) == {"iat", "exp", "sub", "sid", "jti"}


def test_a_full_token_verifies():
    """The positive control for everything below."""
    assert _verify(_token())["sid"] == "sess-1"


@pytest.mark.parametrize("claim", ["sid", "jti"])
def test_a_consumer_shorter_require_list_does_not_shrink_the_floor(claim):
    """Before v0.10.0 a consumer's `options` REPLACED the defaults -- persona passes
    `require=["iat", "exp", "sub"]` -- so a token without `sid`/`jti` verified."""
    shorter = {
        "require": ["iat", "exp", "sub"], "verify_signature": True, "verify_aud": True,
        "verify_iss": True, "verify_exp": True, "verify_iat": True, "verify_nbf": True,
        "strict_aud": False,
    }
    assert _verify(_token(), options=shorter)                      # control
    assert _reason(_token(**{claim: None}), options=shorter) == "MissingRequiredClaimError"


def test_a_consumer_may_add_to_the_floor():
    more = {"require": ["nonce"]}
    assert _verify(_token(nonce="n"), options=more)                # control
    assert _reason(_token(), options=more) == "MissingRequiredClaimError"
    # ...and adding does not remove the floor.
    assert _reason(_token(nonce="n", sid=None), options=more) == "MissingRequiredClaimError"


@pytest.mark.parametrize(
    "flag", ["verify_signature", "verify_exp", "verify_iat", "verify_iss", "verify_aud"]
)
def test_a_mandatory_check_cannot_be_switched_off(flag):
    with pytest.raises(ValueError):
        _verifier(options={flag: False})


@pytest.mark.parametrize("missing", ["issuer", "audience"])
def test_an_empty_issuer_or_audience_refuses_to_start(missing):
    """C-078 §5: a verifier with `iss` or `aud` unset refuses to start -- an empty string too."""
    with pytest.raises(ValueError):
        _verifier(**{missing: ""})


# ── row 2: a missing floor claim is 401 PLAT0101 at verification ───────────────────────────


@pytest.mark.parametrize("claim", REQUIRED_CLAIMS)
def test_a_token_missing_a_floor_claim_is_invalid(claim):
    assert _reason(_token(**{claim: None})) == "MissingRequiredClaimError"


@pytest.mark.parametrize("claim", ["sid", "jti"])
@pytest.mark.parametrize("value", ["", 7])
def test_an_empty_or_non_string_sid_or_jti_is_invalid(claim, value):
    reason = _reason(_token(**{claim: value}))
    assert reason in {f"malformed_{claim}", "InvalidSubjectError", "InvalidJTIError"}


class _Req:
    def __init__(self, token):
        self._token = token

    def get_header(self, name):
        return f"Bearer {self._token}"


def _authenticate(token, **kwargs):
    auth = JWTAuthenticator(_verifier(**kwargs), Selector("Authorization", "Bearer"))
    return asyncio.run(auth(_Req(token)))


@pytest.mark.parametrize("claim", ["sid", "jti"])
def test_a_token_without_sid_or_jti_is_401_plat0101_at_the_authenticator(claim):
    """Not the resolver's `CapabilityDenied` (403): an identity defect, refused as one."""
    assert _authenticate(_token())                                 # control
    with pytest.raises(Unauthenticated) as e:
        _authenticate(_token(**{claim: None}))
    assert e.value.plat_code == "PLAT0101"
    assert not isinstance(e.value, (TokenExpired, CapabilityDenied))


def test_a_token_missing_sid_and_expired_is_not_merely_expired():
    """RUL-175: PLAT0108 only when expiry ALONE fails. PyJWT checks `require` first."""
    past = {"iat": int(time.time()) - 400, "exp": int(time.time()) - 100}
    assert _reason(_token(**past)) == EXPIRED                      # control
    assert _reason(_token(**past, sid=None)) != EXPIRED


# ── row 3: the lifetime ceiling ────────────────────────────────────────────────────────────


def test_the_default_ceiling_is_an_hour():
    assert DEFAULT_MAX_TOKEN_LIFETIME == 3600


def test_a_lifetime_at_the_ceiling_verifies_and_one_second_over_is_refused():
    now = int(time.time())
    assert _verify(_token(iat=now, exp=now + 3600))                 # control: at the ceiling
    assert _reason(_token(iat=now, exp=now + 3601)) == "lifetime_exceeds_ceiling"


def test_a_millisecond_iat_is_measured_as_auth_measures_it():
    """Auth mints `iat` with milliseconds and `exp = int(iat) + ttl` (AUTH-ADR-222): a 3600 s
    token measures 3600 whatever its fraction, so it must not be refused at the boundary."""
    iat = int(time.time()) + 0.999
    assert _verify(_token(iat=iat, exp=int(iat) + 3600))


def test_the_ceiling_is_tunable():
    now = int(time.time())
    assert _verify(_token(iat=now, exp=now + 600), max_token_lifetime=600)
    assert _reason(
        _token(iat=now, exp=now + 601), max_token_lifetime=600
    ) == "lifetime_exceeds_ceiling"


def test_an_over_long_lifetime_is_401_plat0101_not_plat0108():
    now = int(time.time())
    with pytest.raises(Unauthenticated) as e:
        _authenticate(_token(iat=now, exp=now + 7200))
    assert e.value.plat_code == "PLAT0101" and not isinstance(e.value, TokenExpired)


def test_an_over_long_token_that_has_also_expired_is_not_merely_expired():
    now = int(time.time())
    assert _reason(_token(iat=now - 7300, exp=now - 100)) != EXPIRED


# ── row 4: leeway ──────────────────────────────────────────────────────────────────────────


def test_the_default_leeway_is_30_seconds():
    assert DEFAULT_LEEWAY == 30


def test_a_token_ten_seconds_past_exp_is_inside_the_default_leeway():
    now = int(time.time())
    skewed = _token(iat=now - 300, exp=now - 10)
    assert _verify(skewed)["sub"] == "user-1"
    # The control: with v0.9.0's leeway of 0 the same token is expired.
    assert _reason(skewed, leeway=0.0) == EXPIRED


def test_a_token_past_the_leeway_is_expired():
    now = int(time.time())
    assert _reason(_token(iat=now - 300, exp=now - 45)) == EXPIRED


def test_a_negative_leeway_is_refused():
    with pytest.raises(ValueError):
        _verifier(leeway=-1)


# ── the jti reaches the resolver ───────────────────────────────────────────────────────────


def test_jti_is_forwarded_whatever_the_consumers_allowlist():
    """Persona forwards `{"sid"}` only. Without this the check would see no `jti` -- and a
    consumer forgetting to list it would have the check silently pass."""
    v = _verifier(forwarded_claims=frozenset({"sid"}))
    claims = asyncio.run(v.verify(_token(entitlements=["X"])))
    assert v.principal_claims(claims) == {"sid": "sess-1", "jti": "jti-1"}


# ── row 5 and 6: the current-token check ───────────────────────────────────────────────────


CTX = {
    "session_ref": "sess-1", "user_ref": "user-1", "client_ref": "client-1",
    "device_ref": "device-1", "session_state": SESSION_STATE_ENABLED, "device_trust_level": 3,
    "session_trust_level": 1, "trust_elevated_until": None, "actor_type": "CUSTOMER",
    "session_kind": "NORMAL", "delegations": [], "grants": ["CUSTOMER_GRANT"],
}

_ABSENT = object()


def _ctx(current_jti=_ABSENT):
    data = dict(CTX)
    if current_jti is not _ABSENT:
        data["current_jti"] = current_jti
    return TrustContext.from_feed(data)


class _Mem:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ttl):
        self.store[key] = value


class _Auth:
    def __init__(self, current_jti=_ABSENT):
        self.current_jti = current_jti
        self.down = False

    async def fetch(self, session_ref, *, user_ref):
        if self.down:
            raise AuthzUnavailable("down")
        return _ctx(self.current_jti)


class _User:
    def __init__(self, **claims):
        self.id = "user-1"
        self.type = "user"
        self._claims = {"sid": "sess-1", **claims}

    def get(self, key):
        return self._claims.get(key)


def _resolver(auth, **kw):
    return AuthServiceResolver(auth, TrustContextCache(_Mem()), **kw)


def test_the_feed_parses_current_jti_and_tolerates_its_absence():
    assert _ctx("jti-1").current_jti == "jti-1"
    assert _ctx(None).current_jti is None
    assert _ctx().current_jti is None


def test_the_default_staleness_is_60_seconds():
    assert DEFAULT_JTI_STALENESS == 60


@pytest.mark.parametrize("strict", [False, True], ids=["lenient", "strict"])
async def test_the_current_token_resolves(strict):
    """The positive control for the refusals below."""
    p = await _resolver(_Auth("jti-1"), strict_current_jti=strict).resolve(_User(jti="jti-1"))
    assert p.session_ref == "sess-1"


@pytest.mark.parametrize("strict", [False, True], ids=["lenient", "strict"])
async def test_a_superseded_token_is_401_plat0108(strict):
    """Refused in BOTH modes once the feed names a current token: lenient only governs a feed
    that names none (RUL-265 Q-J8)."""
    with pytest.raises(TokenSuperseded) as e:
        await _resolver(_Auth("jti-2"), strict_current_jti=strict).resolve(_User(jti="jti-1"))
    assert e.value.plat_code == "PLAT0108"
    assert isinstance(e.value, TokenExpired)        # a host mapping expiry maps this too


async def test_end_to_end_a_superseded_token_from_the_verifier_is_refused():
    """The verifier's forwarded claims are what the resolver reads."""
    v = _verifier(forwarded_claims=frozenset({"sid"}))
    claims = await v.verify(_token(jti="old"))
    user = _User(**v.principal_claims(claims))
    with pytest.raises(TokenSuperseded):
        await _resolver(_Auth("new")).resolve(user)
    assert await _resolver(_Auth("old")).resolve(user)


# rollout: the feed carries no current_jti


@pytest.mark.parametrize("current", [_ABSENT, None], ids=["absent", "null"])
async def test_lenient_a_feed_with_no_current_jti_logs_and_passes(current):
    from structlog.testing import capture_logs

    with capture_logs() as logs:
        p = await _resolver(_Auth(current)).resolve(_User(jti="anything"))
    assert p.session_ref == "sess-1"
    assert any("current-token check skipped" in e["event"] for e in logs)


async def test_strict_a_feed_without_the_field_is_503_not_401():
    """The feed predates auth#365: strict was switched on before auth deployed. Not the
    token's fault -- the client's refresh would not fix it."""
    with pytest.raises(AuthzUnavailable) as e:
        await _resolver(_Auth(), strict_current_jti=True).resolve(_User(jti="jti-1"))
    assert e.value.plat_code == "PLAT0302"


async def test_strict_a_null_current_jti_is_plat0108():
    """Auth's null: a session last minted before its column existed. The token in hand predates
    it; a refresh mints one auth names."""
    with pytest.raises(TokenSuperseded):
        await _resolver(_Auth(None), strict_current_jti=True).resolve(_User(jti="jti-1"))


async def test_strict_a_principal_without_jti_is_401_plat0101():
    with pytest.raises(Unauthenticated) as e:
        await _resolver(_Auth("jti-1"), strict_current_jti=True).resolve(_User())
    assert e.value.plat_code == "PLAT0101" and not isinstance(e.value, TokenExpired)


async def test_lenient_a_principal_without_jti_is_refused_when_there_is_one_to_compare():
    with pytest.raises(Unauthenticated) as e:
        await _resolver(_Auth("jti-1")).resolve(_User())
    assert not isinstance(e.value, TokenExpired)
    # ...and passes when the feed names none (rollout).
    assert await _resolver(_Auth()).resolve(_User())


# staleness: the check never leans on a copy older than jti_staleness


async def test_a_fresh_read_has_age_zero_and_the_last_good_copy_age_infinity():
    auth = _Auth("jti-1")
    resolver = _resolver(auth)
    assert (await resolver._context("sess-1", "user-1", consequential=False))[1] == 0.0
    auth.down = True
    context, age = await resolver._context("sess-1", "user-1", consequential=False, max_age=60)
    assert context.current_jti == "jti-1" and age == math.inf


async def test_resolve_asks_for_a_context_no_older_than_jti_staleness():
    """The seam with #42: `max_age` bounds whatever cache serves the routine path."""
    seen = []

    class _Spy(AuthServiceResolver):
        async def _context(self, *a, **kw):
            seen.append(kw.get("max_age"))
            return await super()._context(*a, **kw)

    await _Spy(_Auth("jti-1"), TrustContextCache(_Mem()), jti_staleness=17).resolve(
        _User(jti="jti-1")
    )
    assert seen == [17]


async def test_strict_the_last_good_copy_cannot_carry_the_check_so_an_outage_is_503():
    auth = _Auth("jti-1")
    resolver = _resolver(auth, strict_current_jti=True)
    assert await resolver.resolve(_User(jti="jti-1"))              # control: auth up
    auth.down = True
    with pytest.raises(AuthzUnavailable) as e:
        await resolver.resolve(_User(jti="jti-1"))
    assert not isinstance(e.value, Unauthenticated)


async def test_lenient_the_last_good_copy_still_serves_a_routine_operation():
    """Its `current_jti` is up to 900 s old: a mismatch against it proves nothing, so the check
    is skipped -- not answered PLAT0108 against a token that may simply be newer."""
    auth = _Auth("jti-1")
    resolver = _resolver(auth)
    await resolver.resolve(_User(jti="jti-1"))
    auth.down = True
    p = await resolver.resolve(_User(jti="jti-2-newer"))
    assert p.session_ref == "sess-1"


@pytest.mark.parametrize("strict", [False, True], ids=["lenient", "strict"])
async def test_check_current_jti_staleness_is_tunable(strict):
    ctx = _ctx("jti-1")
    # 30 s old, a 60 s window: the check runs and refuses the mismatch.
    with pytest.raises(TokenSuperseded):
        await check_current_jti("jti-0", ctx, age=30, jti_staleness=60, strict=strict)
    # 30 s old, a 20 s window: the check cannot rely on it.
    if strict:
        with pytest.raises(AuthzUnavailable):
            await check_current_jti("jti-0", ctx, age=30, jti_staleness=20, strict=True)
    else:
        await check_current_jti("jti-0", ctx, age=30, jti_staleness=20, strict=False)


def test_a_negative_staleness_is_refused():
    with pytest.raises(ValueError):
        _resolver(_Auth(), jti_staleness=-1)

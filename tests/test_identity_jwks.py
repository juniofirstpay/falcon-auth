"""Tests for the remote-JWKS authenticator.

Self-contained: an RSA keypair is generated in-process and served through a stub
fetcher, so nothing here touches a network or a fixture file. The stub counts its
calls, which is how the rotation and single-flight behaviour is asserted.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from falcon_auth.identity.jwks import (
    DEFAULT_DECODE_OPTIONS,
    InvalidToken,
    JWKSStore,
    JWKSVerifier,
)

ISSUER = "https://auth.test"
AUDIENCE = "https://api.test"


def _keypair(kid: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk.update(kid=kid, alg="RS256", use="sig")
    return key, jwk


def _token(key, kid: str, **overrides):
    now = int(time.time())
    claims = {
        "sub": "user-1",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


class _Fetcher:
    """Stub JWKS endpoint. `calls` is what the rotation assertions read."""

    def __init__(self, *jwks):
        self._documents = [{"keys": list(j)} for j in jwks]
        self.calls = 0

    async def __call__(self):
        self.calls += 1
        index = min(self.calls - 1, len(self._documents) - 1)
        return self._documents[index]


#: The session claim a consumer's authorization layer looks sessions up by. The package
#: deliberately has no default for this, so the tests supply one the way a service would.
SESSION_CLAIM = "sid"


def _verifier(store, **kwargs):
    kwargs.setdefault("issuer", ISSUER)
    kwargs.setdefault("audience", AUDIENCE)
    kwargs.setdefault("forwarded_claims", frozenset({SESSION_CLAIM}))
    return JWKSVerifier(store, **kwargs)


# ── happy path ────────────────────────────────────────────────────────────────


def test_valid_token_verifies():
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    claims = asyncio.run(_verifier(store).verify(_token(key, "k1")))
    assert claims["sub"] == "user-1"


# ── the claim allowlist (the hardening that existed in only one repo) ──────────


def test_authorization_claims_are_not_forwarded():
    """A token proposing its own `type`/`entitlements` must not put them on the user."""
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    verifier = _verifier(store)

    token = _token(key, "k1", type="service-account", entitlements=["ORDER_READ_ANY"])
    claims = asyncio.run(verifier.verify(token))

    # The claims are in the token...
    assert claims["entitlements"] == ["ORDER_READ_ANY"]
    # ...and none of them reach the principal.
    assert verifier.principal_claims(claims) == {}


def test_session_claim_is_forwarded():
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    verifier = _verifier(store)
    claims = asyncio.run(verifier.verify(_token(key, "k1", sid="sess-9")))
    assert verifier.principal_claims(claims) == {"sid": "sess-9"}


def test_sub_is_never_forwarded():
    """`sub` is passed explicitly as the user id, so forwarding it too would
    collide with the `id=` keyword and 401 a legitimate token."""
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    verifier = _verifier(store)
    claims = asyncio.run(verifier.verify(_token(key, "k1")))
    assert "sub" not in verifier.principal_claims(claims)


def test_forwarded_claims_is_required():
    """No default, deliberately.

    The correct value is whatever the consumer's authorization layer looks sessions up
    by. Defaulting it would put an authorization fact inside this package and leave one
    constant defined on both sides of the seam. Omitting it must fail loudly at
    construction, not resolve everyone to "holds nothing" in production.
    """
    _, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    with pytest.raises(TypeError):
        JWKSVerifier(store, issuer=ISSUER, audience=AUDIENCE)


def test_forwarded_claims_override_is_honoured():
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    verifier = _verifier(store, forwarded_claims=frozenset({"tenant"}))
    claims = asyncio.run(verifier.verify(_token(key, "k1", tenant="acme", sid="s1")))
    assert verifier.principal_claims(claims) == {"tenant": "acme"}


# ── required claims (the hardening that existed in the other repo) ─────────────


def test_token_without_sub_is_rejected():
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    with pytest.raises(InvalidToken):
        asyncio.run(_verifier(store).verify(_token(key, "k1", sub=None)))


def test_not_yet_valid_token_is_rejected():
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    future = int(time.time()) + 3600
    with pytest.raises(InvalidToken):
        asyncio.run(_verifier(store).verify(_token(key, "k1", nbf=future)))


def test_default_options_require_the_three_registered_claims():
    assert set(DEFAULT_DECODE_OPTIONS["require"]) == {"iat", "exp", "sub"}
    assert DEFAULT_DECODE_OPTIONS["verify_nbf"] is True


# ── claim checks ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://evil.test"},
        {"aud": "https://other.test"},
        {"exp": int(time.time()) - 60, "iat": int(time.time()) - 120},
    ],
    ids=["wrong-issuer", "wrong-audience", "expired"],
)
def test_bad_claims_are_rejected(overrides):
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    with pytest.raises(InvalidToken):
        asyncio.run(_verifier(store).verify(_token(key, "k1", **overrides)))


# ── key selection and rotation ────────────────────────────────────────────────


def test_missing_kid_is_rejected():
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    token = jwt.encode({"sub": "u"}, key, algorithm="RS256")  # no kid header
    with pytest.raises(InvalidToken) as e:
        asyncio.run(_verifier(store).verify(token))
    assert e.value.reason == "missing_kid"


def test_unknown_kid_refetches_once_then_rejects():
    _, jwk = _keypair("k1")
    fetcher = _Fetcher([jwk])
    store = JWKSStore(fetcher)
    other_key, _ = _keypair("k-unknown")
    with pytest.raises(InvalidToken) as e:
        asyncio.run(_verifier(store).verify(_token(other_key, "k-unknown")))
    assert e.value.reason == "unknown_kid"
    assert fetcher.calls == 1


def test_rotated_key_is_picked_up_on_kid_miss():
    """The issuer rotates; a token signed by the new key must verify without a restart."""
    _, old_jwk = _keypair("k1")
    new_key, new_jwk = _keypair("k2")
    fetcher = _Fetcher([old_jwk], [old_jwk, new_jwk])
    store = JWKSStore(fetcher)
    verifier = _verifier(store)

    async def scenario():
        await store.warm()  # call 1 -> only k1
        return await verifier.verify(_token(new_key, "k2"))  # miss -> call 2 -> k2

    claims = asyncio.run(scenario())
    assert claims["sub"] == "user-1"
    assert fetcher.calls == 2


def test_cached_key_does_not_refetch():
    key, jwk = _keypair("k1")
    fetcher = _Fetcher([jwk])
    store = JWKSStore(fetcher, ttl=300.0)
    verifier = _verifier(store)

    async def scenario():
        await store.warm()
        for _ in range(3):
            await verifier.verify(_token(key, "k1"))

    asyncio.run(scenario())
    assert fetcher.calls == 1


def test_concurrent_misses_collapse_into_one_fetch():
    key, jwk = _keypair("k1")
    fetcher = _Fetcher([jwk])
    store = JWKSStore(fetcher)
    verifier = _verifier(store)

    async def scenario():
        token = _token(key, "k1")
        await asyncio.gather(*(verifier.verify(token) for _ in range(5)))

    asyncio.run(scenario())
    assert fetcher.calls == 1


def test_stale_cache_refreshes():
    key, jwk = _keypair("k1")
    fetcher = _Fetcher([jwk])
    store = JWKSStore(fetcher, ttl=-1.0)  # always stale
    verifier = _verifier(store)

    async def scenario():
        await verifier.verify(_token(key, "k1"))
        await verifier.verify(_token(key, "k1"))

    asyncio.run(scenario())
    assert fetcher.calls == 2


def test_fetch_failure_serves_the_cached_key():
    """A refresh failure must not fail a request the cache can already answer."""
    key, jwk = _keypair("k1")

    class Flaky(_Fetcher):
        async def __call__(self):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("jwks endpoint down")
            return {"keys": [jwk]}

    fetcher = Flaky([jwk])
    store = JWKSStore(fetcher, ttl=-1.0)  # forces a refresh attempt every call
    verifier = _verifier(store)

    async def scenario():
        await verifier.verify(_token(key, "k1"))
        return await verifier.verify(_token(key, "k1"))

    assert asyncio.run(scenario())["sub"] == "user-1"
    assert fetcher.calls == 2


def test_pinned_keys_never_fetch():
    key, jwk = _keypair("k1")
    fetcher = _Fetcher([jwk])
    store = JWKSStore(fetcher)
    store.pin_keys([jwk])

    async def scenario():
        await store.warm()
        return await _verifier(store).verify(_token(key, "k1"))

    assert asyncio.run(scenario())["sub"] == "user-1"
    assert fetcher.calls == 0


# ── algorithm pinning ─────────────────────────────────────────────────────────


def test_algorithm_is_pinned_server_side():
    """An HS256 token must not verify, whatever the token header claims.

    The classic confusion attack: sign with HMAC using the RSA *public* key as
    the shared secret. It works against a verifier that reads `alg` from the
    token; it must not work here, where the algorithm list is fixed at
    construction.

    The token is assembled by hand because PyJWT's own `encode` refuses an
    asymmetric key for HS256 — which is the attack being simulated, so the
    guardrail has to be stepped around to test that *our* side also refuses.
    """
    key, jwk = _keypair("k1")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = int(time.time())
    header = {"alg": "HS256", "kid": "k1", "typ": "JWT"}
    payload = {
        "sub": "attacker",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
    }

    def b64(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    signing_input = b".".join(
        (b64(json.dumps(header).encode()), b64(json.dumps(payload).encode()))
    )
    signature = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
    forged = (signing_input + b"." + b64(signature)).decode()

    store = JWKSStore(_Fetcher([jwk]))
    with pytest.raises(InvalidToken):
        asyncio.run(_verifier(store).verify(forged))


def test_malformed_token_is_rejected():
    _, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    with pytest.raises(InvalidToken) as e:
        asyncio.run(_verifier(store).verify("not-a-jwt"))
    assert e.value.reason == "malformed_header"


# ── the Falcon adapter ────────────────────────────────────────────────────────


class _Req:
    """Minimal stand-in for a Falcon request."""

    def __init__(self, headers):
        self._headers = {k.lower(): v for k, v in headers.items()}
        self.context = type("Ctx", (), {})()

    def get_header(self, name):
        return self._headers.get(name.lower())


class _User:
    def __init__(self, id=None, type=None, **extra):
        self.id = id
        self.type = type
        self.extra = extra


def _authenticator(store, **kwargs):
    from falcon_auth.adapters.authenticators import RemoteJWKSAuthenticator

    return RemoteJWKSAuthenticator("Authorization", _verifier(store), **kwargs)


def test_adapter_sets_the_user():
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    auth = _authenticator(store, scheme="DPoP")
    req = _Req({"Authorization": f"DPoP {_token(key, 'k1', sid='s1')}"})

    assert asyncio.run(auth(_User, req, None)) is True
    assert req.context.user.id == "user-1"
    assert req.context.user.type == "user"
    assert req.context.user.extra == {"sid": "s1"}


def test_adapter_does_not_forward_authorization_claims():
    key, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    auth = _authenticator(store, scheme="DPoP")
    token = _token(key, "k1", type="service-account", entitlements=["ALL"])
    req = _Req({"Authorization": f"DPoP {token}"})

    assert asyncio.run(auth(_User, req, None)) is True
    assert req.context.user.type == "user"  # not the token's
    assert "entitlements" not in req.context.user.extra


@pytest.mark.parametrize(
    "header",
    [None, "", "Bearer x.y.z", "DPoP", "x.y.z"],
    ids=["absent", "empty", "wrong-scheme", "scheme-only", "no-scheme"],
)
def test_adapter_rejects_bad_headers(header):
    _, jwk = _keypair("k1")
    store = JWKSStore(_Fetcher([jwk]))
    auth = _authenticator(store, scheme="DPoP")
    req = _Req({} if header is None else {"Authorization": header})
    assert asyncio.run(auth(_User, req, None)) is False


def test_adapter_denies_rather_than_raising_on_store_failure():
    """A dead JWKS endpoint is a 401, never a 500."""

    class Dead:
        calls = 0

        async def __call__(self):
            raise RuntimeError("endpoint down")

    key, _ = _keypair("k1")
    store = JWKSStore(Dead())
    auth = _authenticator(store, scheme="DPoP")
    req = _Req({"Authorization": f"DPoP {_token(key, 'k1')}"})
    assert asyncio.run(auth(_User, req, None)) is False


def test_issuer_and_audience_are_required_with_no_default():
    """Issue #1 A12. Both were optional, and `verify` skips the check when either is falsy -- so
    a consumer that forgot one accepted tokens minted by any issuer, or for any other service,
    on a valid signature from a key it trusts.

    DEFAULT_DECODE_OPTIONS turns verify_iss and verify_aud ON, which made the omission look safe
    while the skip-if-falsy guard quietly disabled them. Now it is a TypeError at construction.
    """
    import pytest

    from falcon_auth.identity.jwks import JWKSStore, JWKSVerifier

    store = JWKSStore(lambda: None)  # type: ignore[arg-type,return-value]

    with pytest.raises(TypeError):
        JWKSVerifier(store, audience="orders", forwarded_claims=frozenset())  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        JWKSVerifier(store, issuer="auth", forwarded_claims=frozenset())  # type: ignore[call-arg]

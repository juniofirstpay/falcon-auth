"""falcon-auth#6, steps 1 and 2: configured credentials, pinned per route.

Step 1 -- an authenticator is a configured credential: a Selector (where it is read), a check
(signature, lookup, certificate), a Binding (proof of possession), and whether it is single-use.

Step 2 -- a route accepts the authenticators it pins, or every one on its plane. One per plane
and one per route are RECOMMENDATIONS, held by verify(profile="strict") and reported by
verify(profile="permissive"); the rules that keep the middleware's answers correct are not.

Middleware tests drive real Falcon requests, as tests/test_adapters_middleware.py does.
"""
from __future__ import annotations

import asyncio
import warnings

import falcon
import falcon.asgi
import falcon.testing
import pytest
from structlog.testing import capture_logs

from falcon_auth import planes
from falcon_auth.adapters import (
    AUTH_CREDENTIAL_ATTR,
    AUTH_METHOD_ATTR,
    AUTH_PRINCIPAL_ATTR,
    PROVEN_AT_PERIMETER,
    ConventionDeviation,
    CustomAuthenticator,
    JWTAuthenticator,
    MTLSAuthenticator,
    PlaneAuthenticationMiddleware,
    PlaneConflict,
    PlaneRegistry,
    ReferenceAuthenticator,
    RemoteJWKSAuthenticator,
    Selector,
    UnregisteredRoute,
    jwt_authenticator,
    mount,
)
from falcon_auth.errors import AuthzUnavailable, Unauthenticated
from falcon_auth.identity.jwks import InvalidToken


# ─── helpers ─────────────────────────────────────────────────────────────────


class _Req:
    def __init__(self, headers: dict[str, str] | None = None):
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.scope: dict = {"type": "http"}

    def get_header(self, name):
        return self._headers.get(name.lower())


class _Verifier:
    """A JWKSVerifier stand-in: `good` verifies, `forged` is invalid, `boom` is an outage."""

    async def verify(self, token):
        if token == "good":
            return {"sub": "u-1", "sid": "s-1"}
        if token == "boom":
            raise RuntimeError("jwks endpoint down")
        raise InvalidToken("bad_signature")

    def principal_claims(self, claims):
        return {"sid": claims["sid"]}


class _User:
    def __init__(self, id, type, **claims):
        self.id, self.type, self.claims = id, type, claims


class _RecordingBinding:
    def __init__(self, fail: BaseException | None = None):
        self.calls: list = []
        self.fail = fail

    async def bind(self, req, principal, token):
        self.calls.append((principal, token))
        if self.fail is not None:
            raise self.fail


BEARER = Selector("Authorization", "Bearer")
DPOP = Selector("Authorization", "DPoP")


def run(coro):
    return asyncio.run(coro)


# ─── step 1: Selector ────────────────────────────────────────────────────────


def test_a_selector_reads_its_scheme_case_insensitively():
    assert BEARER.extract(_Req({"Authorization": "bearer t-1"})) == "t-1"


def test_another_scheme_is_absent_not_invalid():
    assert BEARER.extract(_Req({"Authorization": "DPoP t-1"})) is None
    assert BEARER.extract(_Req({})) is None


def test_a_schemeless_selector_takes_the_whole_value():
    assert Selector("X-Software-Statement").extract(_Req({"X-Software-Statement": "eyJ"})) == "eyJ"


@pytest.mark.parametrize(
    "a, b, overlap",
    [
        (BEARER, DPOP, False),                                   # same header, other scheme
        (BEARER, Selector("authorization", "BEARER"), True),     # case-insensitive
        (BEARER, Selector("Authorization"), True),               # schemeless takes every value
        (BEARER, Selector("X-Other", "Bearer"), False),
        (Selector.TLS, BEARER, False),
    ],
)
def test_selector_overlap(a, b, overlap):
    assert a.overlaps(b) is overlap and b.overlaps(a) is overlap


# ─── step 1: JWTAuthenticator ────────────────────────────────────────────────


def _jwt(**kw):
    kw.setdefault("binding", PROVEN_AT_PERIMETER)
    return JWTAuthenticator(_Verifier(), DPOP, user_cls=_User, **kw)


def test_a_valid_token_builds_the_user():
    user = run(_jwt()(_Req({"Authorization": "DPoP good"})))
    assert (user.id, user.type, user.claims) == ("u-1", "user", {"sid": "s-1"})


def test_a_forged_token_is_401_and_an_outage_is_503():
    with pytest.raises(Unauthenticated):
        run(_jwt()(_Req({"Authorization": "DPoP forged"})))
    with pytest.raises(AuthzUnavailable):
        run(_jwt()(_Req({"Authorization": "DPoP boom"})))


def test_no_token_of_this_kind_is_absent():
    assert run(_jwt()(_Req({"Authorization": "Bearer good"}))) is None


def test_a_host_principal_loader_replaces_user_cls():
    async def load(claims):
        return {"session": claims["sid"]}

    auth = JWTAuthenticator(_Verifier(), DPOP, principal=load, binding=PROVEN_AT_PERIMETER)
    assert run(auth(_Req({"Authorization": "DPoP good"}))) == {"session": "s-1"}


def test_the_binding_runs_inside_after_the_token():
    binding = _RecordingBinding()
    user = run(_jwt(binding=binding)(_Req({"Authorization": "DPoP good"})))
    assert binding.calls == [(user, "good")]


def test_a_failed_binding_is_401_and_a_broken_one_is_503():
    with pytest.raises(Unauthenticated):
        run(_jwt(binding=_RecordingBinding(Unauthenticated("no proof")))(
            _Req({"Authorization": "DPoP good"})))
    with pytest.raises(AuthzUnavailable):
        run(_jwt(binding=_RecordingBinding(RuntimeError("nonce store down")))(
            _Req({"Authorization": "DPoP good"})))


def test_a_single_use_jwt_is_a_one_shot_token():
    auth = JWTAuthenticator(_Verifier(), Selector("X-Software-Statement"), single_use=True)
    assert auth.method == planes.ONE_SHOT_TOKEN and auth.single_use


# ─── step 1: the binding must be declared for a DPoP scheme ──────────────────


def test_a_dpop_scheme_without_a_binding_warns():
    with pytest.warns(DeprecationWarning, match="PROVEN_AT_PERIMETER"):
        JWTAuthenticator(_Verifier(), DPOP, user_cls=_User)


def test_declaring_the_perimeter_silences_it():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        JWTAuthenticator(_Verifier(), DPOP, user_cls=_User, binding=PROVEN_AT_PERIMETER)
        JWTAuthenticator(_Verifier(), BEARER, user_cls=_User)  # not a DPoP scheme


def test_the_old_names_warn_the_same_way():
    with pytest.warns(DeprecationWarning):
        jwt_authenticator(_Verifier(), _User, scheme="DPoP")
    with pytest.warns(DeprecationWarning):
        RemoteJWKSAuthenticator("Authorization", _Verifier(), scheme="DPoP")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        jwt_authenticator(_Verifier(), _User, scheme="DPoP", binding=PROVEN_AT_PERIMETER)
        RemoteJWKSAuthenticator(
            "Authorization", _Verifier(), scheme="DPoP", binding=PROVEN_AT_PERIMETER)


def test_the_boolean_authenticator_cannot_run_a_real_binding():
    with pytest.raises(TypeError):
        RemoteJWKSAuthenticator("Authorization", _Verifier(), scheme="DPoP",
                                binding=_RecordingBinding())


# ─── step 1: ReferenceAuthenticator ──────────────────────────────────────────


def _lookup(result=None, raises=None, delay=0.0):
    calls = []

    async def lookup(token):
        calls.append(token)
        if delay:
            await asyncio.sleep(delay)
        if raises is not None:
            raise raises
        return result

    lookup.calls = calls
    return lookup


def test_a_known_token_is_the_principal():
    auth = ReferenceAuthenticator(_lookup({"client": "c-1"}), BEARER)
    assert run(auth(_Req({"Authorization": "Bearer t"}))) == {"client": "c-1"}
    assert auth.method == planes.REFERENCE_TOKEN


def test_a_presented_token_the_store_does_not_know_is_401_not_absent():
    with pytest.raises(Unauthenticated):
        run(ReferenceAuthenticator(_lookup(None), BEARER)(_Req({"Authorization": "Bearer t"})))


def test_the_lookup_never_runs_without_a_token_of_its_kind():
    lookup = _lookup({"x": 1})
    assert run(ReferenceAuthenticator(lookup, BEARER)(_Req({"Authorization": "Link t"}))) is None
    assert lookup.calls == []


@pytest.mark.parametrize(
    "raises, expected",
    [
        (Unauthenticated("revoked"), Unauthenticated),
        (AuthzUnavailable("db down"), AuthzUnavailable),
        (ConnectionError("refused"), AuthzUnavailable),
    ],
)
def test_the_lookup_has_three_outcomes(raises, expected):
    with pytest.raises(expected):
        run(ReferenceAuthenticator(_lookup(raises=raises), BEARER)(
            _Req({"Authorization": "Bearer t"})))


def test_a_slow_lookup_is_503():
    auth = ReferenceAuthenticator(_lookup({"x": 1}, delay=0.2), BEARER, timeout=0.01)
    with pytest.raises(AuthzUnavailable, match="timed out"):
        run(auth(_Req({"Authorization": "Bearer t"})))


def test_a_single_use_reference_is_a_one_shot_token_and_is_not_spent_here():
    lookup = _lookup({"rotation": "r-1"})
    auth = ReferenceAuthenticator(lookup, BEARER, single_use=True)
    req = _Req({"Authorization": "Bearer t"})
    run(auth(req)), run(auth(req))
    assert auth.method == planes.ONE_SHOT_TOKEN
    assert lookup.calls == ["t", "t"]  # checked twice; spending is the handler's


def test_an_unknown_plane_is_refused():
    with pytest.raises(ValueError):
        ReferenceAuthenticator(_lookup(), BEARER, plane="ADMIN")  # type: ignore[arg-type]


def test_mtls_defaults_to_the_service_plane():
    assert MTLSAuthenticator(object()).planes == {planes.SERVICE}  # type: ignore[arg-type]


# ─── step 2: the middleware ──────────────────────────────────────────────────


class NotFound(Exception):
    pass


async def _render_404(req, resp, ex, params):
    resp.status, resp.media = falcon.HTTP_404, {"code": "NOT_FOUND"}


async def _render_401(req, resp, ex, params):
    resp.status, resp.media = falcon.HTTP_401, {"code": "UNAUTHENTICATED"}


class Echo:
    async def on_get(self, req, resp):
        resp.media = {
            "credential": getattr(req.context, AUTH_CREDENTIAL_ATTR, None),
            "method": getattr(req.context, AUTH_METHOD_ATTR, None),
            "principal": getattr(req.context, AUTH_PRINCIPAL_ATTR, None),
        }


def fake(name, selector, *, plane, method, header=None):
    """A configured credential that reads `selector`: 'good' passes, 'bad' is invalid."""

    async def attempt(req):
        token = selector.extract(req) if header is None else req.get_header(header)
        if token is None:
            return None
        if token == "bad":
            raise Unauthenticated(f"invalid {name}")
        return f"{name}-principal"

    return CustomAuthenticator(attempt, plane=plane, method=method, selector=selector)


CERT = Selector("X-Client-Cert")

#: The identity provider's USER plane, in miniature.
IDP = {
    "access_token": fake("access_token", DPOP, plane=planes.USER, method=planes.JWT),
    "client_session": fake("client_session", BEARER, plane=planes.USER,
                           method=planes.REFERENCE_TOKEN),
    "mtls": fake("mtls", CERT, plane=planes.SERVICE, method=planes.MTLS),
}


def build(routes, *, authenticators=IDP, flagged=None, exempt_paths=None, bare=()):
    """routes: [(path, plane, credential)]; bare: paths added with app.add_route only."""
    registry = PlaneRegistry()
    kwargs = {} if exempt_paths is None else {"exempt_paths": exempt_paths}
    mw = PlaneAuthenticationMiddleware(
        registry,
        authenticators=authenticators,
        not_found_error=NotFound,
        on_plane_mismatch=(lambda *a: flagged.append(a)) if flagged is not None else None,
        **kwargs,
    )
    app = falcon.asgi.App(middleware=[mw])
    app.add_error_handler(NotFound, _render_404)
    app.add_error_handler(Unauthenticated, _render_401)
    for path, plane, credential in routes:
        mount(registry, app, path, Echo(), plane=plane, credential=credential,
              reason="test" if plane == planes.PUBLIC else None)
    for path in bare:
        app.add_route(path, Echo())
    return falcon.testing.TestClient(app), mw


def test_a_pinned_route_accepts_its_credential_and_stamps_its_name():
    client, mw = build([("/v1/token:create", planes.USER, "client_session")])
    mw.verify(profile="permissive")
    r = client.simulate_get("/v1/token:create", headers={"Authorization": "Bearer good"})
    assert r.status_code == 200
    assert r.json == {"credential": "client_session", "method": "REFERENCE_TOKEN",
                      "principal": "client_session-principal"}


def test_another_credential_on_the_same_plane_is_401_not_404_and_not_flagged():
    """An access token sent to a client-session route: the endpoint's credential is absent, and
    nothing about the plane is revealed -- the holder is on the right plane, at the wrong door."""
    flagged = []
    client, _ = build([("/v1/token:create", planes.USER, "client_session")], flagged=flagged)
    r = client.simulate_get("/v1/token:create", headers={"Authorization": "DPoP good"})
    assert r.status_code == 401 and flagged == []


def test_a_credential_from_another_plane_is_still_the_404_and_flagged():
    flagged = []
    client, _ = build([("/v1/token:create", planes.USER, "client_session")], flagged=flagged)
    r = client.simulate_get("/v1/token:create", headers={"X-Client-Cert": "good"})
    assert r.status_code == 404 and r.json == {"code": "NOT_FOUND"}
    assert flagged == [("/v1/token:create", planes.USER, planes.MTLS)]


def test_a_route_may_accept_two_credentials_with_disjoint_carriers():
    """auth's forgot-MPIN today: an access token OR a pre-login client session."""
    client, mw = build([("/v1/mpin/forgot:begin", planes.USER, ["access_token", "client_session"])])
    mw.verify(profile="permissive")
    by_token = client.simulate_get("/v1/mpin/forgot:begin", headers={"Authorization": "DPoP good"})
    by_session = client.simulate_get("/v1/mpin/forgot:begin",
                                     headers={"Authorization": "Bearer good"})
    assert (by_token.json["credential"], by_session.json["credential"]) == (
        "access_token", "client_session")


def test_an_invalid_accepted_credential_does_not_fall_through_to_the_next():
    client, _ = build([("/v1/x", planes.USER, ["access_token", "client_session"])])
    r = client.simulate_get("/v1/x", headers={"Authorization": "DPoP bad"})
    assert r.status_code == 401


def test_an_unpinned_route_accepts_every_authenticator_on_its_plane():
    client, _ = build([("/v1/svc/x", planes.SERVICE, None)])
    assert client.simulate_get("/v1/svc/x", headers={"X-Client-Cert": "good"}).json[
        "credential"] == "mtls"


def test_the_original_method_keyed_shape_still_works_unchanged():
    """Every consumer written before #6 -- persona's PR #109 among them."""
    legacy = {
        planes.JWT: fake("jwt", DPOP, plane=planes.USER, method=planes.JWT),
        planes.MTLS: fake("mtls", CERT, plane=planes.SERVICE, method=planes.MTLS),
    }
    client, mw = build([("/v1/orders", planes.USER, None)], authenticators=legacy)
    mw.verify()
    r = client.simulate_get("/v1/orders", headers={"Authorization": "DPoP good"})
    assert r.json["credential"] == "JWT" and r.json["method"] == "JWT"
    assert client.simulate_get("/v1/orders", headers={"X-Client-Cert": "good"}).status_code == 404


# ─── step 2: what is always refused ──────────────────────────────────────────


def test_pinning_an_unknown_credential_is_refused_at_boot_and_at_request():
    client, mw = build([("/v1/x", planes.USER, "nonexistent")])
    with pytest.raises(UnregisteredRoute, match="nonexistent"):
        mw.verify()
    assert client.simulate_get("/v1/x", headers={"Authorization": "DPoP good"}).status_code == 500


def test_pinning_a_credential_from_another_plane_is_refused():
    _, mw = build([("/v1/x", planes.USER, "mtls")])
    with pytest.raises(UnregisteredRoute, match="SERVICE"):
        mw.verify()


def test_a_public_route_naming_a_credential_is_refused_at_mount():
    with pytest.raises(PlaneConflict, match="PUBLIC"):
        build([("/v1/open", planes.PUBLIC, "access_token")])


def test_two_accepted_credentials_on_one_carrier_are_refused():
    both_bearer = dict(IDP, key_rotation=fake("key_rotation", BEARER, plane=planes.USER,
                                              method=planes.ONE_SHOT_TOKEN))
    _, mw = build([("/v1/x", planes.USER, ["client_session", "key_rotation"])],
                  authenticators=both_bearer)
    with pytest.raises(PlaneConflict, match="same carrier"):
        mw.verify(profile="permissive")


def test_sharing_a_carrier_within_one_plane_is_fine_when_routes_pin():
    """client_session and key_rotation both read `Authorization: Bearer` -- each route pins one."""
    both_bearer = dict(IDP, key_rotation=fake("key_rotation", BEARER, plane=planes.USER,
                                              method=planes.ONE_SHOT_TOKEN))
    client, mw = build([("/v1/a", planes.USER, "client_session"),
                        ("/v1/b", planes.USER, "key_rotation")], authenticators=both_bearer)
    mw.verify(profile="permissive")
    r = client.simulate_get("/v1/b", headers={"Authorization": "Bearer good"})
    assert r.json["credential"] == "key_rotation"


def test_sharing_a_carrier_across_planes_is_refused_at_construction():
    clash = {
        "user_bearer": fake("user_bearer", BEARER, plane=planes.USER, method=planes.JWT),
        "svc_bearer": fake("svc_bearer", BEARER, plane=planes.SERVICE, method=planes.MTLS),
    }
    with pytest.raises(PlaneConflict, match="different planes"):
        build([], authenticators=clash)


def test_mixing_the_two_shapes_is_refused():
    with pytest.raises(TypeError, match="one shape"):
        build([], authenticators={planes.JWT: IDP["access_token"], "mtls": IDP["mtls"]})


def test_a_named_authenticator_must_declare_its_plane():
    async def bare(req):
        return None

    with pytest.raises(TypeError, match="declares no plane"):
        build([], authenticators={"bare": bare})


# ─── step 2: what the profile decides ────────────────────────────────────────


def test_strict_refuses_a_method_c038_does_not_put_on_the_plane():
    _, mw = build([("/v1/token:create", planes.USER, "client_session")])
    with pytest.raises(ConventionDeviation, match="REFERENCE_TOKEN"):
        mw.verify()


def test_permissive_starts_and_logs_each_deviation_once():
    _, mw = build([("/v1/token:create", planes.USER, "client_session")])
    with capture_logs() as logs:
        mw.verify(profile="permissive")
    found = [e for e in logs if e["event"] == "plane_convention_deviation"]
    assert len(found) == 1 and "client_session (REFERENCE_TOKEN) on USER" in found[0]["findings"]


def test_strict_refuses_an_authenticator_on_two_planes():
    two = {"either": fake("either", DPOP, plane=[planes.USER, planes.CALLBACK],
                          method=planes.JWT)}
    _, mw = build([("/v1/x", planes.USER, None)], authenticators=two)
    with pytest.raises(ConventionDeviation, match="more than one plane"):
        mw.verify()


def test_strict_refuses_a_route_accepting_two_of_the_same_method():
    twice = {
        "a": fake("a", DPOP, plane=planes.USER, method=planes.JWT),
        "b": fake("b", Selector("X-Other", "Token"), plane=planes.USER, method=planes.JWT),
    }
    _, mw = build([("/v1/x", planes.USER, None)], authenticators=twice)
    with pytest.raises(ConventionDeviation, match="same method"):
        mw.verify()


def test_callbacks_two_methods_are_c038s_own_allowance_and_pass_strict():
    callback = {
        planes.HMAC: fake("hmac", Selector("X-Signature"), plane=planes.CALLBACK,
                          method=planes.HMAC),
        planes.ONE_SHOT_TOKEN: fake("oneshot", Selector("X-One-Shot"), plane=planes.CALLBACK,
                                    method=planes.ONE_SHOT_TOKEN),
    }
    _, mw = build([("/v1/callbacks/x", planes.CALLBACK, None)], authenticators=callback)
    mw.verify()


def test_an_unknown_profile_is_refused():
    _, mw = build([])
    with pytest.raises(ValueError):
        mw.verify(profile="lenient")  # type: ignore[arg-type]


# ─── the probe exemption ─────────────────────────────────────────────────────


def test_an_unregistered_default_probe_passes_through():
    client, _ = build([], bare=["/health"])
    assert client.simulate_get("/health").status_code == 200


def test_a_host_named_probe_passes_through():
    client, _ = build([], bare=["/_info"], exempt_paths={"/_info"})
    assert client.simulate_get("/_info").status_code == 200


def test_any_other_unregistered_route_is_still_refused():
    client, _ = build([], bare=["/v1/forgotten"])
    assert client.simulate_get("/v1/forgotten").status_code == 500


def test_a_registered_route_is_never_exempt():
    """Naming a USER route in exempt_paths cannot make it public."""
    client, _ = build([("/health", planes.USER, "access_token")], exempt_paths={"/health"})
    assert client.simulate_get("/health").status_code == 401

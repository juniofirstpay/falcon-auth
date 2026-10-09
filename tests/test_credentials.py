"""falcon-auth#6, steps 1 and 2: configured credentials, pinned per route.

Step 1 -- an authenticator is a configured credential: a Selector (where it is read), a check
(signature, lookup, certificate), a Binding (proof of possession), and whether it is single-use.

Step 2, as C-060 (`v30`) rules it -- a route declares EXACTLY ONE credential; the wrong-plane
search counts only I/O-free credentials and never the forwarding hop; the wrong-plane answer is
the route not-found (PLAT0006, RUL-158); CLIENT is the identity provider's and refused here.

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
    auth = ReferenceAuthenticator(_lookup({"client": "c-1"}), BEARER, plane="CLIENT")
    assert run(auth(_Req({"Authorization": "Bearer t"}))) == {"client": "c-1"}
    assert auth.method == planes.REFERENCE_TOKEN


def test_a_presented_token_the_store_does_not_know_is_401_not_absent():
    with pytest.raises(Unauthenticated):
        run(ReferenceAuthenticator(_lookup(None), BEARER, plane="CLIENT")(_Req({"Authorization": "Bearer t"})))


def test_the_lookup_never_runs_without_a_token_of_its_kind():
    lookup = _lookup({"x": 1})
    assert run(ReferenceAuthenticator(lookup, BEARER, plane="CLIENT")(_Req({"Authorization": "Link t"}))) is None
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
        run(ReferenceAuthenticator(_lookup(raises=raises), BEARER, plane="CLIENT")(
            _Req({"Authorization": "Bearer t"})))


def test_a_slow_lookup_is_503():
    auth = ReferenceAuthenticator(_lookup({"x": 1}, delay=0.2), BEARER, plane="CLIENT", timeout=0.01)
    with pytest.raises(AuthzUnavailable, match="timed out"):
        run(auth(_Req({"Authorization": "Bearer t"})))


def test_a_single_use_reference_is_a_one_shot_token_and_is_not_spent_here():
    lookup = _lookup({"rotation": "r-1"})
    auth = ReferenceAuthenticator(lookup, BEARER, plane="CALLBACK", single_use=True)
    req = _Req({"Authorization": "Bearer t"})
    run(auth(req)), run(auth(req))
    assert auth.method == planes.ONE_SHOT_TOKEN
    assert lookup.calls == ["t", "t"]  # checked twice; spending is the handler's


def test_an_unknown_plane_is_refused():
    with pytest.raises(ValueError):
        ReferenceAuthenticator(_lookup(), BEARER, plane="ADMIN")  # type: ignore[arg-type]


def test_a_credential_has_one_plane():
    with pytest.raises(ValueError, match="ONE"):
        ReferenceAuthenticator(_lookup(), BEARER, plane=["CLIENT", "CALLBACK"])  # type: ignore[arg-type]


def test_a_reference_authenticator_names_its_plane():
    """No default: C-060 puts a reusable reference token on CLIENT only -- there is no default
    that would be right for a resource service."""
    with pytest.raises(TypeError):
        ReferenceAuthenticator(_lookup(), BEARER)  # type: ignore[call-arg]


def test_mtls_defaults_to_the_service_plane():
    assert MTLSAuthenticator(object()).planes == {planes.SERVICE}  # type: ignore[arg-type]


# ─── step 2: the middleware ──────────────────────────────────────────────────


class Echo:
    async def on_get(self, req, resp):
        resp.media = {
            "credential": getattr(req.context, AUTH_CREDENTIAL_ATTR, None),
            "method": getattr(req.context, AUTH_METHOD_ATTR, None),
            "principal": _plain(getattr(req.context, AUTH_PRINCIPAL_ATTR, None)),
        }


def _plain(principal):
    return getattr(principal, "source", principal)


async def _render_route_not_found(req, resp, ex, params):
    """The host's router miss: PLAT0006 (RUL-158). The wrong-plane answer must be exactly this."""
    resp.status, resp.media = falcon.HTTP_404, {"code": "PLAT0006", "message": "route_not_found"}


async def _render_401(req, resp, ex, params):
    resp.status, resp.media = falcon.HTTP_401, {"code": "PLAT0101"}


class _Principal:
    def __init__(self, source):
        self.source = source


def fake(name, selector, *, plane, method, principal=None):
    """A configured credential that reads `selector`: 'bad' is invalid, anything else valid."""

    async def attempt(req):
        token = selector.extract(req)
        if token is None:
            return None
        if token == "bad":
            raise Unauthenticated(f"invalid {name}")
        return principal(token) if principal else f"{name}-principal"

    return CustomAuthenticator(attempt, plane=plane, method=method, selector=selector)


CERT = Selector("X-Client-Cert")

#: A resource service: USER by JWT, SERVICE by mTLS, two CALLBACK sources pinned per route.
RESOURCE = {
    "access_token": fake("access_token", DPOP, plane=planes.USER, method=planes.JWT),
    "mtls": fake("mtls", CERT, plane=planes.SERVICE, method=planes.MTLS,
                 principal=_Principal),
    "rail_hmac": fake("rail_hmac", Selector("X-Signature"), plane=planes.CALLBACK,
                      method=planes.HMAC),
    "psp_token": fake("psp_token", Selector("X-Callback-Token"), plane=planes.CALLBACK,
                      method=planes.ONE_SHOT_TOKEN),
}


def build(routes, *, authenticators=RESOURCE, flagged=None, bare=(), **kwargs):
    """routes: [(path, plane, credential)]; bare: paths added with app.add_route only."""
    registry = PlaneRegistry()
    mw = PlaneAuthenticationMiddleware(
        registry,
        authenticators=authenticators,
        on_plane_mismatch=(lambda *a: flagged.append(a)) if flagged is not None else None,
        **kwargs,
    )
    app = falcon.asgi.App(middleware=[mw])
    app.add_error_handler(falcon.HTTPRouteNotFound, _render_route_not_found)
    app.add_error_handler(Unauthenticated, _render_401)
    per_plane = {}  # C-006: one resource class serves exactly one plane
    for path, plane, credential in routes:
        cls = per_plane.setdefault(plane, type(f"Echo{plane}", (Echo,), {}))
        mount(registry, app, path, cls(), plane=plane, credential=credential,
              reason="test" if plane == planes.PUBLIC else None,
              actor_types={"CUSTOMER"} if plane == planes.USER else None)
    for path in bare:
        app.add_route(path, Echo())
    return falcon.testing.TestClient(app), mw


ROUTES = [
    ("/v1/orders", planes.USER, None),
    ("/v1/svc/orders", planes.SERVICE, None),
    ("/v1/callbacks/rail", planes.CALLBACK, "rail_hmac"),
    ("/v1/callbacks/psp", planes.CALLBACK, "psp_token"),
]


def test_each_route_opens_with_its_one_credential_and_stamps_its_name():
    client, mw = build(ROUTES)
    mw.verify()
    r = client.simulate_get("/v1/callbacks/psp", headers={"X-Callback-Token": "t"})
    assert r.json == {"credential": "psp_token", "method": "ONE_SHOT_TOKEN",
                      "principal": "psp_token-principal"}
    assert client.simulate_get("/v1/orders", headers={"Authorization": "DPoP t"}).json[
        "credential"] == "access_token"


def test_the_original_method_keyed_shape_still_works():
    """persona's PR #109 shape: one authenticator per plane, no pins."""
    legacy = {planes.JWT: RESOURCE["access_token"], planes.MTLS: RESOURCE["mtls"]}
    client, mw = build(ROUTES[:2], authenticators=legacy)
    mw.verify()
    assert client.simulate_get("/v1/orders", headers={"Authorization": "DPoP t"}).json[
        "credential"] == "JWT"


# ─── step 4: the wrong-plane answer ──────────────────────────────────────────


def test_a_valid_credential_of_another_plane_is_404_plat0006_identical_to_a_router_miss():
    """RUL-158: the route not-found, byte-identical to a path that does not exist at all."""
    flagged = []
    client, _ = build(ROUTES, flagged=flagged)
    wrong_plane = client.simulate_get("/v1/orders", headers={"X-Client-Cert": "payments"})
    router_miss = client.simulate_get("/v1/no-such-route")
    assert wrong_plane.status_code == router_miss.status_code == 404
    assert wrong_plane.content == router_miss.content
    assert wrong_plane.json["code"] == "PLAT0006"
    assert flagged == [("/v1/orders", planes.USER, planes.MTLS)]


@pytest.mark.parametrize("header", ["X-Signature", "X-Callback-Token"])
def test_a_credential_needing_a_lookup_never_makes_a_404(header):
    """C-060 §6: only I/O-free credentials enter the search. A valid callback credential sent to a
    USER route is ABSENT there -- 401, not 404 -- so junk cannot turn the 404 into database load."""
    flagged = []
    client, _ = build(ROUTES, flagged=flagged)
    r = client.simulate_get("/v1/orders", headers={header: "t"})
    assert r.status_code == 401 and flagged == []


def test_a_client_key_proof_alone_on_a_user_route_is_401():
    """C-060's own conformance case: a USER request missing its token, with only a proof."""
    client, _ = build(ROUTES)
    r = client.simulate_get("/v1/orders", headers={"DPoP": "eyJ.proof"})
    assert r.status_code == 401


def test_the_forwarding_hops_certificate_is_never_a_caller_credential():
    """C-060 §6. The gateway forwards user requests over its own mTLS leaf and is also an
    allow-listed peer for routes it calls on its own behalf. A user request with no token must be
    401, not a 404 caused by the hop's certificate."""
    gateway = MTLSAuthenticator(_AllowList({"gateway.internal": "gateway"}),
                                transport_peers={"gateway"})
    client, _ = build(ROUTES[:2], authenticators={
        "access_token": RESOURCE["access_token"], "mtls": gateway})
    r = client.simulate_get("/v1/orders", extras=_cert("gateway.internal"))
    assert r.status_code == 401


def test_the_forwarding_hop_is_still_an_ordinary_caller_on_a_service_route():
    gateway = MTLSAuthenticator(_AllowList({"gateway.internal": "gateway"}),
                                transport_peers={"gateway"})
    client, _ = build(ROUTES[:2], authenticators={
        "access_token": RESOURCE["access_token"], "mtls": gateway})
    assert client.simulate_get("/v1/svc/orders", extras=_cert("gateway.internal")).json[
        "credential"] == "mtls"


def test_another_credential_of_the_same_plane_is_401_and_not_flagged():
    flagged = []
    client, _ = build(ROUTES, flagged=flagged)
    r = client.simulate_get("/v1/callbacks/rail", headers={"X-Callback-Token": "t"})
    assert r.status_code == 401 and flagged == []


def test_an_invalid_credential_is_401_and_does_not_search():
    client, _ = build(ROUTES)
    r = client.simulate_get("/v1/orders",
                            headers={"Authorization": "DPoP bad", "X-Client-Cert": "payments"})
    assert r.status_code == 401


# ─── one credential per route (C-060 §3) ─────────────────────────────────────


def test_credential_takes_one_name_never_a_list():
    with pytest.raises(PlaneConflict, match="exactly one"):
        build([("/v1/callbacks/x", planes.CALLBACK, ["rail_hmac", "psp_token"])])


def test_an_unpinned_route_on_a_plane_with_two_authenticators_is_refused():
    """It would accept 'any of' them -- refused at boot, and at request as the net under it."""
    client, mw = build([("/v1/callbacks/x", planes.CALLBACK, None)])
    with pytest.raises(UnregisteredRoute, match="exactly one"):
        mw.verify()
    assert client.simulate_get("/v1/callbacks/x", headers={"X-Signature": "t"}).status_code == 500


def test_pinning_an_unknown_credential_is_refused():
    client, mw = build([("/v1/x", planes.USER, "nonexistent")])
    with pytest.raises(UnregisteredRoute, match="nonexistent"):
        mw.verify()


def test_pinning_a_credential_from_another_plane_is_refused():
    _, mw = build([("/v1/x", planes.USER, "mtls")])
    with pytest.raises(UnregisteredRoute, match="SERVICE"):
        mw.verify()


def test_a_public_route_naming_a_credential_is_refused_at_mount():
    with pytest.raises(PlaneConflict, match="PUBLIC"):
        build([("/v1/open", planes.PUBLIC, "access_token")])


# ─── C-060's table, at construction ──────────────────────────────────────────


def test_a_client_route_is_refused():
    """C-060 §2: CLIENT is mounted by the identity provider only, which does not use this package
    (RUL-157)."""
    with pytest.raises(PlaneConflict, match="identity provider"):
        build([("/v1/client/token", planes.CLIENT, None)])


def test_a_client_authenticator_is_refused():
    session = ReferenceAuthenticator(_lookup({"x": 1}), BEARER, plane=planes.CLIENT)
    with pytest.raises(ConventionDeviation, match="identity provider"):
        build([], authenticators={"client_session": session})


def test_a_method_off_c060s_table_is_refused():
    """A reference token on USER -- what falcon-auth#6 once proposed, and C-060 ruled against."""
    on_user = CustomAuthenticator(_lookup(), plane=planes.USER, method=planes.REFERENCE_TOKEN,
                                  selector=BEARER)
    with pytest.raises(ConventionDeviation, match="C-060"):
        build([], authenticators={"session": on_user})


def test_sharing_a_carrier_across_planes_is_refused():
    clash = {
        "user": fake("user", BEARER, plane=planes.USER, method=planes.JWT),
        "svc": fake("svc", BEARER, plane=planes.SERVICE, method=planes.MTLS),
    }
    with pytest.raises(PlaneConflict, match="different planes"):
        build([], authenticators=clash)


def test_mixing_the_two_shapes_is_refused():
    with pytest.raises(TypeError, match="one shape"):
        build([], authenticators={planes.JWT: RESOURCE["access_token"], "mtls": RESOURCE["mtls"]})


def test_a_named_authenticator_must_declare_its_plane():
    async def bare(req):
        return None

    with pytest.raises(TypeError, match="declares no plane"):
        build([], authenticators={"bare": bare})


def test_there_is_no_permissive_profile():
    """C-060 calls a permissive profile a loophole; C-061 §1: a broken property refuses start."""
    _, mw = build(ROUTES)
    with pytest.raises(TypeError):
        mw.verify(profile="permissive")  # type: ignore[call-arg]


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
    client, _ = build([("/v1/status", planes.USER, "access_token")],
                      exempt_paths={"/v1/status"})
    assert client.simulate_get("/v1/status").status_code == 401


# ─── helpers for real certificates ───────────────────────────────────────────


class _AllowList:
    """A Verifier stand-in over a {cn: source} map, reading the CN the way eastwest does."""

    def __init__(self, sources):
        self._sources = sources

    def authenticate(self, scope):
        from falcon_auth.eastwest.verifier import peer_cn
        from falcon_auth import UnknownCNError

        cn = peer_cn(scope)
        if cn not in self._sources:
            raise UnknownCNError(cn=cn)
        return _Principal(self._sources[cn])


def _cert(cn):
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    der = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
           .public_key(key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now - dt.timedelta(minutes=1))
           .not_valid_after(now + dt.timedelta(hours=1))
           .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    return {"extensions": {"tls": {"peer_cert_der": der}}}

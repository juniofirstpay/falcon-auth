"""falcon-auth#27: a SERVICE route reached with no client certificate answers 401 PLAT0103.

`registry/PLAT.md` gives PLAT0103 (client_certificate_missing, "Seen as: svcplane 9000") to
exactly this. Through the plane middleware it was 401 PLAT0101 ("Please sign in again."), a
customer's copy on a service-to-service call.
"""
from __future__ import annotations

import falcon
import falcon.asgi
import falcon.testing
import pytest

from falcon_auth import ClientCertificateMissing, Unauthenticated, planes
from falcon_auth.adapters import (
    CustomAuthenticator,
    MTLSAuthenticator,
    PlaneAuthenticationMiddleware,
    PlaneRegistry,
    Selector,
    mount,
    mtls_authenticator,
    register_error_handlers,
)

REFUSED = {"code": "PLAT0103", "message": "The request could not be authorised."}


class _Verifier:
    def authenticate(self, scope):  # pragma: no cover - never reached without a certificate
        raise AssertionError("no certificate, so no CN to check")


async def _user(req):
    return {"sub": "u1"} if Selector("Authorization", "Bearer").extract(req) == "good" else None


class Svc:
    async def on_get(self, req, resp):
        resp.media = {}


class Orders:
    async def on_get(self, req, resp):
        resp.media = {}


def _client(authenticators):
    registry = PlaneRegistry()
    app = falcon.asgi.App(middleware=[
        PlaneAuthenticationMiddleware(registry, authenticators=authenticators)])
    register_error_handlers(app)
    mount(registry, app, "/v1/svc/orders", Svc(), plane=planes.SERVICE)
    mount(registry, app, "/v1/orders", Orders(), plane=planes.USER, actor_types={"CUSTOMER"})
    return falcon.testing.TestClient(app)


NAMED = {
    "peer": MTLSAuthenticator(_Verifier()),
    "access_token": CustomAuthenticator(_user, plane=planes.USER, method=planes.JWT,
                                        selector=Selector("Authorization", "Bearer")),
}
LEGACY = {planes.MTLS: mtls_authenticator(_Verifier()), planes.JWT: NAMED["access_token"]}


@pytest.mark.parametrize("authenticators", [NAMED, LEGACY], ids=["named", "method-keyed"])
def test_no_client_certificate_gets_plat0103(authenticators):
    r = _client(authenticators).simulate_get("/v1/svc/orders")
    assert (r.status_code, r.json) == (401, REFUSED)


def test_a_user_route_without_a_token_is_still_plat0101():
    """The answer follows the ROUTE's credential, not a global default."""
    r = _client(NAMED).simulate_get("/v1/orders")
    assert (r.status_code, r.json["code"]) == (401, "PLAT0101")


def test_a_valid_user_token_on_a_service_route_is_still_the_router_miss():
    """Absent at the authenticator, so the wrong-plane search still runs first (C-060 §6)."""
    r = _client(NAMED).simulate_get("/v1/svc/orders", headers={"Authorization": "Bearer good"})
    assert r.status_code == 404


def test_it_is_an_unauthenticated():
    assert issubclass(ClientCertificateMissing, Unauthenticated)
    assert MTLSAuthenticator.absent_error is ClientCertificateMissing

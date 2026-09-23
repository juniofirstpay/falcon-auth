"""Tests for the per-request plane assertion.

Driven through real Falcon requests rather than by calling `process_resource` directly. The
lifecycle is half the design here -- which hook runs, and when Falcon runs it at all -- so a
test that calls the method by hand would verify the part that was never in doubt.
"""

import falcon
import falcon.asgi
import falcon.testing
import pytest

from falcon_auth import planes
from falcon_auth.adapters.middleware import (
    AUTH_METHOD_ATTR,
    AUTH_PRINCIPAL_ATTR,
    PLANE_ATTR,
    PlaneAuthenticationMiddleware,
)
from falcon_auth.adapters.routing import PlaneRegistry, UnregisteredRoute, mount
from falcon_auth.errors import Unauthenticated


# ── the host's own not-found, which the 404 must be indistinguishable from ────


class OrderNotFound(Exception):
    """Stands in for the host's real domain not-found."""


async def render_not_found(req, resp, ex, params):
    resp.status = falcon.HTTP_404
    resp.media = {"code": "ORDR0404", "message": "not found"}


async def render_unauthenticated(req, resp, ex, params):
    resp.status = falcon.HTTP_401
    resp.media = {"code": "ORDR0401", "message": "unauthenticated"}


# ── credential fakes: header present+good / present+bad / absent ──────────────


def authenticator(header: str, name: str):
    async def attempt(req):
        value = req.get_header(header)
        if value is None:
            return None
        if value == "bad":
            raise Unauthenticated(f"invalid {name}")
        return f"{name}-principal"

    return attempt


JWT_HEADER = "Authorization"
MTLS_HEADER = "X-Client-Cert"
HMAC_HEADER = "X-Signature"
ONESHOT_HEADER = "X-One-Shot"

ALL_AUTHENTICATORS = {
    planes.JWT: authenticator(JWT_HEADER, "jwt"),
    planes.MTLS: authenticator(MTLS_HEADER, "mtls"),
    planes.HMAC: authenticator(HMAC_HEADER, "hmac"),
    planes.ONE_SHOT_TOKEN: authenticator(ONESHOT_HEADER, "oneshot"),
}


class Echo:
    """Echoes what the middleware stamped, so a 200 proves more than a status code."""

    async def on_get(self, req, resp):
        resp.media = {
            "plane": getattr(req.context, PLANE_ATTR, None),
            "method": getattr(req.context, AUTH_METHOD_ATTR, None),
            "principal": getattr(req.context, AUTH_PRINCIPAL_ATTR, None),
        }


class Boom:
    """A handler whose own domain not-found is the body the 404 must match."""

    async def on_get(self, req, resp):
        raise OrderNotFound()


def build(plane, *, authenticators=None, on_mismatch=None, reason=None):
    registry = PlaneRegistry()
    middleware = PlaneAuthenticationMiddleware(
        registry,
        authenticators=ALL_AUTHENTICATORS if authenticators is None else authenticators,
        not_found_error=OrderNotFound,
        on_plane_mismatch=on_mismatch,
    )
    app = falcon.asgi.App(middleware=[middleware])
    app.add_error_handler(OrderNotFound, render_not_found)
    app.add_error_handler(Unauthenticated, render_unauthenticated)
    mount(registry, app, "/v1/thing", Echo(), plane=plane, reason=reason)
    mount(registry, app, "/v1/boom", Boom(), plane=plane, reason=reason)
    return falcon.testing.TestClient(app), registry, app


# ── steps 1-2: the primary method ─────────────────────────────────────────────


def test_a_valid_primary_credential_passes_and_is_stamped():
    client, _, _ = build(planes.USER)
    r = client.simulate_get("/v1/thing", headers={JWT_HEADER: "good"})
    assert r.status_code == 200
    assert r.json == {"plane": "USER", "method": "JWT", "principal": "jwt-principal"}


def test_an_invalid_primary_credential_is_401_and_does_not_fall_through():
    """Step 2 is a final answer. Falling through to the step-3 search would answer 404 to a
    forged token, telling the holder that a bad token and no token differ -- and that the
    endpoint is on some other plane."""
    client, _, _ = build(planes.USER)
    r = client.simulate_get("/v1/thing", headers={JWT_HEADER: "bad"})
    assert r.status_code == 401


def test_the_service_plane_takes_mtls():
    client, _, _ = build(planes.SERVICE)
    r = client.simulate_get("/v1/thing", headers={MTLS_HEADER: "good"})
    assert r.json == {"plane": "SERVICE", "method": "MTLS", "principal": "mtls-principal"}


# ── step 5: nothing at all ────────────────────────────────────────────────────


def test_no_credential_of_any_kind_is_401():
    client, _, _ = build(planes.USER)
    r = client.simulate_get("/v1/thing")
    assert r.status_code == 401


# ── step 4: the wrong-plane 404 ───────────────────────────────────────────────


def test_a_service_credential_on_a_user_route_is_404():
    client, _, _ = build(planes.USER)
    r = client.simulate_get("/v1/thing", headers={MTLS_HEADER: "good"})
    assert r.status_code == 404


def test_a_user_credential_on_a_service_route_is_404():
    client, _, _ = build(planes.SERVICE)
    r = client.simulate_get("/v1/thing", headers={JWT_HEADER: "good"})
    assert r.status_code == 404


def test_the_mismatch_404_is_indistinguishable_from_a_genuine_not_found():
    """The whole reason the status is 404 rather than 403. If the body differed, the status
    would be a 403 wearing a costume and would hand back the signal it was chosen to withhold."""
    client, _, _ = build(planes.USER)
    mismatch = client.simulate_get("/v1/thing", headers={MTLS_HEADER: "good"})
    genuine = client.simulate_get("/v1/boom", headers={JWT_HEADER: "good"})
    assert genuine.status_code == 404, "the handler's own domain not-found"
    assert mismatch.status_code == genuine.status_code
    assert mismatch.json == genuine.json


def test_the_mismatch_is_flagged_for_the_operator():
    """C-038 requires it be logged AND flagged. The 404 is the answer to the caller; the flag is
    the answer to the operator."""
    flagged = []
    client, _, _ = build(planes.USER, on_mismatch=lambda *a: flagged.append(a))
    client.simulate_get("/v1/thing", headers={MTLS_HEADER: "good"})
    assert flagged == [("/v1/thing", "USER", "MTLS")]


def test_an_invalid_foreign_credential_is_401_not_404():
    """Step 4 is a VALID credential for another plane. Garbage in a header is a caller with no
    usable credential -- step 5 -- and answering 404 would let anyone map the estate by sending
    nonsense."""
    client, _, _ = build(planes.USER)
    r = client.simulate_get("/v1/thing", headers={MTLS_HEADER: "bad"})
    assert r.status_code == 401


def test_a_credential_this_host_cannot_verify_is_not_recognised_as_foreign():
    """With no mTLS authenticator supplied, an mTLS credential is invisible here. It cannot be
    recognised as belonging elsewhere, so the caller ends at step 5."""
    client, _, _ = build(planes.USER, authenticators={planes.JWT: ALL_AUTHENTICATORS[planes.JWT]})
    r = client.simulate_get("/v1/thing", headers={MTLS_HEADER: "good"})
    assert r.status_code == 401


# ── the CALLBACK plane, which carries two methods ─────────────────────────────


def test_callback_accepts_either_of_its_two_methods():
    client, _, _ = build(planes.CALLBACK)
    by_hmac = client.simulate_get("/v1/thing", headers={HMAC_HEADER: "good"})
    by_token = client.simulate_get("/v1/thing", headers={ONESHOT_HEADER: "good"})
    assert by_hmac.json["method"] == "HMAC"
    assert by_token.json["method"] == "ONE_SHOT_TOKEN"


def test_an_invalid_callback_credential_does_not_fall_through_to_the_other():
    """C-031 pins each SOURCE to one method. A source whose signature fails must not be waved
    through because it also sent a token."""
    client, _, _ = build(planes.CALLBACK)
    r = client.simulate_get("/v1/thing", headers={HMAC_HEADER: "bad", ONESHOT_HEADER: "good"})
    assert r.status_code == 401


# ── the PUBLIC plane ──────────────────────────────────────────────────────────


def test_public_demands_nothing_and_inspects_nothing():
    """Looking at a credential nobody verified invites a handler to start trusting it."""
    client, _, _ = build(planes.PUBLIC, reason="served before any account exists")
    r = client.simulate_get("/v1/thing")
    assert r.status_code == 200
    assert r.json == {"plane": "PUBLIC", "method": None, "principal": None}


def test_public_ignores_a_credential_that_is_present():
    client, _, _ = build(planes.PUBLIC, reason="served before any account exists")
    r = client.simulate_get("/v1/thing", headers={MTLS_HEADER: "good"})
    assert r.json["method"] is None


# ── the lifecycle cases Falcon forces on us ───────────────────────────────────


def test_a_wrong_verb_is_left_to_falcons_own_405():
    """Falcon runs process_resource for a DELETE against a GET-only resource, and the registry
    has no row for that pair. Refusing there would turn a clean 405 into a 500."""
    client, _, _ = build(planes.USER)
    r = client.simulate_delete("/v1/thing", headers={JWT_HEADER: "good"})
    assert r.status_code == 405


def test_an_unrouted_path_never_reaches_the_middleware():
    client, _, _ = build(planes.USER)
    assert client.simulate_get("/v1/nowhere").status_code == 404


def test_a_route_that_bypassed_mount_is_refused():
    """The net under verify_app. An unregistered route has no plane, so nothing can be required
    of its callers -- and "nothing required" is the outcome the arrangement exists to prevent.

    Falcon renders the raise as a generic 500 rather than letting it propagate. That is the
    right shape: the request is NOT served, and the body says nothing about why."""
    client, registry, app = build(planes.USER)
    app.add_route("/v1/sneaky", Echo())
    r = client.simulate_get("/v1/sneaky", headers={JWT_HEADER: "good"})
    assert r.status_code == 500
    assert "plane" not in r.text, "the handler must not have run"


def test_a_plane_whose_method_has_no_authenticator_fails_loudly():
    """A route nobody can open. Failing beats answering 401 to every caller forever, which gets
    diagnosed as a credential problem for a day and a half."""
    client, _, _ = build(planes.SERVICE, authenticators={planes.JWT: ALL_AUTHENTICATORS[planes.JWT]})
    r = client.simulate_get("/v1/thing", headers={MTLS_HEADER: "good"})
    assert r.status_code == 500
    assert "plane" not in r.text


def test_the_refusal_branches_raise_a_catchable_wiring_error():
    """Asserted directly, because Falcon flattens it to a 500 over HTTP: a host that wants to
    fail its own startup or alert on this needs the type, not the status."""
    from falcon_auth.adapters.middleware import PlaneAuthenticationMiddleware

    registry = PlaneRegistry()
    mw = PlaneAuthenticationMiddleware(
        registry, authenticators={}, not_found_error=OrderNotFound
    )

    class Req:
        uri_template = "/v1/unknown"
        method = "GET"

    with pytest.raises(UnregisteredRoute, match="was never registered"):
        import asyncio

        asyncio.run(mw.process_resource(Req(), None, Echo(), {}))

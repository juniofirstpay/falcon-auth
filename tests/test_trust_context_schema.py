"""The trust-context feed, per `registry/TRUST-CONTEXT.md` (normative, RUL-162-165).

Strict parsing -- a missing required field is never defaulted (S4) -- with exactly one recorded
exception, the C-052 §3 deviation (RUL-162, platform-conventions#23).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError
from structlog.testing import capture_logs

from falcon_auth.trustcontext import HttpTrustContextClient, TrustContext

CUSTOMER = {
    "session_ref": "sess-1",
    "user_ref": "user-1",
    "client_ref": "client-1",
    "device_ref": "device-1",
    "session_state": 1,
    "device_trust_level": 3,
    "session_trust_level": 1,
    "trust_elevated_until": None,
    "grants": ["CUSTOMER_GRANT"],
    "actor_type": "CUSTOMER",
    "session_kind": "NORMAL",
    "delegations": [],
}

DELEGATION = {
    "ref": "dlg_1",
    "grant": "DELEGATED_CUSTOMER_GRANT",
    "subject_ref": "user-2",
    "valid_until": "2099-01-01T00:00:00.000Z",
}

SHADOW = {
    **CUSTOMER,
    "user_ref": "op-1",
    "grants": [],
    "actor_type": "OPERATOR",
    "actor_kind": "AGENT",
    "session_kind": "SHADOW",
    "delegations": [{**DELEGATION, "grant": "CUSTOMER_IMPERSONATION_GRANT", "case_ref": "case_9"}],
}


# ─── the shapes the schema allows ────────────────────────────────────────────


def test_a_customer_session_parses():
    ctx = TrustContext.model_validate(CUSTOMER)
    assert (ctx.actor_type, ctx.session_kind, ctx.delegations, ctx.actor_type_assumed) == (
        "CUSTOMER", "NORMAL", [], False)


def test_a_delegated_customer_session_parses():
    ctx = TrustContext.model_validate({**CUSTOMER, "delegations": [DELEGATION]})
    assert ctx.delegations[0].subject_ref == "user-2" and ctx.delegations[0].live()


def test_a_shadow_session_parses():
    ctx = TrustContext.model_validate(SHADOW)
    assert ctx.actor_kind == "AGENT" and ctx.delegations[0].case_ref == "case_9"


def test_unknown_fields_are_accepted():
    """S4: additive changes only, so a parser accepts what it does not know."""
    TrustContext.model_validate({**CUSTOMER, "something_new": 1})


# ─── S4: a missing required field is never defaulted ─────────────────────────


@pytest.mark.parametrize(
    "missing",
    ["grants", "actor_type", "session_kind", "delegations", "client_ref", "device_ref",
     "trust_elevated_until"],
)
def test_a_missing_required_field_fails(missing):
    with pytest.raises(ValidationError):
        TrustContext.model_validate({k: v for k, v in CUSTOMER.items() if k != missing})


def test_an_actor_type_outside_the_closed_set_fails():
    with pytest.raises(ValidationError):
        TrustContext.model_validate({**CUSTOMER, "actor_type": "ADMIN"})


# ─── actor_kind iff OPERATOR (C-052 §2) ──────────────────────────────────────


def test_an_operator_needs_a_kind():
    with pytest.raises(ValidationError, match="actor_kind"):
        TrustContext.model_validate({**CUSTOMER, "actor_type": "OPERATOR"})


def test_a_customer_has_no_kind():
    with pytest.raises(ValidationError, match="actor_kind"):
        TrustContext.model_validate({**CUSTOMER, "actor_kind": "AGENT"})


# ─── S3: a shadow session ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "broken",
    [
        {"actor_type": "CUSTOMER", "actor_kind": None},
        {"grants": ["CUSTOMER_GRANT"]},
        {"delegations": []},
        {"delegations": [SHADOW["delegations"][0], SHADOW["delegations"][0]]},
        {"delegations": [DELEGATION]},                                   # no case_ref
    ],
    ids=["not-an-operator", "holds-grants", "no-delegation", "two-delegations", "no-case-ref"],
)
def test_a_shadow_session_breaking_s3_fails(broken):
    with pytest.raises(ValidationError, match="S3"):
        TrustContext.model_validate({**SHADOW, **broken})


def test_case_ref_appears_only_on_a_shadow_session():
    with pytest.raises(ValidationError, match="case_ref"):
        TrustContext.model_validate({**CUSTOMER, "delegations": [{**DELEGATION, "case_ref": "c"}]})


def test_valid_until_is_c009_utc_z():
    with pytest.raises(ValidationError, match="C-009"):
        TrustContext.model_validate(
            {**CUSTOMER, "delegations": [{**DELEGATION, "valid_until": "2099-01-01T00:00:00+05:30"}]})


def test_an_expired_delegation_is_not_live():
    ctx = TrustContext.model_validate(
        {**CUSTOMER, "delegations": [{**DELEGATION, "valid_until": "2000-01-01T00:00:00.000Z"}]})
    assert not ctx.delegations[0].live()


# ─── the recorded C-052 §3 deviation (RUL-162) ───────────────────────────────

AUTH_TODAY = {k: v for k, v in CUSTOMER.items()
              if k not in ("actor_type", "session_kind", "delegations")}


def test_off_by_default_an_absent_actor_type_fails():
    with pytest.raises(ValidationError):
        TrustContext.from_feed(AUTH_TODAY)


def test_on_an_absent_actor_type_reads_as_customer_and_is_logged():
    with capture_logs() as logs:
        ctx = TrustContext.from_feed(AUTH_TODAY, assume_customer_actor_type=True)
    assert (ctx.actor_type, ctx.session_kind, ctx.delegations, ctx.actor_type_assumed) == (
        "CUSTOMER", "NORMAL", [], True)
    assert any(e["event"] == "trust_context_actor_type_assumed" for e in logs)


def test_on_a_present_actor_type_is_taken_as_sent_and_nothing_is_assumed():
    ctx = TrustContext.from_feed(SHADOW, assume_customer_actor_type=True)
    assert ctx.actor_type == "OPERATOR" and not ctx.actor_type_assumed


def test_the_deviation_never_defaults_grants():
    with pytest.raises(ValidationError):
        TrustContext.from_feed({k: v for k, v in AUTH_TODAY.items() if k != "grants"},
                               assume_customer_actor_type=True)


def test_the_assumed_flag_is_never_taken_from_the_wire():
    assert not TrustContext.model_validate({**CUSTOMER, "actor_type_assumed": True}).actor_type_assumed
    assert "actor_type_assumed" not in TrustContext.model_validate(CUSTOMER).model_dump()


async def test_the_http_client_carries_the_switch():
    def client(payload, **kw):
        class _Resp:
            status = 200

            async def json(self):
                return payload

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class _Session:
            def get(self, path, **kw):
                return _Resp()

        return HttpTrustContextClient(lambda: _Session(), path_template="/t/{session_ref}",  # type: ignore[arg-type,return-value]
                                      api_version=None, **kw)

    from falcon_auth.errors import AuthzUnavailable

    with pytest.raises(AuthzUnavailable):
        await client(AUTH_TODAY).fetch("sess-1", user_ref="user-1")
    with capture_logs():
        ctx = await client(AUTH_TODAY, assume_customer_actor_type=True).fetch("sess-1",
                                                                            user_ref="user-1")
    assert ctx.actor_type == "CUSTOMER" and ctx.actor_type_assumed


# ─── the principal carries what the guards (C-052, C-053) will read ──────────


async def test_the_resolver_puts_the_actor_fields_on_the_principal():
    from falcon_auth.entitlement.resolver import AuthServiceResolver
    from falcon_auth.trustcontext import NullCache, TrustContextCache

    class _Client:
        async def fetch(self, session_ref, *, user_ref):
            return TrustContext.model_validate(SHADOW)

    class _User:
        id = "op-1"

        def get(self, key, default=None):
            return {"sid": "sess-1"}.get(key, default)

    principal = await AuthServiceResolver(_Client(), TrustContextCache(NullCache())).resolve(_User())
    assert (principal.actor_type, principal.actor_kind, principal.session_kind) == (
        "OPERATOR", "AGENT", "SHADOW")
    assert principal.delegations[0].case_ref == "case_9" and not principal.actor_type_assumed

from __future__ import annotations

import falcon

from falcon_auth import (
    MissingClientCertError,
    MissingScopeError,
    SvcPlaneError,
    SvcPlaneErrorCodes,
    UnknownCNError,
)


# ─── SvcPlaneErrorCodes ──────────────────────────────────────────────────────


def test_default_codes_match_reserved_band():
    # Reserved default band on the wire:
    #   E9000 client_certificate_required
    #   E9001 unknown_certificate_identity
    #   E9002 scope_not_granted
    codes = SvcPlaneErrorCodes()
    assert codes.missing_cert == 9000
    assert codes.unknown_cn == 9001
    assert codes.missing_scope == 9002


def test_codes_are_immutable_dataclass():
    import dataclasses
    codes = SvcPlaneErrorCodes()
    assert dataclasses.is_dataclass(codes)
    # frozen=True → attribute assignment raises FrozenInstanceError.
    try:
        codes.missing_cert = 1  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:  # pragma: no cover - regression only
        raise AssertionError("expected FrozenInstanceError")


# ─── hardened wire fields per subclass ───────────────────────────────────────


def test_missing_client_cert_error_hardened_fields():
    ex = MissingClientCertError()
    assert ex.code == 9000
    assert ex.title == "MissingClientCertError"
    assert ex.http_status == falcon.HTTP_401
    assert ex.description == "east-west plane requires a client certificate (mTLS)"
    assert ex.extras is None


def test_unknown_cn_error_hardened_fields_and_cn_extras():
    ex = UnknownCNError(cn="stranger.svc")
    assert ex.code == 9001
    assert ex.title == "UnknownCNError"
    assert ex.http_status == falcon.HTTP_403
    assert ex.description == "certificate CN is not in the allow-list"
    assert ex.extras == {"cn": "stranger.svc"}
    assert ex.cn == "stranger.svc"


def test_missing_scope_error_interpolates_scope_into_description():
    ex = MissingScopeError(scope="invites:dispatch")
    assert ex.code == 9002
    assert ex.title == "MissingScopeError"
    assert ex.http_status == falcon.HTTP_403
    assert ex.description == "certificate identity is not granted invites:dispatch"
    assert ex.extras == {"scope": "invites:dispatch"}
    assert ex.scope == "invites:dispatch"


# ─── wire format (SvcPlaneError.json) ────────────────────────────────────────


def test_json_omits_extras_when_none():
    body = MissingClientCertError().json()
    assert body == {
        "code": 9000,
        "title": "MissingClientCertError",
        "description": "east-west plane requires a client certificate (mTLS)",
    }
    assert "extras" not in body


def test_json_includes_extras_when_present():
    body = UnknownCNError(cn="stranger.svc").json()
    assert body == {
        "code": 9001,
        "title": "UnknownCNError",
        "description": "certificate CN is not in the allow-list",
        "extras": {"cn": "stranger.svc"},
    }


def test_json_includes_interpolated_description_for_missing_scope():
    body = MissingScopeError(scope="invites:dispatch").json()
    assert body == {
        "code": 9002,
        "title": "MissingScopeError",
        "description": "certificate identity is not granted invites:dispatch",
        "extras": {"scope": "invites:dispatch"},
    }


# ─── code override ──────────────────────────────────────────────────────────


def test_missing_client_cert_error_accepts_custom_code():
    ex = MissingClientCertError(code=5000)
    assert ex.code == 5000
    # Everything else stays hardened.
    assert ex.title == "MissingClientCertError"
    assert ex.description == "east-west plane requires a client certificate (mTLS)"


def test_unknown_cn_error_accepts_custom_code():
    ex = UnknownCNError(cn="x.svc", code=5001)
    assert ex.code == 5001
    assert ex.cn == "x.svc"


def test_missing_scope_error_accepts_custom_code():
    ex = MissingScopeError(scope="x:y", code=5002)
    assert ex.code == 5002
    assert ex.scope == "x:y"


# ─── inheritance / handler dispatch ──────────────────────────────────────────


def test_all_three_subclasses_inherit_from_svcplane_error():
    # register_error_handlers(app) plumbs one handler for SvcPlaneError — the
    # inheritance chain is what lets it catch all three conditions.
    assert issubclass(MissingClientCertError, SvcPlaneError)
    assert issubclass(UnknownCNError, SvcPlaneError)
    assert issubclass(MissingScopeError, SvcPlaneError)

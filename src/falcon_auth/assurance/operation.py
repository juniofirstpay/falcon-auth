"""Per-operation step-up: did the user prove themselves for THIS act.

The sibling of :mod:`falcon_auth.assurance.stepup`, and not a variant of it. The two answer
questions that only sound alike:

    general elevation      is this session elevated RIGHT NOW          a state, a time window
    per-operation step-up  did the user step up FOR THIS OPERATION     an act, a single use

WHY A MUTATION CANNOT USE THE FIRST ONE. An elevation window authorizes a *period*. Gate a write
on it and one step-up authorizes every write until the window closes -- the user proved
themselves once and paid for a hundred mutations. That is not a weaker version of the same
control; it is a different control that happens to report the same tier. A read may sit behind
the window, because reading twice is reading the same thing twice. A write may not.

The two therefore coexist on one resource: a profile route can gate its GET on
:func:`~falcon_auth.assurance.stepup.check_session_elevated` and its PATCH on this, and that is
the intended shape rather than a redundancy to be tidied away.

CONSUME BEFORE EXECUTE. :func:`verify_operation` SPENDS the authorization. Call it before the
mutation and perform the write only on success: consuming afterwards would let a crash between
write and consume authorize a second execution. The cost is accepted and real -- if the write
then fails, the challenge is gone and the user must step up again rather than retry.

THE ORDERING THAT MATTERS, and it is why there is no ``before`` hook for this.
``X-Operation-ID`` is also the idempotency key, so the same value identifies the challenge AND
the cached response. A retry whose first response was lost must return that cached response and
must NOT reach here -- the challenge was consumed on the first attempt, so this would answer
:class:`OperationChallengeMiss` and fail the exact retry the key exists to make safe.

The verify therefore belongs AFTER the idempotency reservation, on the branch that says this is
a genuine first execution -- and in this estate that reservation is taken INLINE in the
responder, after every hook has run. A hook would spend the challenge on every replay. Since
``X-Operation-ID`` *is* the idempotency key, a route using this mechanism has idempotency by
construction, so a hook is wrong wherever it would be used at all.

Call :func:`falcon_auth.adapters.hooks.verify_operation_for` from the responder instead, and
reuse the fingerprint the reservation already computes rather than defining "canonical" twice.

BODY BINDING IS CALLER-SIDE. Auth stores the body hash the challenge was raised against and
returns it rather than comparing, because canonicalizing a body is the consuming service's
concern -- it owns its schema, and two byte-different encodings of the same request are the
same request only by rules this package cannot know. The host supplies the hash function; this
module compares and refuses a mismatch. Without that comparison a challenge raised to move 500
authorizes a body that moves 50000.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import aiohttp
from pydantic import BaseModel, ConfigDict, ValidationError
from structlog import get_logger

from ..errors import AuthzError, AuthzUnavailable

logger = get_logger(__name__)

__all__ = (
    "AUTH_CODE_OPERATION_MISS",
    "BodyHasher",
    "HttpOperationVerifier",
    "OperationBodyMismatch",
    "OperationChallengeMiss",
    "OperationPurposeMismatch",
    "OperationVerification",
    "OperationVerifier",
    "verify_operation",
)


class OperationChallengeMiss(AuthzError):
    """The challenge is not spendable: unknown, not passed, expired, or already consumed.

    Auth answers all of those with one uniform code, deliberately -- a consumed operation
    "looks gone", so challenge state does not leak across the mTLS boundary. This package keeps
    that uniformity rather than guessing which case it was.

    **Not a retry.** The client's recovery is to run step-up again under a NEW operation id.
    Distinguishable from an ordinary failure on purpose: a client that treats it as transient
    retries forever into a challenge that will never become spendable again.
    """


class OperationPurposeMismatch(AuthzError):
    """A real challenge, passed and unspent -- raised for a different purpose.

    Note what has already happened by the time this raises: auth **consumed** the challenge,
    because it was perfectly valid for the purpose it was raised under. Auth cannot make this
    check -- the operation id is unique only within a session and auth does not know which route
    is redeeming it. So the challenge is spent either way, and the user must re-challenge under
    the right purpose. That is the cost of catching cross-purpose replay at the only place it
    can be caught.
    """


class OperationBodyMismatch(AuthzError):
    """The request body is not the one the step-up was raised against.

    The challenge authorized a specific act. A body that hashes differently is a different act,
    whatever the operation id says -- this is the check that stops a step-up for one amount
    being spent on another.
    """


class OperationVerification(BaseModel):
    """What auth returns when a challenge is successfully consumed."""

    model_config = ConfigDict(extra="ignore")

    session_ref: str
    user_ref: str
    operation_id: str
    #: The policy this challenge was raised under, e.g. ``mpin_reset``. THE discriminator:
    #: `ChallengePolicy` is keyed by purpose, and a challenge passed for one purpose must not
    #: authorize another. See :func:`verify_operation`'s ``expected_purpose``.
    purpose: str
    #: The tier recorded on the challenge row. Read it as provenance, NOT as session trust: an
    #: operation-scoped step-up does not move the session's ambient tier (AUTH-ADR-112), so
    #: this says what policy the challenge was raised under, not what the session now is.
    target_session_tier: int
    #: base64url of the body hash the challenge was bound to, or ``None`` when the purpose's
    #: policy declares it not body-bound (`ChallengePolicy.body_hash_required`). The CALLER
    #: compares it; auth stores and returns it but does not compare.
    request_body_hash: str | None = None
    #: ISO-8601 UTC -- when this call spent the challenge.
    consumed_at: str | None = None


class OperationVerifier(Protocol):
    """Consumes a challenge at auth. Injected, so this module performs no HTTP of its own."""

    async def verify(
        self, session_ref: str, operation_id: str, *, user_ref: str
    ) -> OperationVerification: ...


async def verify_operation(
    verifier: OperationVerifier,
    session_ref: str,
    operation_id: str,
    *,
    user_ref: str,
    expected_purpose: str,
    body_hash: str | None = None,
) -> OperationVerification:
    """Consume the challenge for ``operation_id`` and check it authorizes THIS act.

    **This spends the authorization.** Call it before the mutation; execute only on success.

    :param expected_purpose: the purpose this route accepts. **Required, with no default.**

        Purpose is the discriminator, not a tier. A challenge is raised under a policy
        (`ChallengePolicy`, keyed by purpose) and passed against that policy; a challenge the
        user passed for ``mpin_reset`` must not be spendable on a wallet transfer just because
        both are operation-scoped. Auth cannot make that check -- the operation id is unique
        within a session, and auth does not know which route is redeeming it -- so it is the
        consuming service's, and it is the reason this parameter has no default. Defaulting it
        would make cross-purpose replay the behaviour you get by forgetting.

    :param body_hash: this service's canonical hash of the request body, or ``None`` if it has
        not computed one. ``None`` is not "skip the check" -- see :func:`_check_body`.

    :raises OperationChallengeMiss: unknown, unpassed, expired or already consumed.
    :raises OperationPurposeMismatch: a real challenge, raised for a different purpose.
    :raises OperationBodyMismatch: the body is not the one the challenge was bound to.
    :raises AuthzUnavailable: the lookup itself failed, or our certificate lacks
        ``step_up:verify``. An infrastructure fault, never a user denial.

    .. note::
       There is deliberately no ``required_tier`` here. An operation-scoped step-up does **not**
       raise the session's ambient trust tier (AUTH-ADR-112): ``challenge:authenticate`` returns
       **204** and writes no trust state, because a proof scoped to one operation must not grant
       a blanket window over the whole session. ``target_session_tier`` still rides on the
       response as provenance, but gating on it would assert session-trust semantics this path
       does not have. The session tier is :mod:`falcon_auth.assurance.stepup`'s question.
    """
    verification = await verifier.verify(session_ref, operation_id, user_ref=user_ref)

    if verification.purpose != expected_purpose:
        # A real, passed, unspent challenge -- for a different act. Refusing it here is the only
        # place this can be caught: auth consumed it because it was valid FOR ITS OWN purpose.
        raise OperationPurposeMismatch(
            "this step-up was raised for a different purpose",
            operation_id=operation_id,
            expected=expected_purpose,
            present=verification.purpose,
        )

    _check_body(verification, body_hash, operation_id)
    return verification


def _check_body(
    verification: OperationVerification, body_hash: str | None, operation_id: str
) -> None:
    """Compare our canonical body hash against the one the challenge was bound to.

    Four cases, and the asymmetry between the middle two is the point:

        auth bound a hash, we computed one     compare; mismatch is a refusal
        auth bound a hash, we computed NONE    REFUSE -- the binding exists and we cannot
                                               honour it, so we must not spend the challenge
        auth bound none, we computed one       fine; the purpose is not body-bound and there is
                                               nothing to compare against
        auth bound none, we computed none      fine

    The second case is the one worth being strict about. Treating "we have no hash" as "no
    check needed" would let a service opt out of body binding by forgetting to pass a hash --
    which is exactly how a body-bound challenge stops being body-bound.
    """
    expected = verification.request_body_hash
    if expected is None:
        return
    if body_hash is None:
        raise OperationBodyMismatch(
            "this challenge is bound to a request body but no body hash was computed to check "
            "it against -- refusing rather than spending a binding we cannot honour",
            operation_id=operation_id,
        )
    if body_hash != expected:
        raise OperationBodyMismatch(
            "the request body is not the one this step-up was raised against",
            operation_id=operation_id,
        )


#: A host-supplied canonicalizer: parsed request body in, hash string out.
#:
#: The package cannot write this. Canonicalizing means turning a body into one predictable
#: string so the same logical request always hashes the same way -- which field order, which
#: number formatting, which fields count at all. Those are schema questions and the schema is
#: the consumer's.
BodyHasher = Callable[[Any], str]


# -- the HTTP client ------------------------------------------------------------------------

#: auth's uniform "not spendable" code: unknown, not passed, expired, or already consumed.
AUTH_CODE_OPERATION_MISS = 8501


class HttpOperationVerifier:
    """Default `OperationVerifier` over the host's mTLS session.

    Requires **mTLS + `require_service_scope("step_up:verify")`** on this service's certificate.
    A 403 therefore means OUR certificate is missing that scope -- a deployment fault, mapped to
    `AuthzUnavailable`, never to a user denial. Reporting it as one would read as "every user
    lost their step-up" during a bad rollout.
    """

    def __init__(
        self,
        session_getter: Callable[[], aiohttp.ClientSession],
        *,
        path_template: str,
        api_version: str | None,
    ) -> None:
        """
        :param path_template: auth's operation-verify path, with `{session_ref}` and
            `{operation_id}` placeholders. Required, with no default, for the same reason the
            trust-context path is: where auth is mounted and under which API version is a
            deployment fact, and a library that guesses it is wrong for the first consumer who
            mounts it elsewhere.
        :param api_version: value for the ``X-API-Version`` header, or ``None`` to send none.
            **Required, with no default.**

            C-039 drops this header -- the version is the first path segment -- but auth has not
            adopted C-039 and gates every endpoint on it (`validate_api_version`, 400/E1004 when
            missing or unknown). So the correct value depends on which auth you are talking to,
            and both plausible defaults are wrong somewhere: defaulting to ``"1"`` keeps sending
            a header the convention retired, and defaulting to ``None`` 400s against auth as
            deployed today. Neither failure is loud, so the host states it.
        """
        self._session_getter = session_getter
        self._path_template = path_template
        self._headers = {"X-API-Version": api_version} if api_version is not None else {}

    async def verify(
        self, session_ref: str, operation_id: str, *, user_ref: str
    ) -> OperationVerification:
        path = self._path_template.format(
            session_ref=session_ref, operation_id=operation_id
        )
        try:
            session = self._session_getter()
            async with session.post(
                path, json={"user_ref": user_ref}, headers=self._headers
            ) as response:
                if response.status == 200:
                    return OperationVerification.model_validate(await response.json())
                await self._raise_for(response, operation_id)
        except (OperationChallengeMiss, AuthzUnavailable):
            raise
        except ValidationError as e:
            await logger.aerror("operation-verify response failed validation", exc_info=e)
            raise AuthzUnavailable(
                "operation-verify response did not match the expected shape"
            ) from e
        except aiohttp.ClientError as e:
            await logger.aerror("operation-verify transport failure", exc_info=e)
            raise AuthzUnavailable("step-up source unreachable") from e
        except TimeoutError as e:
            await logger.aerror("operation-verify timed out", exc_info=e)
            raise AuthzUnavailable("step-up source timed out") from e
        raise AuthzUnavailable("operation-verify returned no usable response")  # pragma: no cover

    async def _raise_for(self, response: Any, operation_id: str) -> None:
        body: Any = None
        try:
            body = await response.json()
        except Exception:  # noqa: BLE001 -- an unparseable error body must not mask the status
            body = None
        code = _operation_error_code(body)

        if response.status == 410 or code == AUTH_CODE_OPERATION_MISS:
            # Uniform by design: unknown, unpassed, expired and consumed are indistinguishable
            # here, so challenge state does not leak. NOT a retry -- a new challenge is needed.
            raise OperationChallengeMiss(
                "this step-up challenge is not spendable -- run step-up again under a new "
                "operation id",
                operation_id=operation_id,
            )
        if response.status == 403:
            await logger.aerror(
                "operation-verify refused our certificate -- is `step_up:verify` granted to "
                "this service?",
                status=response.status,
            )
            raise AuthzUnavailable("this service is not entitled to verify step-up operations")
        await logger.aerror(
            "operation-verify error response", status=response.status, code=code, body=body
        )
        raise AuthzUnavailable(f"step-up source returned {response.status}")


def _operation_error_code(body: Any) -> int | None:
    """auth's error envelope is `{"code": n}` or `{"error": {"code": n}}` -- accept both."""
    if not isinstance(body, dict):
        return None
    raw = body.get("code")
    if raw is None:
        nested = body.get("error")
        raw = nested.get("code") if isinstance(nested, dict) else None
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None

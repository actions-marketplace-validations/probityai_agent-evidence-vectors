"""Recheck visible authority state at every grant or lease presentation."""

from __future__ import annotations

from typing import Any

from .common import InputError, authentic, equivalent, instant, refusal, sign_test_authorization


def window_reason(authorization: dict[str, Any], presentation: dict[str, Any]) -> str | None:
    issued = instant(authorization["issued_at"])
    expires = instant(authorization["expires_at"])
    at = instant(presentation["at"])
    if expires <= issued:
        raise InputError("authorization: empty or reversed validity window")
    if at < issued:
        return "authority_not_yet_valid"
    if at >= expires:
        return "authority_expired"
    return None


def grant_reason(authorization: dict[str, Any], presentation: dict[str, Any]) -> str | None:
    revoked = presentation["revoked_kids"]
    if not isinstance(revoked, list) or any(not isinstance(kid, str) for kid in revoked):
        raise InputError("revoked_kids: expected strings")
    if authorization["kid"] in revoked:
        return "authority_revoked"
    if not equivalent(authorization["observation"], presentation["observation"]):
        return "authority_stale"
    if authorization["decision"] != "accept":
        return "decision_not_accept"
    return None


def lease_reason(authorization: dict[str, Any], presentation: dict[str, Any]) -> str | None:
    fields = ("policy_bundle", "toolspec_hash", "toolspec_version")
    if any(not equivalent(authorization[field], presentation[field]) for field in fields):
        return "authority_stale"
    return None


def evaluate(case: dict[str, Any]) -> dict[str, Any]:
    stage = case["stage"]
    if stage not in {"grant", "dispatch"}:
        raise InputError("unknown authority stage")
    authorization = case["authorization"]
    envelope = sign_test_authorization(authorization)
    verified = authentic(envelope)
    presentations = case["presentations"] if stage == "grant" else [case["dispatch"]]
    spent = False
    outcomes: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    check = grant_reason if stage == "grant" else lease_reason
    for index, presentation in enumerate(presentations):
        reason = "authority_unverifiable" if not verified else window_reason(
            authorization, presentation
        )
        if reason is None:
            reason = "authority_consumed" if spent else check(authorization, presentation)
        outcome = "ADMITTED" if stage == "grant" else "DISPATCHED"
        outcomes.append(refusal(reason) if reason else {"outcome": outcome, "refusal_class": None})
        if reason is None:
            spent = True
            events.append({"type": "grant_admitted" if stage == "grant" else "dispatch",
                           "attempt": index, "at": presentation["at"]})
    return {"outcomes": outcomes, "authority_verified": verified,
            "authority_spent": spent, "events": events, "authorization_envelope": envelope}

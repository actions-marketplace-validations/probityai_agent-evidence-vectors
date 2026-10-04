"""Bind the presented call and spend authority only on an accepted dispatch."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .common import (
    InputError,
    authentic,
    digest,
    equivalent,
    refusal,
    sign_test_authorization,
    string,
    success,
    wire,
)

CALL_FIELDS = ("tool", "arguments", "tenant", "target")


def invoke_fixture_callback(call: dict[str, Any], attempt: int,
                            captured: list[dict[str, Any]]) -> None:
    captured.append({"type": "dispatch", "attempt": attempt, "call": call,
                     "at": datetime.now(UTC).isoformat(),
                     "callback": "local_fixture_call_log",
                     "call_sha256": digest(wire(call))})


def validate_call(call: dict[str, Any]) -> None:
    if not isinstance(call, dict) or not isinstance(call.get("arguments"), dict):
        raise InputError("call: object arguments required")
    for name in ("tool", "tenant", "target", "actor"):
        string(call.get(name), name)


def dispatch_reason(payload: dict[str, Any], call: dict[str, Any], spent: bool) -> str | None:
    if call["actor"] != payload["actor"]:
        return "principal_mismatch"
    if any(not equivalent(call[field], payload[field]) for field in CALL_FIELDS):
        return "call_mismatch"
    if spent:
        return "authority_consumed"
    return None


def evaluate(case: dict[str, Any]) -> dict[str, Any]:
    authorization = case["authorization"]
    validate_call(authorization)
    calls = case["dispatches"]
    if not isinstance(calls, list) or not calls:
        raise InputError("dispatches: a nonempty list is required")
    envelope = sign_test_authorization(authorization)
    verified = authentic(envelope)
    spent = False
    outcomes: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        validate_call(call)
        reason = dispatch_reason(envelope["payload"], call, spent) if verified else (
            "authority_unverifiable"
        )
        outcomes.append(refusal(reason) if reason else success("DISPATCHED"))
        if reason is None:
            spent = True
            invoke_fixture_callback(call, index, events)
    return {"outcomes": outcomes, "authority_verified": verified,
            "authority_spent": spent, "events": events, "authorization_envelope": envelope}

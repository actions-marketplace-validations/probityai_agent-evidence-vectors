"""Keep dispatch, reports and the declared observed delta as separate facts."""

from __future__ import annotations

from typing import Any

from .common import InputError, equivalent


def numeric(item: Any) -> bool:
    return isinstance(item, (int, float)) and not isinstance(item, bool)


def field_matches(rule: str, expected: Any, observed: dict[str, Any], field: str) -> bool:
    if rule == "present":
        return field in observed
    if rule == "absent":
        return field not in observed
    if field not in observed:
        return False
    value = observed[field]
    if rule == "exact":
        return equivalent(expected, value)
    if rule == "version_increment":
        return numeric(expected) and numeric(value) and value > expected
    raise InputError("unsupported effect comparison rule")


def effect_status(postcondition: Any, observed: Any) -> str:
    if postcondition is None:
        return "NOT_EVALUATED"
    fields = postcondition["expected_fields"]
    rules = postcondition["comparison_rules"]
    if not isinstance(fields, dict) or not isinstance(rules, dict):
        raise InputError("postcondition: expected field and comparison objects")
    if not fields or any(rule not in {"exact", "present", "absent", "version_increment"}
                         for rule in rules.values()):
        return "EFFECT_UNSUPPORTED"
    if observed is None:
        return "EFFECT_UNOBSERVABLE"
    if not isinstance(observed, dict):
        raise InputError("observed: object or null required")
    matched = all(field_matches(rules.get(field, "exact"), expected, observed, field)
                  for field, expected in fields.items())
    return "EFFECT_VERIFIED" if matched else "EFFECT_MISMATCH"


def evaluate(case: dict[str, Any]) -> dict[str, Any]:
    dispatch = case["dispatch"]["outcome"]
    if dispatch == "REFUSED":
        return {"effect_status": "NOT_EVALUATED", "highest_established_state": "NOT_DISPATCHED"}
    if dispatch not in {"DISPATCHED", "BEGAN_OUTCOME_UNKNOWN"}:
        raise InputError("unknown dispatch outcome")
    report = case["execution_report"]
    reported_success = isinstance(report, dict) and report.get("status") == "success"
    state = "EXECUTION_REPORTED_SUCCESS" if reported_success else "DISPATCHED"
    status = effect_status(case["postcondition"], case["observed"])
    if status == "EFFECT_VERIFIED":
        state = "EFFECT_VERIFIED"
    elif status == "EFFECT_MISMATCH":
        state = "DISPATCHED"
    return {"effect_status": status, "highest_established_state": state,
            "execution_report": report, "declared_postcondition": case["postcondition"],
            "supplied_observation": case["observed"]}

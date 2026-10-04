"""Additional falsification inputs; the upstream frozen bytes stay untouched."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from remora_boundary.common import load_raw


def clone(profile: Path, contract: str, identifier: str, new_id: str) -> dict[str, Any]:
    path = profile / "source/artifacts/interop" / contract / "fixtures.json"
    cases = load_raw(path.read_bytes())
    case = copy.deepcopy(next(case for case in cases["cases"] if case["id"] == identifier))
    case["id"] = new_id
    return case


def own_cases(profile: Path) -> list[tuple[str, dict[str, Any]]]:
    rows: list[tuple[str, dict[str, Any]]] = []
    binding = "exact-call-binding-v1"
    case = clone(profile, binding, "argument_value_changed", "own-bool-number-distinction")
    case["dispatches"][0]["arguments"] = copy.deepcopy(case["authorization"]["arguments"])
    case["dispatches"][0]["arguments"]["meta"]["retries"] = False
    rows.append((binding, case))
    case = clone(profile, binding, "actor_changed", "own-wrong-principal-does-not-consume")
    valid = {key: value for key, value in case["authorization"].items() if key != "integrity"}
    case["dispatches"] += [copy.deepcopy(valid), copy.deepcopy(valid)]
    case["expected"]["outcomes"] += [
        {"outcome": "DISPATCHED", "refusal_class": None},
        {"outcome": "REFUSED", "refusal_class": "authority_consumed"},
    ]
    rows.append((binding, case))
    rows.extend(fresh_cases(profile))
    rows.extend(effect_cases(profile))
    return rows


def fresh_cases(profile: Path) -> list[tuple[str, dict[str, Any]]]:
    contract = "fresh-authority-v1"
    rows: list[tuple[str, dict[str, Any]]] = []
    for identifier, at, refusal in (
        ("own-expiry-endpoint-exclusive", "2026-10-04T12:05:00Z", "authority_expired"),
        ("own-issue-endpoint-inclusive", "2026-10-04T12:00:00Z", None),
    ):
        case = clone(profile, contract, "grant_within_window_admitted", identifier)
        case["presentations"][0]["at"] = at
        case["expected"]["outcomes"] = [{"outcome": "REFUSED" if refusal else "ADMITTED",
                                         "refusal_class": refusal}]
        rows.append((contract, case))
    case = clone(profile, contract, "grant_for_other_observation", "own-stale-does-not-consume")
    correct = copy.deepcopy(case["presentations"][0])
    correct["observation"] = case["authorization"]["observation"]
    case["presentations"] += [correct, copy.deepcopy(correct)]
    case["expected"]["outcomes"] += [
        {"outcome": "ADMITTED", "refusal_class": None},
        {"outcome": "REFUSED", "refusal_class": "authority_consumed"},
    ]
    rows.append((contract, case))
    for integrity in ("unsigned", "tampered"):
        case = clone(profile, contract, "grant_within_window_admitted", f"own-grant-{integrity}")
        case["authorization"]["integrity"] = integrity
        case["expected"] = {"outcomes": [{"outcome": "REFUSED",
                                          "refusal_class": "authority_unverifiable"}],
                            "claim_result": "NOT_ESTABLISHED"}
        rows.append((contract, case))
    return rows


def effect_cases(profile: Path) -> list[tuple[str, dict[str, Any]]]:
    contract = "effect-evidence-v1"
    rows: list[tuple[str, dict[str, Any]]] = []
    for identifier, rule, observed, status in (
        ("own-presence-is-not-value", "present", {"status": None}, "EFFECT_VERIFIED"),
        ("own-absence-field-observed", "absent", {"status": None}, "EFFECT_MISMATCH"),
        ("own-absence-field-missing", "absent", {}, "EFFECT_VERIFIED"),
        ("own-unknown-comparison", "not-a-rule", {"status": "closed"}, "EFFECT_UNSUPPORTED"),
        ("own-hash-contract-undefined", "hash", {"status": "closed"}, "EFFECT_UNSUPPORTED"),
    ):
        case = clone(profile, contract, "verified_declared_delta", identifier)
        case["observed"] = observed
        case["postcondition"]["comparison_rules"] = {"status": rule}
        case["expected"]["effect_status"] = status
        case["expected"]["highest_established_state"] = {
            "EFFECT_VERIFIED": "EFFECT_VERIFIED", "EFFECT_MISMATCH": "DISPATCHED",
            "EFFECT_UNSUPPORTED": "EXECUTION_REPORTED_SUCCESS",
        }[status]
        rows.append((contract, case))
    case = clone(profile, contract, "version_advanced", "own-bool-not-version-counter")
    case["observed"]["version"] = True
    case["expected"]["effect_status"] = "EFFECT_MISMATCH"
    case["expected"]["highest_established_state"] = "DISPATCHED"
    rows.append((contract, case))
    return rows


# Each mutation changes executed source in an isolated copy. The unmodified
# installed reader and frozen source remain the baseline, rather than sharing
# a fault flag with the experiment's expected-answer comparator.
SOURCE_FAULTS = (
    ("skip-authority-integrity", "common.py", "return hmac.compare_digest(expected, "
     "envelope[\"signature\"])", "return True", "exact-call-binding-v1"),
    ("ignore-principal-binding", "binding.py", "if call[\"actor\"] != payload[\"actor\"]:",
     "if False:", "exact-call-binding-v1"),
    ("allow-replay", "binding.py", "spent = True", "spent = False", "exact-call-binding-v1"),
    ("consume-refused-call", "binding.py", "outcomes.append(refusal(reason) if reason else "
     "success(\"DISPATCHED\"))", "outcomes.append(refusal(reason) if reason else "
     "success(\"DISPATCHED\"))\n        spent = True", "exact-call-binding-v1"),
    ("ignore-revocation", "fresh.py", "if authorization[\"kid\"] in revoked:",
     "if False:", "fresh-authority-v1"),
    ("ignore-policy-change", "fresh.py", "fields = (\"policy_bundle\", \"toolspec_hash\", "
     "\"toolspec_version\")", "fields = (\"toolspec_hash\", \"toolspec_version\")",
     "fresh-authority-v1"),
    ("report-alone-verifies-effect", "effects.py", "if status == \"EFFECT_VERIFIED\":",
     "if reported_success:", "effect-evidence-v1"),
    ("collapse-bool-and-number", "common.py", "if isinstance(value, bool):\n        return "
     "[\"boolean\", value]", "if isinstance(value, bool):\n        return [\"number\", value]",
     "effect-evidence-v1"),
)

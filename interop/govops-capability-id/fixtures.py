"""Finite saved-record controls; these keys are public test fixtures only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
AUTHORITY = "fixture:pdp"
KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"probity-govops-id-fixture-v0").digest())
PUBLIC = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
DESCRIPTOR = '{"action":"invoke","resource":{"id":"payment-authorization","type":"tool"}}'
SYNTAX_ID = "sha256:63a9ab0e183e7fc63921e03fc2b957fe6e3de272fa9ae43272e613c387cd895f"
BINDINGS = {
    "subject_id": "fixture:person",
    "runtime_agent_id": "fixture:agent:child",
    "invocation_id": "fixture:call:one",
    "attempt_id": "fixture:attempt:one",
    "target_id": "fixture:target:payments",
}


def wire(value: Any) -> bytes:
    """Serialize the outer test record without touching its raw descriptors."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()


def signed(value: dict[str, Any]) -> dict[str, str]:
    raw = wire(value)
    return {"authority_id": AUTHORITY, "raw": raw.decode(), "signature_hex": KEY.sign(raw).hex()}


def request(id_binding: str = "descriptor-digest") -> dict[str, Any]:
    capability = SYNTAX_ID if id_binding == "descriptor-digest" else "fixture:issued:payments"
    decision = {
        **BINDINGS,
        "decision_id": "fixture:decision:one",
        "authority_id": AUTHORITY,
        "granted": True,
        "id_binding": id_binding,
        "capability_id": capability,
        "descriptor_text": DESCRIPTOR,
    }
    return {
        "route": "decision",
        "catalog_capability_id": "fixture:catalog:pay",
        "decision": signed(decision),
        "invocation": {**BINDINGS, "capability_id": capability, "descriptor_text": DESCRIPTOR},
    }


def case(name: str, value: dict[str, Any] | bytes, verdict: str, reason: str | None = None, **options: Any) -> dict[str, Any]:
    expected: dict[str, Any] = {"verdict": verdict, "target_effect": "not-observed"}
    if reason is not None:
        expected["reason"] = reason
    return {"name": name, "request": value if isinstance(value, bytes) else wire(value), "expected": expected, **options}


def historical_cases() -> list[dict[str, Any]]:
    """Adapt authority context while keeping each historical raw descriptor intact."""
    reasons = {
        "valid": None,
        "duplicate-member": "DuplicateMember",
        "integer-not-ijson-safe": "UnsafeInteger",
        "number-not-integer": "IdNotDerived",
        "invoker-chosen-id": "InvokerChosenId",
        "id-not-derived": "IdNotDerived",
        "descriptor-mismatch": "DescriptorSubstitution",
        "ill-formed-string": "StringNotScalar",
    }
    base = HERE / "history/vectors-capability-id"
    manifest = json.loads((base / "MANIFEST.json").read_text())
    result = []
    for row in manifest["members"]:
        original = json.loads((base / "members" / (row["id"] + ".json")).read_text())
        value = request()
        decision = json.loads(value["decision"]["raw"])
        decision.update(original["decision"])
        value["decision"] = signed(decision)
        value["invocation"].update(original["invocation"])
        reason = reasons[row["expect"]]
        result.append(
            case(
                "history/" + row["id"],
                value,
                "bound" if reason is None else "refused",
                reason,
                historical_expect=row["expect"],
                adaptation="Fixed public test key and explicit record bindings added; original descriptor text and capability ID retained.",
                numeric_policy_difference="Native integers-only accepts integral values; historical checker refuses float spellings."
                if row["id"] == "CAP-R3"
                else None,
            )
        )
    return result


def binding_cases() -> list[dict[str, Any]]:
    result = [case("controls/digest-id", request(), "bound"), case("controls/issuer-assigned-id", request("issuer-assigned"), "bound")]
    for field in BINDINGS:
        value = request()
        value["invocation"][field] = "fixture:other"
        result.append(case("controls/scope-" + field, value, "refused", "BindingMismatch:" + field))
    value = request()
    value["invocation"]["runtime_agent_id"] = value["catalog_capability_id"]
    result.append(case("controls/catalog-is-not-runtime-agent", value, "refused", "BindingMismatch:runtime_agent_id"))
    value = request()
    value["catalog_capability_id"] = "fixture:another-catalog-entry"
    result.append(case("controls/catalog-label-only", value, "bound"))
    value = request("issuer-assigned")
    value["invocation"]["capability_id"] = "fixture:gateway-choice"
    result.append(case("controls/gateway-chosen-opaque-id", value, "refused", "InvokerChosenId"))
    alias = '{"action":"execute","resource":{"id":"payment-authorization","type":"tool"}}'
    alias_id = "sha256:" + hashlib.sha256(alias.encode()).hexdigest()
    value = request()
    value["invocation"]["descriptor_text"] = alias
    value["alias_catalog"] = {SYNTAX_ID: "fixture:semantic:pay", alias_id: "fixture:semantic:pay"}
    row = case("controls/semantic-alias-does-not-rebind-grant", value, "refused", "DescriptorSubstitution")
    row["expected"]["correlation"] = {"syntax_match": False, "semantic_alias_match": True, "alias_source": "caller-supplied-local-catalog"}
    result.append(row)
    return result


def authority_cases() -> list[dict[str, Any]]:
    result = []
    value = request()
    value["decision"]["signature_hex"] = "00" * 64
    result.append(case("controls/invalid-signature", value, "refused", "InvalidDecisionSignature"))
    value = request()
    value["decision"]["raw"] += " "
    result.append(case("controls/signed-raw-bytes-changed", value, "refused", "InvalidDecisionSignature"))
    value = request()
    decision = json.loads(value["decision"]["raw"])
    decision["granted"] = False
    value["decision"] = signed(decision)
    result.append(case("controls/denied-decision", value, "refused", "DecisionNotGranted"))
    for name, options in [
        ("no-trusted-key", {"trust": "none"}),
        ("other-authority", {"expected_authority": "fixture:other"}),
        ("wrong-key", {"trust": "wrong"}),
    ]:
        reason = "InvalidDecisionSignature" if name == "wrong-key" else "UntrustedAuthority"
        result.append(case("controls/" + name, request(), "refused", reason, **options))
    value = request()
    raw = value["decision"]["raw"].replace('"granted":true', '"granted":false,"granted":true').encode()
    value["decision"] = {"authority_id": AUTHORITY, "raw": raw.decode(), "signature_hex": KEY.sign(raw).hex()}
    result.append(case("controls/signed-decision-duplicate", value, "refused", "DuplicateMember"))
    return result


def admission_cases() -> list[dict[str, Any]]:
    samples = [
        ("duplicate", '{"action":"invoke","action":"delete","resource":{}}', "DuplicateMember", {}),
        ("escaped-duplicate", '{"action":"invoke","a\\u0063tion":"delete","resource":{}}', "DuplicateMember", {}),
        ("unsafe-integer", '{"action":"invoke","resource":{"n":9007199254740993}}', "UnsafeInteger", {}),
        ("fractional-value", '{"action":"invoke","resource":{"n":1.5}}', "NonIntegerNumber", {}),
        ("lone-surrogate", '{"action":"invoke","resource":{"id":"\\ud800"}}', "StringNotScalar", {}),
        ("deep", '{"action":"invoke","resource":{"a":[[[]]]}}', "TooDeep", {"max_depth": 3}),
        ("small-cap", DESCRIPTOR, "TooLarge", {"max_bytes": 16}),
        ("scalar", '"invoke"', "DescriptorShape", {}),
    ]
    result = []
    for name, descriptor, reason, options in samples:
        value = request()
        value["route"] = "ingestion"
        value["invocation"]["descriptor_text"] = descriptor
        result.append(case("controls/raw-" + name, value, "refused", reason, **options))
    result.append(case("controls/outer-duplicate", b'{"route":"ingestion","route":"decision"}', "refused", "DuplicateMember"))
    result.append(case("controls/outer-invalid-utf8", b'{"route":"\xff"}', "refused", "StringNotScalar"))
    for name, profile, descriptor in [
        ("integral-float-spelling", "ijson-integers", '{"action":"invoke","resource":{"n":1.0}}'),
        ("rfc-float", "rfc8785", '{"action":"invoke","resource":{"n":1.5}}'),
        ("ijson-float", "ijson", '{"action":"invoke","resource":{"n":1.5}}'),
        ("rfc-large-integer", "rfc8785", '{"action":"invoke","resource":{"n":9007199254740993}}'),
    ]:
        value = request()
        value["route"] = "ingestion"
        value["invocation"]["descriptor_text"] = descriptor
        result.append(case("controls/" + name, value, "correlated", profile=profile))
    return result


def ingestion_cases() -> list[dict[str, Any]]:
    result = []
    for name in ("original", "another-call", "another-agent", "another-target"):
        value = request("issuer-assigned")
        value["route"] = "ingestion"
        value.pop("decision")
        field = {"another-call": "invocation_id", "another-agent": "runtime_agent_id", "another-target": "target_id"}.get(name)
        if field:
            value["invocation"][field] = "fixture:other"
        row = case("controls/ingestion-" + name, value, "correlated")
        row["expected"].update(authority="not-verified", correlation_scope="descriptor-syntax-only")
        result.append(row)
    return result


def cases() -> list[dict[str, Any]]:
    assert "sha256:" + hashlib.sha256(DESCRIPTOR.encode()).hexdigest() == SYNTAX_ID
    return historical_cases() + binding_cases() + authority_cases() + admission_cases() + ingestion_cases()

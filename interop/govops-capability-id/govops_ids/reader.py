"""Keep syntax correlation, authority bindings and target evidence separate."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BINDINGS = ("subject_id", "runtime_agent_id", "invocation_id", "attempt_id", "target_id")


class Refused(Exception):
    """A finite refusal with the stage that produced it."""

    def __init__(self, reason: str, stage: str = "binding") -> None:
        super().__init__(reason)
        self.reason = reason
        self.stage = stage


@dataclass(frozen=True)
class Admitter:
    """Installed raw jcs-admit command, with explicitly bounded options."""

    executable: Path
    profile: str = "ijson-integers"
    max_depth: int = 32
    max_bytes: int = 1048576

    def admit(self, raw: bytes) -> bytes:
        """Admit the original input before any Python value parsing."""
        if len(raw) > self.max_bytes:
            raise Refused("TooLarge", "raw-admission")
        command = [str(self.executable), self.profile, str(self.max_depth), str(self.max_bytes)]
        try:
            result = subprocess.run(command, input=raw, capture_output=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused("AdmitterUnavailable", "raw-admission") from exc
        if result.returncode or result.stderr:
            raise Refused("AdmitterFailed", "raw-admission")
        return _canonical_response(result.stdout)


def _canonical_response(raw: bytes) -> bytes:
    try:
        response = json.loads(raw)
        if not isinstance(response, dict):
            raise ValueError("object required")
        if response.get("status") == "refused" and set(response) == {"status", "error_class"}:
            if isinstance(response["error_class"], str) and response["error_class"]:
                raise Refused(response["error_class"], "raw-admission")
        if response.get("status") != "accepted" or set(response) != {"status", "canonical_hex"}:
            raise ValueError("unexpected admission response")
        canonical = bytes.fromhex(response["canonical_hex"])
        if not canonical:
            raise ValueError("empty canonical output")
        return canonical
    except (TypeError, ValueError, KeyError) as exc:
        raise Refused("AdmitterProtocol", "raw-admission") from exc


def _object(raw: bytes, admitter: Admitter) -> dict[str, Any]:
    canonical = admitter.admit(raw)
    try:
        value = json.loads(canonical)
    except (ValueError, UnicodeError) as exc:
        raise Refused("AdmitterProtocol", "raw-admission") from exc
    if not isinstance(value, dict):
        raise Refused("ObjectRequired", "descriptor")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise Refused("MissingString:" + name, "record")
    return value


def _raw_text(value: Any, name: str) -> bytes:
    try:
        return _text(value, name).encode("utf-8")
    except UnicodeError as exc:
        raise Refused("StringNotScalar", "raw-admission") from exc


def fingerprint(raw: bytes, admitter: Admitter) -> dict[str, Any]:
    """Derive syntax identity; this function grants no authority."""
    canonical = admitter.admit(raw)
    value = json.loads(canonical)
    if not isinstance(value, dict) or not isinstance(value.get("resource"), dict):
        raise Refused("DescriptorShape", "descriptor")
    _text(value.get("action"), "action")
    return {
        "syntax_id": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_hex": canonical.hex(),
        "numeric_profile": admitter.profile,
    }


def _invocation(request: dict[str, Any], admitter: Admitter) -> tuple[dict[str, Any], dict[str, Any]]:
    invocation = request.get("invocation")
    if not isinstance(invocation, dict):
        raise Refused("InvocationRequired", "record")
    for field in BINDINGS:
        _text(invocation.get(field), field)
    _text(invocation.get("capability_id"), "capability_id")
    descriptor = fingerprint(_raw_text(invocation.get("descriptor_text"), "descriptor_text"), admitter)
    return invocation, descriptor


def _decision(
    request: dict[str, Any], admitter: Admitter, trusted_keys: Mapping[str, bytes], expected_authority: str | None
) -> tuple[dict[str, Any], dict[str, Any], str]:
    envelope = request.get("decision")
    if not isinstance(envelope, dict):
        raise Refused("DecisionRequired", "authority")
    authority = _text(envelope.get("authority_id"), "authority_id")
    if expected_authority is None or authority != expected_authority or authority not in trusted_keys:
        raise Refused("UntrustedAuthority", "authority")
    raw = _raw_text(envelope.get("raw"), "decision.raw")
    try:
        signature = bytes.fromhex(_text(envelope.get("signature_hex"), "signature_hex"))
        Ed25519PublicKey.from_public_bytes(trusted_keys[authority]).verify(signature, raw)
    except (ValueError, InvalidSignature) as exc:
        raise Refused("InvalidDecisionSignature", "authority") from exc
    decision = _object(raw, admitter)
    if decision.get("authority_id") != authority or decision.get("granted") is not True:
        raise Refused("DecisionNotGranted", "authority")
    _text(decision.get("decision_id"), "decision_id")
    descriptor = fingerprint(_raw_text(decision.get("descriptor_text"), "decision.descriptor_text"), admitter)
    return decision, descriptor, authority


def _aliases(catalog: Any, left: str, right: str) -> bool | None:
    if not isinstance(catalog, dict):
        return None
    label = catalog.get(left)
    other = catalog.get(right)
    if not isinstance(label, str) or not label or not isinstance(other, str) or not other:
        return None
    return label == other


def _binding(decision: dict[str, Any], invocation: dict[str, Any], left: dict[str, Any], right: dict[str, Any]) -> None:
    binding = decision.get("id_binding")
    capability = _text(decision.get("capability_id"), "decision.capability_id")
    if binding not in ("descriptor-digest", "issuer-assigned"):
        raise Refused("UnknownIdBinding")
    if binding == "descriptor-digest" and capability != left["syntax_id"]:
        raise Refused("IdNotDerived")
    if invocation["capability_id"] != capability:
        raise Refused("InvokerChosenId")
    if left["syntax_id"] != right["syntax_id"]:
        raise Refused("DescriptorSubstitution")
    for field in BINDINGS:
        if _text(decision.get(field), "decision." + field) != invocation[field]:
            raise Refused("BindingMismatch:" + field)


def _read(request: dict[str, Any], admitter: Admitter, trusted_keys: Mapping[str, bytes], expected_authority: str | None) -> dict[str, Any]:
    invocation, descriptor = _invocation(request, admitter)
    result: dict[str, Any] = {
        "route": request.get("route"),
        "descriptor": descriptor,
        "identities": {field: invocation[field] for field in BINDINGS},
        "catalog_capability_id": request.get("catalog_capability_id"),
        "reported_capability_id": invocation["capability_id"],
        "target_effect": "not-observed",
    }
    if request.get("route") == "ingestion":
        result.update(verdict="correlated", authority="not-verified", correlation_scope="descriptor-syntax-only")
        return result
    if request.get("route") != "decision":
        raise Refused("UnknownRoute", "record")
    decision, granted_descriptor, authority = _decision(request, admitter, trusted_keys, expected_authority)
    result.update(authority="signature-verified", decision_id=decision["decision_id"], authority_id=authority)
    result["correlation"] = {
        "syntax_match": granted_descriptor["syntax_id"] == descriptor["syntax_id"],
        "semantic_alias_match": _aliases(request.get("alias_catalog"), granted_descriptor["syntax_id"], descriptor["syntax_id"]),
        "alias_source": "caller-supplied-local-catalog",
    }
    try:
        _binding(decision, invocation, granted_descriptor, descriptor)
    except Refused as exc:
        result.update(verdict="refused", reason=exc.reason, stage=exc.stage)
        return result
    result.update(verdict="bound", correlation_scope="signed-record-bindings", id_binding=decision["id_binding"])
    return result


def evaluate(
    raw: bytes, admitter: Admitter, trusted_keys: Mapping[str, bytes] | None = None, expected_authority: str | None = None
) -> dict[str, Any]:
    """Judge saved records with trust selected outside the untrusted input."""
    try:
        return _read(_object(raw, admitter), admitter, trusted_keys or {}, expected_authority)
    except Refused as exc:
        return {
            "verdict": "refused",
            "reason": exc.reason,
            "stage": exc.stage,
            "authority": "not-verified",
            "target_effect": "not-observed",
        }

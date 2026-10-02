"""Read a bounded AgentID attestation profile from retained bytes, offline.

The reader recomputes evidence relationships. It does not resolve production
identity, revocation, freshness, policy sufficiency or execution. Input errors
raise ``InputError`` and log the same bounded message without input contents.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import struct
from datetime import UTC, datetime
from typing import Any, NoReturn

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

LOG = logging.getLogger(__name__)
MAX_BYTES = 65536
MAX_DEPTH = 32
MAX_NODES = 4096
MAX_KEYS = 32
SAFE_INTEGER = 2**53 - 1
PROFILE = "probity.agentid-offline.v0.1"
UNESTABLISHED = [
    "production_identity",
    "historical_revocation",
    "current_key_control",
    "freshness",
    "policy_sufficiency",
    "execution",
    "independent_custody",
    "action_tuple_uniqueness",
]
REQUEST_FIELDS = ["subject_did", "amount_usd", "charge_ref", "nonce"]
ACTION_FIELDS = ["agent_id", "action_type", "scope", "issued_at"]


class InputError(ValueError):
    """A malformed, ambiguous or unsupported input has no successful reading."""


def refuse(message: str) -> NoReturn:
    """Log a bounded diagnostic and raise InputError with the identical text."""
    LOG.warning(message)
    raise InputError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Construct a JSON object, rejecting duplicate names at every nesting level."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate JSON object member")
        result[key] = value
    return result


def children(value: Any) -> list[Any]:
    """Return nested values, including object keys for Unicode validation."""
    if isinstance(value, dict):
        return list(value) + list(value.values())
    return value if isinstance(value, list) else []


def scalar(value: Any) -> None:
    """Reject floats, non-finite numbers, unsafe integers and invalid Unicode."""
    if type(value) is float:
        refuse("floating-point values are outside this profile")
    if type(value) is int and abs(value) > SAFE_INTEGER:
        refuse("integer is outside the safe range")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            refuse("invalid Unicode scalar")


def domain(value: Any) -> None:
    """Enforce an iterative depth/node budget before RFC 8785 serialization.

    Parameters
    ----------
    value : object
        Parsed JSON. This optional profile supports safe integers, booleans,
        nulls, Unicode strings, arrays and objects; floating point is excluded.

    Raises
    ------
    InputError
        If a scalar or the depth/node budget falls outside the profile.
    """
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            refuse("JSON resource budget exceeded")
        scalar(item)
        pending.extend((child, depth + 1) for child in children(item))


def load_json(payload: bytes) -> dict[str, Any]:
    """Parse at most 64 KiB of strict UTF-8 object JSON with unique members.

    The same parser reads the attestation, request, JWKS and protected header.
    Duplicate keys are refused before canonicalization instead of silently
    choosing the first or last occurrence. UTF-8 BOMs are outside this profile.
    """
    if len(payload) > MAX_BYTES:
        refuse("JSON byte budget exceeded")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, InputError):
            raise
        refuse("malformed JSON input")
    if not isinstance(value, dict):
        refuse("JSON root must be an object")
    domain(value)
    return value


def object_field(value: dict[str, Any], field: str) -> dict[str, Any]:
    """Require an object member with a stable diagnostic naming only its field."""
    item = value.get(field)
    if not isinstance(item, dict):
        refuse(f"required object: {field}")
    return item


def text_field(value: dict[str, Any], field: str) -> str:
    """Require a nonempty string without writing its potentially sensitive value."""
    item = value.get(field)
    if not isinstance(item, str) or not item:
        refuse(f"required string: {field}")
    return item


def canonical(value: Any) -> bytes:
    """Return RFC 8785 bytes after enforcing the bounded numeric/resource domain."""
    domain(value)
    return rfc8785.dumps(value)


def digest(value: Any) -> str:
    """Return the lowercase SHA-256 of canonical(value), with no producer imports."""
    return hashlib.sha256(canonical(value)).hexdigest()


def decode64(value: str) -> bytes:
    """Decode canonical unpadded base64url, refusing padding and alternate pad bits."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        refuse("invalid base64url encoding")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError:
        refuse("invalid base64url encoding")
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        refuse("noncanonical base64url encoding")
    return decoded


def split_jws(value: str) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    """Parse this profile's compact EdDSA JWS with exactly alg, typ and kid.

    General JOSE processing, detached payloads, critical extensions and b64=false
    are outside this profile. Unknown header members fail closed rather than
    being accepted with unexamined semantics. Unknown payload members remain
    covered by the core digest and signed-payload equality comparison.
    """
    parts = value.split(".")
    if len(parts) != 3:
        refuse("compact JWS must have three segments")
    header = load_json(decode64(parts[0]))
    if set(header) != {"alg", "typ", "kid"}:
        refuse("unsupported protected header members")
    if header["alg"] != "EdDSA" or header["typ"] != "VerifierAttestation":
        refuse("unsupported protected header algorithm or type")
    text_field(header, "kid")
    signature = decode64(parts[2])
    if len(signature) != 64:
        refuse("Ed25519 signature must be 64 bytes")
    return header, decode64(parts[1]), f"{parts[0]}.{parts[1]}".encode("ascii"), signature


def select_key(jwks: dict[str, Any], kid: str) -> bytes:
    """Select exactly one public Ed25519 verification key from at most 32 entries.

    Duplicate identifiers anywhere in the JWKS are ambiguous and refused.
    Selection never follows a payload URL or a JWS-supplied key. The caller's
    retained JWKS is a declared trust input, not authenticated identity evidence.
    """
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_KEYS:
        refuse("JWKS must contain between 1 and 32 keys")
    if not all(isinstance(key, dict) for key in keys):
        refuse("JWKS key must be an object")
    identifiers = [text_field(key, "kid") for key in keys]
    if len(set(identifiers)) != len(identifiers):
        refuse("duplicate JWKS kid")
    if kid not in identifiers:
        refuse("signing kid is absent from retained JWKS")
    return key_material(keys[identifiers.index(kid)])


def key_material(key: dict[str, Any]) -> bytes:
    """Validate the selected key's declared purpose, public-only form and width."""
    expected = {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig"}
    if any(key.get(field) != value for field, value in expected.items()):
        refuse("unsupported JWKS key parameters")
    if "d" in key or key.get("key_ops", ["verify"]) != ["verify"]:
        refuse("JWKS key is not public verification-only material")
    public = decode64(text_field(key, "x"))
    if len(public) != 32:
        refuse("Ed25519 public key must be 32 bytes")
    return public


def verify_signature(public: bytes, message: bytes, signature: bytes) -> bool:
    """Check signature consistency under the supplied key without promoting trust."""
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except InvalidSignature:
        return False
    return True


def timestamp_ms(value: str) -> int:
    """Parse the fixture's UTC timestamp with exactly millisecond precision.

    This reproduces the signed action-reference input; it is not a freshness or
    expiry decision. Integer arithmetic avoids floating-point timestamp rounding.
    """
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        refuse("issued_at must be UTC with millisecond precision")
    try:
        delta = datetime.fromisoformat(value.replace("Z", "+00:00")) - datetime(
            1970, 1, 1, tzinfo=UTC
        )
    except ValueError:
        refuse("issued_at is not a valid timestamp")
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000


def bound_request(att: dict[str, Any], request: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Build the signed binding preimage and compare it to the caller's request.

    Both self-consistency and the request comparison are reported separately.
    Equality covers subject_did, amount_usd, charge_ref and nonce; action_type
    and scope are additionally consumed by action_reference.
    """
    binding = object_field(att, "binding")
    subject = object_field(att, "subject")
    for value in (binding, request):
        text_field(value, "charge_ref")
        text_field(value, "nonce")
        if type(value.get("amount_usd")) is not int:
            refuse("amount_usd must be a safe integer")
    preimage = {field: binding[field] for field in ("amount_usd", "charge_ref", "nonce")}
    preimage["subject_did"] = text_field(subject, "did")
    text_field(request, "subject_did")
    return preimage, all(request[field] == value for field, value in preimage.items())


def action_reference(att: dict[str, Any], request: dict[str, Any]) -> str:
    """Recompute the producer's raw-concatenation action-ref-v1 construction.

    This preserves the specified construction; it does not claim the concatenated
    strings uniquely encode all possible tuples. The result is tied to the exact
    supplied request and issued_at, without proving execution or policy validity.
    """
    subject = object_field(att, "subject")
    fields = (
        text_field(subject, "agent_id"),
        text_field(request, "action_type"),
        text_field(request, "scope"),
    )
    milliseconds = timestamp_ms(text_field(att, "issued_at"))
    message = b"".join(value.encode("utf-8") for value in fields) + struct.pack(">q", milliseconds)
    return hashlib.sha256(message).hexdigest()


def evaluate(attestation: bytes, request_bytes: bytes, jwks_bytes: bytes) -> dict[str, Any]:
    """Evaluate eight bounded relationships over three immutable byte inputs.

    Parameters
    ----------
    attestation, request_bytes, jwks_bytes : bytes
        UTF-8 JSON bytes. Every input is parsed by load_json; no network is used.

    Returns
    -------
    dict[str, object]
        Per-claim established/contradicted results, input SHA-256 digests and
        explicit unestablished trust/execution claims. All comparisons passing
        means byte/signature consistency with the supplied request and key only.

    Raises
    ------
    InputError
        If required fields, encoding, algorithm, key selection or bounded resource
        conditions are unsupported or ambiguous. Such inputs have no pass result.
    """
    att, request, jwks = map(load_json, (attestation, request_bytes, jwks_bytes))
    if (
        att.get("type") != "VerifierAttestation"
        or att.get("spec") != "ctef-verifier-attestation/v0.1"
    ):
        refuse("unsupported attestation profile")
    verifier = object_field(att, "verifier")
    binding = object_field(att, "binding")
    core = {key: value for key, value in att.items() if key not in ("digest", "jws")}
    header, payload, signed, signature = split_jws(text_field(att, "jws"))
    public = select_key(jwks, header["kid"])
    binding_input, matches_request = bound_request(att, request)
    reference = {
        "kid": text_field(verifier, "kid"),
        "verifier": text_field(verifier, "id"),
        "subject_did": binding_input["subject_did"],
    }
    checks = {
        "core_digest": digest(core) == text_field(att, "digest"),
        "signed_payload_equals_core": payload == canonical(core),
        "signature_under_retained_key": verify_signature(public, signed, signature),
        "header_kid_matches_signed_verifier": header["kid"] == verifier["kid"],
        "binding_digest": digest(binding_input) == text_field(binding, "binding_digest"),
        "request_binding_matches": matches_request,
        "action_ref": action_reference(att, request) == text_field(binding, "action_ref"),
        "attestation_ref": digest(reference) == text_field(att, "attestation_ref"),
    }
    return {
        "profile": PROFILE,
        "claims": {name: "established" if ok else "contradicted" for name, ok in checks.items()},
        "all_comparisons_match": all(checks.values()),
        "input_sha256": dict(
            zip(
                ("attestation", "request", "jwks"),
                map(
                    lambda data: hashlib.sha256(data).hexdigest(),
                    (attestation, request_bytes, jwks_bytes),
                ),
                strict=True,
            )
        ),
        "not_established": UNESTABLISHED.copy(),
        "request_binding_fields": REQUEST_FIELDS.copy(),
        "action_reference_fields": ACTION_FIELDS.copy(),
        "formal_pack_3": "not_run",
    }

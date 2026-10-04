"""Read a selected AgentAvow signed tool map into a named-definition pin.

The extraction candidate keeps the historical literal-name reader unchanged.
Cryptographic verification, payload canonicality, issuer, server, named-tool
binding and reference-time validity are evaluated independently. No key URL is
fetched, and a definition match establishes no runtime action authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))
sys.path.insert(0, str(ROOT.parent / "agentavow-live-mcp"))
from definition_pin import InvalidInput, definition_digest  # noqa: E402

LOGGER = logging.getLogger(__name__)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class InputError(ValueError):
    """A selected input cannot be evaluated safely by this bounded reader."""


def refuse(message: str) -> NoReturn:
    """Log a stable refusal and raise :class:`InputError`."""
    LOGGER.warning(message)
    raise InputError(message)


def name_bytes(name: object) -> bytes:
    """Encode a nonempty tool name as scalar Unicode UTF-8, without normalization."""
    if not isinstance(name, str) or not name:
        refuse("tool name must be a nonempty string")
    try:
        return name.encode("utf-8")
    except UnicodeEncodeError:
        refuse("tool name contains an invalid Unicode scalar")


def encode_octet(value: int) -> str:
    """Encode one octet using the issuer's printable-ASCII exception rule."""
    return chr(value) if 0x21 <= value <= 0x7E and value not in (0x25, 0x3D) else f"%{value:02X}"


def tool_key(name: object) -> str:
    """Compute the pinned version-1 signed-map lookup key for an exact name.

    Parameters
    ----------
    name : str
        Raw served MCP tool name. Normalization and percent decoding are absent.

    Returns
    -------
    str
        ``tool:`` plus the percent-encoded name. If the body exceeds 128 ASCII
        characters, retain its first 96, a tilde, and the first 16 lowercase
        hex digits of SHA-256 over the complete raw UTF-8 name. A cut inside a
        percent triplet is deliberately retained, matching the source profile.

    Notes
    -----
    The truncated suffix provides 64 bits of hash identity. It does not prove
    mathematical injectivity. :func:`capture_digest` refuses observed name/key
    ambiguity before an extracted pin can be consumed.
    """
    raw = name_bytes(name)
    body = "".join(encode_octet(value) for value in raw)
    if len(body) > 128:
        body = body[:96] + "~" + hashlib.sha256(raw).hexdigest()[:16]
    return "tool:" + body


def encode_base64url(raw: bytes) -> str:
    """Return canonical unpadded JOSE text."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_base64url(value: str) -> bytes:
    """Decode only nonempty canonical unpadded JOSE text."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        refuse("invalid base64url encoding")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        refuse("invalid base64url encoding")
    if encode_base64url(raw) != value:
        refuse("invalid base64url encoding")
    return raw


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Parse an object without collapsing duplicate members at any depth."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate JSON member")
        result[key] = value
    return result


def load_json(raw: bytes) -> dict[str, Any]:
    """Read one JSON object with duplicate and encoding refusals."""
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse("invalid JSON encoding")
    if not isinstance(value, dict):
        refuse("JSON root must be an object")
    return value


def canonicalize(value: dict[str, Any]) -> bytes:
    """Produce RFC 8785 bytes, refusing values outside its input domain."""
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, TypeError):
        refuse("payload is outside the RFC 8785 input domain")


def selected_key(header: dict[str, Any], jwk: dict[str, Any]) -> bytes:
    """Check pinned key/header selection and decode the exact Ed25519 key bytes.

    A key without a nonempty identifier cannot match an omitted header member.
    Critical extensions and unencoded payload modes are outside this profile.
    """
    if not isinstance(jwk, dict) or (jwk.get("kty"), jwk.get("crv"), jwk.get("alg")) != (
        "OKP",
        "Ed25519",
        "EdDSA",
    ):
        refuse("unsupported pinned public key")
    if not isinstance(jwk.get("kid"), str) or not jwk["kid"]:
        refuse("pinned key must have a nonempty kid")
    if header.get("alg") != "EdDSA" or header.get("kid") != jwk["kid"]:
        refuse("JWS algorithm or kid differs from the pinned key")
    if "crit" in header or "b64" in header:
        refuse("unsupported JOSE header extension")
    return decode_base64url(jwk.get("x", ""))


def read_jws(jws: str, jwk: dict[str, Any]) -> tuple[dict[str, Any], bool, bool]:
    """Verify compact Ed25519 JWS under a caller-selected public test key.

    Parameters
    ----------
    jws : str
        Three canonical unpadded base64url segments. Payload bytes are retained.
    jwk : dict[str, Any]
        Pinned OKP/Ed25519/EdDSA public key with its selected kid. Embedded key
        hints and URLs do not establish authority and are never fetched.

    Returns
    -------
    tuple[dict[str, Any], bool, bool]
        Parsed payload, signature-valid axis and canonical-bytes axis. Invalid
        cryptographic signatures remain observable as False; malformed inputs
        raise :class:`InputError` rather than being silently repaired.
    """
    if not isinstance(jws, str) or len(jws.split(".")) != 3:
        refuse("compact JWS must contain three segments")
    header_text, payload_text, signature_text = jws.split(".")
    header = load_json(decode_base64url(header_text))
    raw_key = selected_key(header, jwk)
    signature = decode_base64url(signature_text)
    if len(raw_key) != 32 or len(signature) != 64:
        refuse("Ed25519 key or signature length differs")
    raw_payload = decode_base64url(payload_text)
    payload = load_json(raw_payload)
    valid = verify_ed25519(raw_key, signature, (header_text + "." + payload_text).encode())
    return payload, valid, canonicalize(payload) == raw_payload


def verify_ed25519(key: bytes, signature: bytes, message: bytes) -> bool:
    """Return the signature axis without inheriting any payload or trust axis."""
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


def timestamp(value: object) -> datetime:
    """Parse a timezone-aware ISO reference instant, retaining its offset."""
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value
    ):
        refuse("timestamp must be an ISO instant with a timezone")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        refuse("timestamp must be an ISO instant with a timezone")


def signed_map(payload: dict[str, Any]) -> dict[str, str]:
    """Require a well-shaped signed tool-digest map before selecting one entry."""
    scan = payload.get("scan")
    if not isinstance(scan, dict) or not isinstance(scan.get("toolDigests"), dict):
        refuse("signed payload must contain a tool digest map")
    mapping = scan["toolDigests"]
    for key, digest in mapping.items():
        if not isinstance(key, str) or not key.startswith("tool:"):
            refuse("signed tool digest map has an invalid key")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            refuse("signed tool digest map has an invalid digest")
    return mapping


def bound_id(payload: dict[str, Any], field: str) -> str:
    """Read a required signed issuer or server identity without coercion."""
    obj = payload.get(field)
    if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
        refuse(f"signed {field} must contain an id")
    return obj["id"]


def evaluate(jws: str, jwk: dict[str, Any], issuer: str, gate: dict[str, str]) -> dict:
    """Evaluate the six native axes plus caller-selected issuer identity.

    Parameters
    ----------
    jws, jwk : str, dict[str, Any]
        See :func:`read_jws`; the key is selected outside the producer packet.
    issuer : str
        Caller-selected issuer id. Matching a key and id is this finite policy,
        not network DID resolution or proof of production key authorization.
    gate : dict[str, str]
        Exact subject_id, tool_name, observed_tool_digest and evaluation_time.

    Returns
    -------
    dict
        Separate signature, canonical, issuer, subject, tool, digest and window
        axes; rely is their conjunction. An absent named-tool entry leaves the
        digest axis ``not_evaluated``. No axis establishes runtime behavior.
    """
    if not isinstance(issuer, str) or not issuer:
        refuse("selected issuer must be a nonempty string")
    if not isinstance(gate, dict) or set(gate) != {
        "subject_id",
        "tool_name",
        "observed_tool_digest",
        "evaluation_time",
    }:
        refuse("gate fields differ from the candidate contract")
    observed = gate["observed_tool_digest"]
    if not isinstance(observed, str) or not DIGEST.fullmatch(observed):
        refuse("observed tool digest is malformed")
    payload, signature_valid, canonical_bytes = read_jws(jws, jwk)
    mapping = signed_map(payload)
    key = tool_key(gate["tool_name"])
    issued, expires = timestamp(payload.get("issuedAt")), timestamp(payload.get("expiresAt"))
    if issued >= expires:
        refuse("signed validity window is empty or reversed")
    reference = timestamp(gate["evaluation_time"])
    axes = {
        "signature_valid": signature_valid,
        "canonical_bytes": canonical_bytes,
        "issuer_binds": bound_id(payload, "issuer") == issuer,
        "subject_binds": bound_id(payload, "subject") == gate["subject_id"],
        "tool_binds": key in mapping,
        "tool_digest_binds": mapping[key] == observed if key in mapping else "not_evaluated",
        "fresh": issued <= reference < expires,
    }
    return {**axes, "rely": all(value is True for value in axes.values())}


def extract_pin(jws: str, jwk: dict[str, Any], issuer: str, gate: dict[str, str]) -> dict[str, str]:
    """Emit the historical reader's pin shape only after all selected axes pass.

    The endpoint is the selected MCP subject's suffix. The exact name selects
    its encoded signed-map entry; no literal-name fallback or map-key decoding
    occurs. The resulting digest pin authorizes no invocation by itself.
    """
    result = evaluate(jws, jwk, issuer, gate)
    if not result["rely"]:
        refuse("signed map cannot supply a usable definition pin")
    subject = gate["subject_id"]
    if not subject.startswith("mcp:https://"):
        refuse("selected subject must be an HTTPS MCP endpoint")
    return {
        "endpoint": subject[4:],
        "toolName": gate["tool_name"],
        "toolDigest": gate["observed_tool_digest"],
    }


def capture_digest(tools: list[dict[str, Any]], name: str) -> str:
    """Select one served definition, refusing duplicate names and key collisions.

    This bounded check only establishes uniqueness in the supplied tools/list
    capture. It makes no completeness claim about unseen definitions or a
    signed truncated key's full original name. Definition fields are hashed
    by the unchanged version-1 reader, including its bounded numeric domain.
    """
    if not isinstance(tools, list) or any(not isinstance(tool, dict) for tool in tools):
        refuse("tools/list must be an array of objects")
    names = [tool.get("name") for tool in tools]
    keys = [tool_key(item) for item in names]
    if len(set(keys)) != len(keys):
        refuse("tools/list has ambiguous names or encoded keys")
    selected = [tool for tool in tools if tool.get("name") == name]
    if len(selected) != 1:
        refuse("selected tool is absent from tools/list")
    try:
        return definition_digest(selected[0])
    except InvalidInput:
        refuse("served definition is outside the bounded digest profile")

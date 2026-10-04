"""Independent, bounded JEP Core 0.7 validation and test-only production."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

LOGGER = logging.getLogger(__name__)
PROFILE = "jep-core-0.7"
SIGNATURE_CLASS = "JEP-Baseline-Ed25519-JWS-JCS-0.7"
CHECK_NAMES = (
    "syntax",
    "cryptographic",
    "event_identity",
    "extension_processing",
    "reference_integrity",
    "actor_binding",
    "freshness",
    "audience",
    "chain_integrity",
    "policy",
)


class ValidationError(ValueError):
    """A bounded failure with a stable check and JEP error code."""

    def __init__(self, check: str, code: str, message: str) -> None:
        super().__init__(message)
        self.check = check
        self.code = code


def _members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate members at every JSON object depth."""
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("syntax", "ERR_DUPLICATE_MEMBER", f"duplicate member: {key}")
        value[key] = item
    return value


def parse(raw: str) -> dict[str, Any]:
    """Parse the delivered JSON without normalizing ambiguous input first."""
    value = json.loads(raw, object_pairs_hook=_members, parse_constant=_nonfinite)
    if not isinstance(value, dict):
        raise ValidationError("syntax", "ERR_INVALID_EVENT", "event must be an object")
    return value


def _nonfinite(value: str) -> Any:
    """Refuse JSON extensions that have no interoperable canonical form."""
    raise ValidationError("syntax", "ERR_INVALID_EVENT", f"non-finite JSON number: {value}")


def _require(condition: bool, code: str, message: str, check: str = "syntax") -> None:
    """Raise a named validation failure without coercing missing evidence."""
    if not condition:
        raise ValidationError(check, code, message)


def syntax(event: dict[str, Any]) -> None:
    """Check Core fields and verb-specific obligations for the selected baseline."""
    required = {"jep", "id", "verb", "who", "when", "what", "sig"}
    _require(required <= event.keys(), "ERR_MISSING_FIELD", "missing required Core field")
    _require(event["jep"] == "1", "ERR_UNSUPPORTED_VERSION", "unsupported wire major")
    identifier = event["id"]
    _require(
        isinstance(identifier, str) and bool(identifier) and identifier.isascii(),
        "ERR_INVALID_EVENT_ID",
        "id must be a nonempty ASCII string",
    )
    _require(event["verb"] in ("J", "D", "T", "V"), "ERR_INVALID_VERB", "unsupported verb")
    _require(
        isinstance(event["who"], str) and bool(event["who"]),
        "ERR_INVALID_ACTOR",
        "who must be a nonempty string",
    )
    _require(
        type(event["when"]) is int and event["when"] >= 0,
        "ERR_INVALID_TIMESTAMP",
        "when must be a nonnegative integer",
    )
    _verb_syntax(event)
    _extension_syntax(event)
    _require(isinstance(event["sig"], str), "ERR_SIGNATURE_INVALID", "sig must be a string")


def _verb_syntax(event: dict[str, Any]) -> None:
    """Keep D, T and V's required claim fields separate from domain semantics."""
    fields = {
        "J": (),
        "D": ("delegatee", "scope"),
        "T": ("termination_scope",),
        "V": ("verification_scope", "result"),
    }[event["verb"]]
    if fields:
        _require(
            isinstance(event["what"], dict) and set(fields) <= event["what"].keys(),
            "ERR_MISSING_FIELD",
            "missing verb-specific Core field",
        )
    if event["verb"] in ("T", "V"):
        _require(
            "ref" in event and isinstance(event["ref"], (str, dict, list)),
            "ERR_MISSING_FIELD",
            "T and V require a reference",
        )


def _extension_syntax(event: dict[str, Any]) -> None:
    """Require a well-formed extension map and explicit critical identifiers."""
    _require(isinstance(event.get("ext", {}), dict), "ERR_INVALID_EVENT", "ext must be an object")
    critical = event.get("ext_crit", [])
    _require(isinstance(critical, list), "ERR_INVALID_EVENT", "ext_crit must be a list")
    _require(
        all(isinstance(item, str) and item for item in critical),
        "ERR_INVALID_EVENT",
        "critical identifiers must be nonempty strings",
    )


def encode64(raw: bytes) -> str:
    """Return the unpadded base64url spelling used by the baseline JWS."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode64(value: str) -> bytes:
    """Refuse padding, noncanonical bits and non-base64url characters."""
    _require(
        bool(re.fullmatch(r"[A-Za-z0-9_-]+", value)),
        "ERR_SIGNATURE_INVALID",
        "invalid base64url segment",
        "cryptographic",
    )
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    _require(
        encode64(raw) == value,
        "ERR_SIGNATURE_INVALID",
        "noncanonical base64url segment",
        "cryptographic",
    )
    return raw


def unsigned(event: dict[str, Any]) -> bytes:
    """Canonicalize all received members except sig; never use a typed projection."""
    return rfc8785.dumps({key: item for key, item in event.items() if key != "sig"})


def _header(event: dict[str, Any]) -> tuple[dict[str, Any], str, bytes]:
    """Parse a detached JWS and preserve its exact protected-header segment."""
    parts = event["sig"].split(".")
    _require(
        len(parts) == 3 and parts[1] == "",
        "ERR_SIGNATURE_INVALID",
        "sig must be detached compact JWS",
        "cryptographic",
    )
    header = parse(decode64(parts[0]).decode())
    _require(
        header.get("alg") == "Ed25519",
        "ERR_UNSUPPORTED_ALGORITHM",
        "baseline requires alg Ed25519",
        "cryptographic",
    )
    _require(
        header.get("b64", True) is True and not header.get("crit"),
        "ERR_SIGNATURE_INVALID",
        "unsupported protected-header processing",
        "cryptographic",
    )
    signature = decode64(parts[2])
    _require(
        len(signature) == 64,
        "ERR_SIGNATURE_INVALID",
        "Ed25519 signature must be 64 bytes",
        "cryptographic",
    )
    return header, parts[0], signature


def _public_key(header: dict[str, Any], keys: dict[str, Any]) -> Ed25519PublicKey | None:
    """Resolve only the caller's explicit local test trust store."""
    kid = header.get("kid")
    key = keys.get(kid) if isinstance(kid, str) else None
    if key is None:
        return None
    _require(
        isinstance(key, dict) and key.get("kty") == "OKP" and key.get("crv") == "Ed25519",
        "ERR_SIGNATURE_INVALID",
        "key type disagrees with baseline",
        "cryptographic",
    )
    return Ed25519PublicKey.from_public_bytes(decode64(key["x"]))


def validate(raw: str, keys: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return measured checks and the verified event, without claiming external truth.

    Parameters
    ----------
    raw : str
        Original UTF-8 fixture text. Duplicate members remain detectable.
    keys : dict of str to Any
        Independently selected public test keys indexed by protected kid.

    Returns
    -------
    tuple
        Structured Core result and verified event, or None after a failed or
        indeterminate required check. Archival event_identity covers the pair's
        syntax; global uniqueness is not established without acceptance state.
    """
    result: dict[str, Any] = {
        "status": "invalid",
        "mode": "archival",
        "profile": PROFILE,
        "checks": {name: "not_checked" for name in CHECK_NAMES},
    }
    try:
        event = parse(raw)
        syntax(event)
        result["checks"]["syntax"] = "pass"
        return _verify_event(event, keys, result)
    except ValidationError as error:
        return _failure(result, error.check, error.code, str(error)), None
    except (ValueError, TypeError, KeyError, UnicodeError) as error:
        check = "syntax" if result["checks"]["syntax"] != "pass" else "cryptographic"
        return _failure(result, check, "ERR_INVALID_EVENT", str(error)), None


def _verify_event(
    event: dict[str, Any], keys: dict[str, Any], result: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Verify signature before processing identity or unknown critical extensions."""
    header, protected, signature = _header(event)
    key = _public_key(header, keys)
    if key is None:
        result["status"] = "indeterminate"
        result["checks"]["cryptographic"] = "indeterminate"
        result["errors"] = [{"code": "ERR_KEY_UNRESOLVED", "message": "test key unavailable"}]
        return result, None
    try:
        key.verify(signature, (protected + "." + encode64(unsigned(event))).encode())
    except InvalidSignature:
        return _failure(
            result, "cryptographic", "ERR_SIGNATURE_INVALID", "signature does not verify"
        ), None
    result["checks"]["cryptographic"] = "pass"
    result["event_identity"] = {"who": event["who"], "id": event["id"]}
    result["event_hash"] = "sha256:" + hashlib.sha256(rfc8785.dumps(event)).hexdigest()
    result["checks"]["event_identity"] = "pass"
    if event.get("ext_crit"):
        return _failure(
            result,
            "extension_processing",
            "ERR_UNKNOWN_CRITICAL_EXTENSION",
            "no optional critical extensions are implemented",
        ), None
    result["checks"]["extension_processing"] = "pass"
    result["status"] = "valid"
    return result, event


def _failure(result: dict[str, Any], check: str, code: str, message: str) -> dict[str, Any]:
    """Record a refused required check and log its stable reason."""
    result["status"] = "invalid"
    result["checks"][check] = "fail"
    result["errors"] = [{"code": code, "check": check, "message": message}]
    LOGGER.info("JEP refusal %s: %s", code, message)
    return result


def produce(template: dict[str, Any]) -> dict[str, Any]:
    """Sign a pinned template with a disclosed test key; grant no actor authority."""
    event = dict(template)
    event.pop("sig", None)
    kid = "probity-test-producer"
    seed = hashlib.sha256(b"Probity JEP Core 0.7 test-only producer key").digest()
    key = Ed25519PrivateKey.from_private_bytes(seed)
    protected = encode64(json.dumps({"alg": "Ed25519", "kid": kid}, separators=(",", ":")).encode())
    payload = protected + "." + encode64(unsigned(event))
    event["sig"] = protected + ".." + encode64(key.sign(payload.encode()))
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": encode64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
    }
    return {"event_json": json.dumps(event, ensure_ascii=False), "keys": {kid: jwk}}

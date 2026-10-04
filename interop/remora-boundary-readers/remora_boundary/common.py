"""Raw JSON admission, typed content and test-only authorization integrity."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from datetime import UTC, datetime, timedelta
from typing import Any

TEST_KEY = b"probity-remora-fixture-key-not-for-live-authorization"
MAX_INPUT_BYTES = 1_048_576


class InputError(ValueError):
    """The input cannot support a property verdict."""


def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON key")
        result[key] = value
    return result


def invalid_constant(value: str) -> None:
    raise InputError(f"non-JSON number: {value}")


def load_raw(raw: bytes) -> Any:
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError("input exceeds the raw byte budget")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                           parse_constant=invalid_constant)
        content(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError("invalid UTF-8 JSON") from exc


def content(value: Any) -> Any:
    """JSON kinds differ; member order does not. Numeric values share one kind."""
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["boolean", value]
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return ["string", value]
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise InputError("non-finite JSON number")
        return ["number", value]
    if isinstance(value, list):
        return ["array", [content(item) for item in value]]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return ["object", [[key, content(value[key])] for key in sorted(value)]]
    raise InputError("unsupported JSON kind")


def equivalent(left: Any, right: Any) -> bool:
    return content(left) == content(right)


def wire(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sign_test_authorization(authorization: dict[str, Any]) -> dict[str, Any]:
    integrity = authorization.get("integrity", "intact")
    if integrity not in {"intact", "unsigned", "tampered"}:
        raise InputError("unknown integrity condition")
    payload = {key: value for key, value in authorization.items() if key != "integrity"}
    signature = hmac.new(TEST_KEY, wire(payload), hashlib.sha256).hexdigest()
    if integrity == "unsigned":
        signature = ""
    elif integrity == "tampered":
        signature = ("0" if signature[0] != "0" else "1") + signature[1:]
    return {"payload": payload, "signature": signature}


def authentic(envelope: dict[str, Any]) -> bool:
    expected = hmac.new(TEST_KEY, wire(envelope["payload"]), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, envelope["signature"])


def string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputError(f"{name}: expected a nonempty string")
    return value


def instant(value: Any) -> datetime:
    text = string(value, "timestamp")
    try:
        at = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError("timestamp: invalid ISO-8601") from exc
    if at.utcoffset() != timedelta(0):
        raise InputError("timestamp: UTC offset required")
    return at.astimezone(UTC)


def refusal(reason: str) -> dict[str, Any]:
    return {"outcome": "REFUSED", "refusal_class": reason}


def success(outcome: str) -> dict[str, Any]:
    return {"outcome": outcome, "refusal_class": None}

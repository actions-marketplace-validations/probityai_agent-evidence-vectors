"""Exchange one jep-byoi/1 request without importing any JEP implementation."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from state import accept, observe
from validator import PROFILE, SIGNATURE_CLASS, produce, validate


def exchange(request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a trusted local request and preserve original event JSON text."""
    if request.get("adapter_protocol") != "jep-byoi/1":
        raise ValueError("adapter_protocol must be jep-byoi/1")
    handlers = {
        "validate": _validate,
        "produce": _produce,
        "observe_effects": _probe,
        "set_state_availability": _availability,
    }
    operation = request.get("operation")
    if operation not in handlers:
        return {"unsupported": f"operation: {operation}"}
    return handlers[operation](request)


def _selected_profile(request: dict[str, Any]) -> None:
    """Refuse an undeclared or incompatible profile rather than silently downgrade."""
    if request.get("profile", PROFILE) != PROFILE:
        raise ValueError("unsupported JEP profile")
    if request.get("signature_class") != SIGNATURE_CLASS:
        raise ValueError("unsupported JEP signature class")


def _validate(request: dict[str, Any]) -> dict[str, Any]:
    """Perform validation before touching acceptance state."""
    _selected_profile(request)
    mode = request.get("mode", "archival")
    if mode not in ("archival", "acceptance"):
        return {"unsupported": f"validation mode: {mode}"}
    result, event = validate(request["event_json"], request["keys"])
    result["mode"] = mode
    if mode == "acceptance":
        _apply_acceptance(request, result, event)
    return {"result": result}


def _apply_acceptance(
    request: dict[str, Any], result: dict[str, Any], event: dict[str, Any] | None
) -> None:
    """Map local state outcomes without upgrading failed cryptographic validation."""
    if event is None:
        outcome = "indeterminate" if result["status"] == "indeterminate" else "rejected"
        result["acceptance"] = {"outcome": outcome, "effect_applied": False}
        return
    outcome = accept(Path(request["state_dir"]), request["acceptance_domain"], event)
    result["acceptance"] = outcome
    if outcome["outcome"] == "rejected":
        result["status"] = "invalid"
        result["checks"]["event_identity"] = "fail"
        result["errors"] = [
            {"code": "ERR_EVENT_ID_CONFLICT", "message": "unsigned content differs"}
        ]
    if outcome["outcome"] == "indeterminate":
        result["status"] = "indeterminate"


def _produce(request: dict[str, Any]) -> dict[str, Any]:
    """Return a test-only signed event and its disclosed public verification key."""
    _selected_profile(request)
    return produce(request["unsigned_event"])


def _probe(request: dict[str, Any]) -> dict[str, Any]:
    """Inspect committed effects through a separate read-only database connection."""
    return {"effect_count": observe(Path(request["state_dir"]), request["acceptance_domain"])}


def _availability(request: dict[str, Any]) -> dict[str, Any]:
    """Inject synthetic unavailability without hiding committed effects from the probe."""
    available = request["available"]
    if type(available) is not bool:
        raise ValueError("available must be a boolean")
    marker = Path(request["state_dir"]) / "unavailable"
    if available:
        marker.unlink(missing_ok=True)
    else:
        marker.write_bytes(b"synthetic acceptance-state failure\n")
    return {"configured": True}


def main() -> int:
    """Read a stdin request and emit one result; validation refusals exit zero."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", nargs="?", choices=("validate", "produce", "probe"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    request = json.load(sys.stdin)
    if args.operation:
        request["operation"] = "observe_effects" if args.operation == "probe" else args.operation
    print(json.dumps(exchange(request), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

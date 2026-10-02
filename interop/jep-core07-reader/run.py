"""Run and retain the preregistered 25/4/8 JEP fixture populations."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.metadata
import json
import platform
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from state import initialize
from validator import PROFILE, SIGNATURE_CLASS

ROOT = Path(__file__).resolve().parent


def digest(path: Path) -> str:
    """Hash exact saved bytes without text normalization."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned_inputs(upstream: Path) -> dict[str, Any]:
    """Authenticate the externally selected manifest before evaluating its files."""
    lock = json.loads((ROOT / "source-lock.json").read_text())
    if digest(upstream / "manifest.json") != lock["manifest_sha256"]:
        raise ValueError("JEP manifest differs from the preregistered pin")
    manifest = json.loads((upstream / "manifest.json").read_text())
    if manifest["files"] != lock["files"]:
        raise ValueError("JEP file manifest differs from the preregistered pin")
    _pinned_files(upstream, manifest["files"])
    populations = tuple(
        len(manifest[key]) for key in ("assertions", "producer_assertions", "acceptance_assertions")
    )
    if populations != (25, 4, 8):
        raise ValueError("JEP manifest must retain the 25/4/8 assertion populations")
    return manifest


def _pinned_files(upstream: Path, files: dict[str, str]) -> None:
    """Refuse changed suite bytes before executing any adapter request."""
    for relative, expected in files.items():
        path = upstream / relative
        if path.is_symlink() or digest(path) != expected.removeprefix("sha256:"):
            raise ValueError(f"JEP input digest mismatch: {relative}")


def invoke(request: dict[str, Any]) -> dict[str, Any]:
    """Call a fresh adapter process and retain the complete request and exchange."""
    argv = [sys.executable, str(ROOT / "adapter.py")]
    request = {
        "adapter_protocol": "jep-byoi/1",
        "profile": PROFILE,
        "signature_class": SIGNATURE_CLASS,
        **request,
    }
    completed = subprocess.run(
        argv, input=json.dumps(request), capture_output=True, text=True, timeout=15, check=False
    )
    retained = {
        "argv": argv,
        "request": request,
        "exit_status": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.returncode:
        raise ValueError(f"adapter exchange failed: {retained}")
    retained["response"] = json.loads(completed.stdout)
    return retained


def differences(expected: Any, actual: Any, path: str = "") -> list[dict[str, Any]]:
    """Compare every required expected field, keeping missing fields visible."""
    if not isinstance(expected, dict):
        return (
            [] if expected == actual else [{"field": path, "expected": expected, "actual": actual}]
        )
    value = actual if isinstance(actual, dict) else {}
    return [
        item
        for key, wanted in expected.items()
        for item in differences(wanted, value.get(key), path + "/" + key)
    ]


def validation_assertion(upstream: Path, assertion: dict[str, Any]) -> dict[str, Any]:
    """Retain actual validation before comparing the published expected answer."""
    exchange = invoke(
        {
            "operation": "validate",
            "event_json": (upstream / assertion["input"]).read_text(),
            "keys": json.loads((upstream / assertion["keys"]).read_text()),
            "mode": assertion["mode"],
        }
    )
    actual = exchange["response"]["result"]
    errors = actual.get("errors", [])
    compared = {**actual, "error_code": errors[0]["code"] if errors else None}
    return _row(assertion, [exchange], differences(assertion["expected"], compared))


def producer_assertion(upstream: Path, assertion: dict[str, Any]) -> dict[str, Any]:
    """Produce and verify independently, retaining event bytes and test keys."""
    produced = invoke(
        {
            "operation": "produce",
            "unsigned_event": json.loads((upstream / assertion["template"]).read_text()),
        }
    )
    response = produced["response"]
    verified = invoke({"operation": "validate", "mode": "archival", **response})
    expected = {"status": "valid", "checks": {"cryptographic": "pass", "syntax": "pass"}}
    event = json.loads(response["event_json"])
    template = json.loads((upstream / assertion["template"]).read_text())
    mismatch = differences(template, event) + differences(expected, verified["response"]["result"])
    return _row(assertion, [produced, verified], mismatch)


def acceptance_assertion(
    upstream: Path, assertion: dict[str, Any], state_root: Path
) -> dict[str, Any]:
    """Exercise fresh processes and a separate read-only probe on isolated state."""
    initialize(state_root)
    exchanges: list[dict[str, Any]] = []
    mismatch: list[dict[str, Any]] = []
    for step in assertion["steps"]:
        actual, traces = _step(upstream, step, state_root)
        exchanges.extend(traces)
        mismatch.extend(differences(step.get("expected", {}), actual))
        mismatch.extend(_probe_step(step, state_root, exchanges))
    return _row(assertion, exchanges, mismatch)


def _step(
    upstream: Path, step: dict[str, Any], state_root: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Execute availability, serial validation or eight genuine competing processes."""
    common = {"state_dir": str(state_root), "acceptance_domain": step.get("acceptance_domain", "a")}
    if step["operation"] == "set_state_availability":
        trace = invoke(
            {"operation": "set_state_availability", "available": step["available"], **common}
        )
        return {}, [trace]
    request = {
        "operation": "validate",
        "event_json": (upstream / step["input"]).read_text(),
        "keys": json.loads((upstream / "keys.json").read_text()),
        "mode": step.get("mode", "acceptance"),
        **common,
    }
    if step["operation"] == "concurrent":
        return _concurrent(request, step["deliveries"])
    trace = invoke(request)
    return trace["response"]["result"], [trace]


def _concurrent(
    request: dict[str, Any], deliveries: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Launch every competing delivery, then verify the persisted safe retry."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=deliveries) as pool:
        traces = list(pool.map(lambda _: invoke(request), range(deliveries)))
    outcomes = [item["response"]["result"] for item in traces]
    retry = invoke(request)
    traces.append(retry)
    if any(item["status"] == "invalid" for item in outcomes):
        raise ValueError("concurrent valid delivery returned an invalid result")
    expected = {
        "status": "valid",
        "acceptance": {"outcome": "already_accepted", "effect_applied": False},
    }
    if differences(expected, retry["response"]["result"]):
        raise ValueError("concurrent acceptance did not preserve safe retry")
    return retry["response"]["result"], traces


def _probe_step(
    step: dict[str, Any], state_root: Path, exchanges: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Compare observed committed effect rows, never self-reported effect flags."""
    if "expected_effect_count" not in step:
        return []
    trace = invoke(
        {
            "operation": "observe_effects",
            "state_dir": str(state_root),
            "acceptance_domain": step["acceptance_domain"],
        }
    )
    exchanges.append(trace)
    return differences({"effect_count": step["expected_effect_count"]}, trace["response"])


def _row(
    assertion: dict[str, Any], exchanges: list[dict[str, Any]], mismatch: list[dict[str, Any]]
) -> dict[str, Any]:
    """Retain the entire measured exchange and its exposed-answer comparison."""
    return {
        "assertion_id": assertion["assertion_id"],
        "result": "fail" if mismatch else "pass",
        "differences": mismatch,
        "exchanges": exchanges,
    }


def main() -> int:
    """Create a fresh retained run tied to the published protocol and reader."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reader-revision", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.reader_revision):
        parser.error("reader revision must be a published 40-character Git commit")
    manifest = pinned_inputs(args.upstream)
    args.output.mkdir(parents=True, exist_ok=False)
    rows = {
        "validation": [validation_assertion(args.upstream, a) for a in manifest["assertions"]],
        "producer": [producer_assertion(args.upstream, a) for a in manifest["producer_assertions"]],
        "acceptance": [
            acceptance_assertion(args.upstream, a, args.output / a["assertion_id"])
            for a in manifest["acceptance_assertions"]
        ],
    }
    summary = {
        name: {"total": len(population), "passed": sum(a["result"] == "pass" for a in population)}
        for name, population in rows.items()
    }
    report = {
        "schema_version": "probity-jep-core07-run-v1",
        "reader_revision": args.reader_revision,
        "protocol_sha256": digest(ROOT / "PROTOCOL.md"),
        "source_lock_sha256": digest(ROOT / "source-lock.json"),
        "reader_files": {
            name: digest(ROOT / name)
            for name in ("validator.py", "state.py", "adapter.py", "run.py")
        },
        "command": shlex.join([sys.executable, *sys.argv]),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cryptography": importlib.metadata.version("cryptography"),
            "rfc8785": importlib.metadata.version("rfc8785"),
        },
        "summary": summary,
        "assertions": rows,
        "limits": [
            "Exposed-answer conformance, not a blind study",
            "Synthetic local SQLite effects, not truth or external execution",
            "Test keys establish no real-world actor authority",
            "Probity controls both processor and read-only probe",
            "No power-loss, distributed failover or JEP host CI adoption",
        ],
    }
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    )
    print(json.dumps(summary))
    return int(any(item["total"] != item["passed"] for item in summary.values()))


if __name__ == "__main__":
    raise SystemExit(main())

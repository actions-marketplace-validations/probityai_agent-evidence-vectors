"""Execute installed Verify on absence claims about the finite dispatch log."""

from __future__ import annotations

import copy
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from remora_boundary.cli import save
from remora_boundary.common import digest, wire


def seconds(value: str, *, upper: bool = False) -> str:
    at = datetime.fromisoformat(value).astimezone(UTC)
    if upper and at.microsecond:
        at += timedelta(seconds=1)
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


def records(row: dict[str, Any], started: str, completed: str) -> tuple[dict, dict, str]:
    case_id = "remora-dispatch-absence-" + row["case_id"]
    invocation = "fixture-invocation-" + row["case_id"]
    scope = {"id": "executed-binding-fixture", "start": seconds(started),
             "end": seconds(completed, upper=True)}
    capability = {"schema_version": "probity-capabilities/v1", "claim_id": case_id,
                  "invocation_id": invocation, "producer": "probity-fixture-callback-log",
                  "visible_event_types": ["dispatch"]}
    events = [{"id": f"dispatch-{index}", "type": "dispatch", "time": seconds(event["at"])}
              for index, event in enumerate(row["observed"]["events"])]
    observation = {"schema_version": "probity-observation/v1", "claim_id": case_id,
                   "invocation_id": invocation, "producer": capability["producer"],
                   "scope": scope, "coverage": "complete", "events": events}
    return capability, observation, "contradicted" if events else "supported"


def bind(path: Path, capability: dict, observation: dict) -> tuple[dict, dict]:
    artifacts, witnesses = {}, {}
    for name, data in (("capability", capability), ("observation", observation)):
        raw = wire(data) + b"\n"
        (path / f"{name}.json").write_bytes(raw)
        artifacts[name] = {"path": f"{name}.json", "length": len(raw), "sha256": digest(raw)}
        witnesses[name] = {"artifact": name, "sha256": digest(raw),
                           "authority": "controlled Probity fixture callback log"}
    case = {"schema_version": "probity-case/v1", "case_id": capability["claim_id"],
            "artifacts": artifacts}
    assessment = {"claim_type": "event_absence/v1", "event_type": "dispatch",
                  "invocation_id": capability["invocation_id"], "scope": observation["scope"],
                  "capability_witness": "capability", "observation_witness": "observation"}
    policy = {"schema_version": "probity-policy/v1", "witnesses": witnesses,
              "assessments": {case["case_id"]: assessment}}
    save(path / "case.json", case)
    save(path / "policy.json", policy)
    return case, policy


def invoke(path: Path, capability: dict, observation: dict, expected: str | None,
           executable: Path, control: str | None = None) -> dict[str, Any]:
    path.mkdir(parents=True)
    case, policy = bind(path, capability, observation)
    if control == "byte-tamper":
        raw = (path / "observation.json").read_bytes()
        (path / "observation.json").write_bytes(raw.replace(b'"complete"', b'"unknown"'))
    if control == "malformed-pinned":
        raw = b'{"schema_version":"probity-observation/v1","schema_version":"duplicate"}'
        (path / "observation.json").write_bytes(raw)
        case["artifacts"]["observation"].update(length=len(raw), sha256=digest(raw))
        policy["witnesses"]["observation"]["sha256"] = digest(raw)
        save(path / "case.json", case)
        save(path / "policy.json", policy)
    command = [str(executable), "case.json", "--policy", "policy.json", "--json",
               "--packet", "decision.txt"]
    completed = subprocess.run(command, cwd=path, capture_output=True, timeout=30, check=False)
    (path / "stdout.json").write_bytes(completed.stdout)
    (path / "stderr.txt").write_bytes(completed.stderr)
    decision = json.loads(completed.stdout) if completed.returncode == 0 else None
    okay = (completed.returncode == 0 and isinstance(decision, dict)
            and decision.get("decision") == expected) if expected else (
        completed.returncode == 2 and not completed.stdout and not (path / "decision.txt").exists()
    )
    result = {"path": path.name, "expected": expected, "exit_status": completed.returncode,
              "decision": decision, "matches_expected": okay,
              "command": "probity-verify case.json --policy policy.json --json "
                         "--packet decision.txt"}
    save(path / "invocation.json", result)
    return result


def qualify(output: Path, native: dict, executable: Path) -> list[dict[str, Any]]:
    binding = next(report for report in native["contracts"]
                   if report["contract_id"] == "exact-call-binding-v1")
    rows = []
    empty = None
    for row in binding["cases"]:
        cap, obs, expected = records(row, native["started_at"], native["completed_at"])
        rows.append(invoke(output / row["case_id"], cap, obs, expected, executable))
        if expected == "supported" and empty is None:
            empty = (cap, obs)
    assert empty is not None
    for name in ("no-field-visibility", "unknown-coverage", "wrong-invocation"):
        cap, obs = copy.deepcopy(empty)
        if name == "no-field-visibility":
            cap["visible_event_types"] = []
        elif name == "unknown-coverage":
            obs["coverage"] = "unknown"
        else:
            obs["invocation_id"] += "-other"
        rows.append(invoke(output / name, cap, obs, "not_established", executable))
    for name, expected in (("byte-tamper", "not_established"), ("malformed-pinned", None)):
        cap, obs = copy.deepcopy(empty)
        rows.append(invoke(output / name, cap, obs, expected, executable, control=name))
    return rows

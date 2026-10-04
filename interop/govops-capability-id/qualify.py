"""Install the reader and retain actual API/CLI results for each finite case."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from fixtures import AUTHORITY, PUBLIC, cases
from govops_ids import Admitter, evaluate

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_sources() -> dict[str, Any]:
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    for group in ("historical", "rawAdmission"):
        for entry in manifest[group]["files"]:
            raw = (REPO / entry["retainedPath"]).read_bytes()
            if len(raw) != entry["bytes"] or digest(raw) != entry["sha256"]:
                raise ValueError("source changed: " + entry["retainedPath"])
    return manifest


def installed(installation: Path) -> tuple[Path, dict[str, str]]:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--root-user-action=ignore",
            "--upgrade",
            "--no-deps",
            "--no-build-isolation",
            "--target",
            str(installation),
            str(HERE),
        ],
        check=True,
        stdout=sys.stderr,
    )
    environment = {**os.environ, "PYTHONPATH": str(installation)}
    return installation / "bin/probity-govops-ids", environment


def trust(row: dict[str, Any]) -> dict[str, bytes]:
    if row.get("trust") == "none":
        return {}
    return {AUTHORITY: b"\x01" * 32 if row.get("trust") == "wrong" else PUBLIC}


def run_case(row: dict[str, Any], executable: Path, admitter_path: Path, environment: dict[str, str], outside: Path) -> dict[str, Any]:
    profile = row.get("profile", "ijson-integers")
    depth, size = row.get("max_depth", 32), row.get("max_bytes", 1048576)
    authority = row.get("expected_authority", AUTHORITY)
    keys = trust(row)
    api = evaluate(row["request"], Admitter(admitter_path, profile, depth, size), keys, authority)
    command = [
        str(executable),
        "--admitter",
        str(admitter_path),
        "--profile",
        profile,
        "--max-depth",
        str(depth),
        "--max-bytes",
        str(size),
        "--expected-authority",
        authority,
    ]
    for name, key in keys.items():
        command += ["--trusted-key", name + "=" + key.hex()]
    process = subprocess.run(command, input=row["request"], capture_output=True, cwd=outside, env=environment, timeout=30, check=False)
    try:
        result = json.loads(process.stdout)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("installed reader emitted no valid report: " + row["name"]) from exc
    expected_status = 0 if result.get("verdict") in ("bound", "correlated") else 1
    matched = all(result.get(key) == value for key, value in row["expected"].items())
    matched = matched and api == result and process.returncode == expected_status and not process.stderr
    return {
        "name": row["name"],
        "raw_input_sha256": digest(row["request"]),
        "raw_input_bytes": len(row["request"]),
        "profile": profile,
        "max_depth": depth,
        "max_bytes": size,
        "expected": row["expected"],
        "actual": result,
        "api_cli_equal": api == result,
        "cli_exit": process.returncode,
        "matched": matched,
        "historical_expect": row.get("historical_expect"),
        "adaptation": row.get("adaptation"),
        "numeric_policy_difference": row.get("numeric_policy_difference"),
        "raw_stdout_sha256": digest(process.stdout),
        "raw_stdout_hex": process.stdout.hex(),
    }


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(REPO), *arguments], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admitter", type=Path, required=True)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=HERE / "report.json")
    args = parser.parse_args()
    sources = verify_sources()
    installation = args.installation.resolve()
    executable, environment = installed(installation)
    outside = installation.parent / "external-reader-cwd"
    outside.mkdir(parents=True, exist_ok=True)
    rows = cases()
    records = [run_case(row, executable, args.admitter.resolve(), environment, outside) for row in rows]
    check = subprocess.check_output(
        [sys.executable, "-c", "import govops_ids.reader; print(govops_ids.reader.__file__)"], cwd=outside, env=environment, text=True
    ).strip()
    if not Path(check).is_relative_to(installation):
        raise ValueError("reader was not imported from its installation")
    legacy = subprocess.run(
        [sys.executable, str(HERE / "history/vectors-capability-id/check_vectors.py")], capture_output=True, check=True, text=True
    )
    bundle = [
        {
            "name": row["name"],
            "request_hex": row["request"].hex(),
            "expected": row["expected"],
            "options": {key: value for key, value in row.items() if key not in ("name", "request", "expected")},
        }
        for row in rows
    ]
    (HERE / ".build").mkdir(exist_ok=True)
    (HERE / ".build/cases.json").write_text(json.dumps(bundle, indent=2) + "\n")
    report = {
        "schema": "probity.govops-id.qualifications.v1",
        "summary": {"cases": len(records), "matched": sum(r["matched"] for r in records)},
        "records": records,
        "source": sources,
        "manifest_sha256": digest((HERE / "MANIFEST.json").read_bytes()),
        "case_bundle_sha256": digest((HERE / ".build/cases.json").read_bytes()),
        "qualified_checkout": git("rev-parse", "HEAD"),
        "worktree_status": git("status", "--porcelain").splitlines(),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "runtime": {
            "python": platform.python_version(),
            "cryptography": importlib.metadata.version("cryptography"),
            "rust": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        },
        "installation": {
            "reader_sha256": digest(Path(check).read_bytes()),
            "admitter_sha256": digest(args.admitter.read_bytes()),
            "outside_working_directory": True,
            "api_cli_equal": all(r["api_cli_equal"] for r in records),
        },
        "historical_original_checker": {
            "exit": legacy.returncode,
            "stdout": legacy.stdout,
            "scope": "Original draft descriptor-correlation checker only; no authority or effects.",
        },
        "scope": {
            "actual_target_effects": "not-observed",
            "kernel_observer": "not-executed",
            "outside_custody": False,
            "host_execution": False,
            "native_record_signature_verification": True,
            "keys": "Public deterministic fixture keys; no production signing or signing-policy change.",
        },
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"]))
    return 0 if report["summary"]["matched"] == report["summary"]["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

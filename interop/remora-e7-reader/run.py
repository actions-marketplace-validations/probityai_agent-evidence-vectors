"""Retain an E7 evaluation and its producer-native external run record."""

from __future__ import annotations

import argparse
import json
import logging
import platform
import re
import sys
from pathlib import Path

from reader import CONTRACT, PACKAGE_DIGEST, REVISION, run_package, sha256


def main() -> int:
    """Run the selected frozen package and retain an immutable output directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reader-revision", required=True)
    parser.add_argument("--run-ref", required=True)
    parser.add_argument("--operator", choices=("AUTHOR", "EXTERNAL"), required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.reader_revision):
        parser.error("reader revision must be a published 40-character Git commit")
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    args.output.mkdir(parents=True, exist_ok=False)
    report = run_package(args.upstream)
    report["reader_files"] = _reader_files()
    report["environment"] = f"Python {platform.python_version()} on {platform.platform()}"
    report["command"] = _command()
    record = {
        "schema_version": "remora-external-run-record-v1",
        "contract_id": CONTRACT,
        "package_digest": PACKAGE_DIGEST,
        "consumed_revision": REVISION,
        "verifier": {
            "project": "Probity",
            "repository": "probityai/agent-evidence-vectors",
            "implementation_revision": args.reader_revision,
            "maintained_by": "EXTERNAL",
        },
        "imports": {"remora_runtime": False, "reference_verifier": False},
        "command": report["command"],
        "environment": report["environment"],
        "input_digests": report["input_digests"],
        "implementation_diversity": "SECOND_IMPLEMENTATION",
        "operator": args.operator,
        "independence": "INDEPENDENT" if args.operator == "EXTERNAL" else "NOT_INDEPENDENT",
        "results": [
            {
                "claim_id": item["claim_id"],
                "case_id": item["case_id"],
                "result": item["claim_result"],
                "note": "Frozen fixture premise only; see report.json for ceilings and non-claims.",
            }
            for item in report["results"]
        ],
        "claim_ceiling_repeated": True,
        "non_claims_repeated": True,
        "run_ref": args.run_ref,
    }
    report["operator_scope"] = (
        "Operator is external to REMORA when EXTERNAL is selected. Reader and output are under "
        "Probity control; this proves no independent effect observation or key/store custody."
    )
    for name, value in (("report.json", report), ("external-run-record-v1.json", record)):
        (args.output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"cases": len(report["results"]), "failures": report["failures"]}))
    return int(bool(report["failures"]))


def _reader_files() -> list[dict[str, str]]:
    """Bind the actual reader sources evaluated by this command."""
    root = Path(__file__).parent
    return [
        {"path": name, "sha256": sha256((root / name).read_bytes())}
        for name in ("reader.py", "run.py")
    ]


def _command() -> str:
    """Render the invocation as an unambiguous shell command."""
    import shlex

    return shlex.join([sys.executable, *sys.argv])


if __name__ == "__main__":
    raise SystemExit(main())

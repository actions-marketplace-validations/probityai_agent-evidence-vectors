"""Read frozen inputs, retain native decisions, and refuse malformed invocations."""

from __future__ import annotations

import argparse
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import binding, effects, fresh
from .common import InputError, digest, load_raw, wire

CONTRACTS = {
    "exact-call-binding-v1": binding.evaluate,
    "fresh-authority-v1": fresh.evaluate,
    "effect-evidence-v1": effects.evaluate,
}


def evaluate_case(contract: str, case: dict[str, Any]) -> dict[str, Any]:
    observed = CONTRACTS[contract](case)
    expected = case["expected"]
    fields = ("outcomes",) if contract != "effect-evidence-v1" else (
        "effect_status", "highest_established_state"
    )
    matches = all(observed.get(field) == expected.get(field) for field in fields)
    result = "ESTABLISHED" if observed.get("authority_verified", True) else "NOT_ESTABLISHED"
    if not matches:
        result = "CONTRADICTED"
    return {"case_id": case["id"], "claim_id": case["claim_id"], "expected": expected,
            "observed": observed, "result": result,
            "matches_expected": matches and result == expected["claim_result"]}


def check_source(profile: Path) -> dict[str, Any]:
    lock = load_raw((profile / "source-lock.json").read_bytes())
    for row in lock["files"]:
        if digest((profile / row["local_path"]).read_bytes()) != row["sha256"]:
            raise InputError(f"frozen source bytes changed: {row['path']}")
    for contract in CONTRACTS:
        root = profile / "source/artifacts/interop" / contract
        if (root / "reference_verifier.py").exists():
            raise InputError("reference implementation bytes are outside this reader's inputs")
        manifest = load_raw((root / "manifest.json").read_bytes())
        lines = "".join(f"{row['path']} {row['sha256']}\n" for row in sorted(
            manifest["package_files"], key=lambda row: row["path"]
        ))
        if "sha256:" + digest(lines.encode()) != manifest["package_digest"]:
            raise InputError("producer package digest mismatch")
        for row in manifest["package_files"]:
            if row["path"].endswith("/reference_verifier.py"):
                continue
            if digest((profile / "source" / row["path"]).read_bytes()) != row["sha256"]:
                raise InputError("producer package member mismatch")
    return lock


def save(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(wire(value) + b"\n")


def claim_records(contract: str, rows: list[dict[str, Any]], packet: dict[str, Any],
                  manifest: dict[str, Any], args: argparse.Namespace,
                  started: str, completed: str, environment: str) -> list[dict[str, Any]]:
    records = []
    for claim in packet["claims"]:
        selected = [row for row in rows if row["claim_id"] == claim["claim_id"]]
        status = "CONTRADICTED" if any(row["result"] == "CONTRADICTED" for row in selected) else (
            "ESTABLISHED" if any(row["result"] == "ESTABLISHED" for row in selected)
            else "NOT_ESTABLISHED"
        )
        fixture = next(row for row in manifest["package_files"]
                       if row["path"].endswith("/fixtures.json"))
        records.append({
            "schema_version": "remora-interop-result-v1", "contract_id": contract,
            "edge": {"exact-call-binding-v1": "E-ECB", "fresh-authority-v1": "E-FA",
                     "effect-evidence-v1": "E-EE"}[contract],
            "claim": claim["claim_id"], "subject": packet["subject"]["id"], "status": status,
            "producer": {"project": "REMORA-research",
                         "repository": "darklordVirtual/REMORA-research",
                         "revision": "fe324dd734734d9227aa894330ac52c2bb916b94"},
            "consumer": {"project": "Probity Vectors",
                         "repository": "probityai/agent-evidence-vectors",
                         "revision": args.implementation_revision},
            "fixture": {"path": fixture["path"], "digest": "sha256:" + fixture["sha256"],
                        "package_digest": manifest["package_digest"]},
            "evaluator": {"project": "Probity REMORA boundary reader",
                          "repository": "probityai/agent-evidence-vectors",
                          "revision": args.implementation_revision,
                          "kind": "SECOND_IMPLEMENTATION", "maintained_by": "EXTERNAL",
                          "imports_producer_runtime": False, "imports_reference_evaluator": False,
                          "command": "probity-remora-boundary --profile PROFILE --output NEW_PATH "
                                     "--implementation-revision EXECUTED_REVISION"},
            "operator": "EXTERNAL", "host": "EXTERNAL",
            "independence_level": "L2_SECOND_IMPLEMENTATION",
            "environment": environment, "started_at": started, "completed_at": completed,
            "cases": [{key: row[key] for key in
                       ("case_id", "claim_id", "expected", "observed", "result")}
                      for row in selected],
            "establishes": [claim["claim_ceiling"]] if status == "ESTABLISHED" else [],
            "does_not_establish": packet["explicit_non_claims"] + [
                "Independent outside custody of this implementation-owned run.",
                "Producer acceptance or publication of an external verification record.",
            ],
            "ceiling": {"implies_endorsement": False, "implies_production_safety": False,
                        "implies_broader_validity": False, "confers_authority": False},
            "run_ref": args.run_ref, "published_at": None,
        })
    return records


def read_contract(contract: str, args: argparse.Namespace, started: str,
                  environment: str) -> dict[str, Any]:
    root = args.profile / "source/artifacts/interop" / contract
    fixtures = load_raw((root / "fixtures.json").read_bytes())
    packet = load_raw((root / "claim-packet.json").read_bytes())
    manifest = load_raw((root / "manifest.json").read_bytes())
    rows = [evaluate_case(contract, case) for case in fixtures["cases"]]
    completed = datetime.now(UTC).isoformat()
    records = claim_records(contract, rows, packet, manifest, args, started, completed, environment)
    input_digests = [{"path": row["path"], "sha256": row["sha256"]}
                     for row in manifest["package_files"]
                     if not row["path"].endswith("/reference_verifier.py")]
    run_record = {
        "schema_version": "remora-external-run-record-v1", "contract_id": contract,
        "package_digest": manifest["package_digest"],
        "consumed_revision": "fe324dd734734d9227aa894330ac52c2bb916b94",
        "verifier": {"project": "Probity REMORA boundary reader",
                     "repository": "probityai/agent-evidence-vectors",
                     "implementation_revision": args.implementation_revision,
                     "maintained_by": "EXTERNAL"},
        "imports": {"remora_runtime": False, "reference_verifier": False},
        "command": "probity-remora-boundary --profile PROFILE --output NEW_PATH "
                   "--implementation-revision EXECUTED_REVISION",
        "environment": environment, "input_digests": input_digests,
        "implementation_diversity": "SECOND_IMPLEMENTATION", "operator": "EXTERNAL",
        "independence": "NOT_INDEPENDENT",
        "results": [{key: row[key] for key in ("claim_id", "case_id", "result")} for row in rows],
        "claim_ceiling_repeated": True, "non_claims_repeated": True,
        "run_ref": args.run_ref, "published_at": None,
    }
    return {"contract_id": contract, "cases": rows, "claims": records,
            "run_record": run_record,
            "package_digest": manifest["package_digest"], "source_revision_authored":
            manifest["source_revision"], "case_count": len(rows),
            "passing_expectations": sum(row["matches_expected"] for row in rows)}


def run(args: argparse.Namespace) -> int:
    check_source(args.profile)
    if args.input:
        case = load_raw(args.input.read_bytes())
        row = evaluate_case(args.contract, case)
        sys.stdout.buffer.write(wire(row) + b"\n")
        return 0 if row["matches_expected"] else 1
    if args.output is None:
        raise InputError("a fresh --output path is required")
    if args.output.exists():
        raise InputError("output already exists; retain each run separately")
    started = datetime.now(UTC).isoformat()
    environment = f"Python {platform.python_version()}; {platform.platform()}"
    contracts = [args.contract] if args.contract else list(CONTRACTS)
    reports = [read_contract(contract, args, started, environment) for contract in contracts]
    failed = any(report["case_count"] != report["passing_expectations"] for report in reports)
    summary = {"schema": "probity-remora-boundary-qualification-v1", "status":
               "failed" if failed else "passed", "implementation_revision":
               args.implementation_revision, "operator": "astrogilda implementation-owned run",
               "implementation_diversity": "SECOND_IMPLEMENTATION",
               "independence": "NOT_INDEPENDENT", "producer_runtime_imported": False,
               "reference_evaluator_imported": False,
               "consumed_revision": "fe324dd734734d9227aa894330ac52c2bb916b94",
               "started_at": started, "completed_at": datetime.now(UTC).isoformat(),
               "environment": environment, "contracts": reports,
               "publication_state": "qualification only; producer review and outside run pending"}
    save(args.output / "native-decisions.json", summary)
    sys.stdout.buffer.write(wire({"status": summary["status"], "cases": sum(
        report["case_count"] for report in reports
    ), "passing_expectations": sum(report["passing_expectations"] for report in reports)}) + b"\n")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--contract", choices=list(CONTRACTS))
    parser.add_argument("--implementation-revision", required=True)
    parser.add_argument("--run-ref", default="qualification-pending-review")
    args = parser.parse_args(argv)
    if args.input and not args.contract:
        parser.error("--input requires --contract")
    try:
        return run(args)
    except (InputError, OSError, KeyError, TypeError, ValueError, RecursionError) as exc:
        print(f"probity-remora-boundary: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

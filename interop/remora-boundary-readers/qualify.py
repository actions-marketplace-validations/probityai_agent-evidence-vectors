"""Retain installed native readers, falsification attempts and Verify decisions."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema

from controls import SOURCE_FAULTS, own_cases
from remora_boundary.cli import save
from remora_boundary.common import digest, load_raw, wire
from verify_bridge import qualify as verify_qualify


def capture(path: Path, command: list[str],
            extra_environment: dict[str, str] | None = None) -> dict:
    path.mkdir(parents=True)
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    environment.update(extra_environment or {})
    result = subprocess.run(command, cwd=path, env=environment, capture_output=True,
                            timeout=60, check=False)
    (path / "stdout.txt").write_bytes(result.stdout)
    (path / "stderr.txt").write_bytes(result.stderr)
    record = {"exit_status": result.returncode, "stdout_sha256": digest(result.stdout),
              "stderr_sha256": digest(result.stderr), "command": [
                  Path(item).name if Path(item).is_absolute() else item for item in command
              ]}
    save(path / "invocation.json", record)
    return record


def command(profile: Path, revision: str) -> list[str]:
    return [sys.executable, "-m", "remora_boundary.cli", "--profile", str(profile),
            "--implementation-revision", revision]


def source_identity(root: Path) -> dict[str, Any]:
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                            capture_output=True, check=True).stdout.decode().strip()
    files = []
    for path in sorted(root.glob("src/probity_verify/**/*.py")):
        raw = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        blob = subprocess.run(["git", "rev-parse", f"HEAD:{relative}"], cwd=root,
                              capture_output=True, check=True).stdout.decode().strip()
        committed = subprocess.run(["git", "show", f"HEAD:{relative}"], cwd=root,
                                   capture_output=True, check=True).stdout
        if raw != committed:
            raise ValueError("Verify source working bytes changed")
        files.append({"path": relative, "blob": blob, "bytes": len(raw), "sha256": digest(raw)})
    return {"repository": "probityai/probity-verify", "revision": commit, "files": files}


def reader_identity(profile: Path) -> dict[str, Any]:
    files = [{"path": path.relative_to(profile).as_posix(), "bytes": len(path.read_bytes()),
              "sha256": digest(path.read_bytes())}
             for path in sorted((profile / "remora_boundary").glob("*.py"))]
    selected = "".join(f"{row['path']} {row['sha256']}\n" for row in files)
    return {"files": files, "source_sha256": digest(selected.encode())}


def installed_identity(output: Path) -> dict[str, Any]:
    probe = (
        "import json,pathlib,hashlib,importlib.metadata,remora_boundary;"
        "root=pathlib.Path(remora_boundary.__file__).parent;"
        "rows=[{'path':'remora_boundary/'+p.name,'bytes':len(p.read_bytes()),"
        "'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in "
        "sorted(root.glob('*.py'))];"
        "print(json.dumps({'files':rows,'distribution_version':"
        "importlib.metadata.version('probity-remora-boundary-reader'),"
        "'location_kind':'site-packages' if 'site-packages' in root.parts else 'source'}))"
    )
    record = capture(output / "installed-reader", [sys.executable, "-c", probe])
    if record["exit_status"] != 0:
        raise ValueError("installed reader probe failed")
    return load_raw((output / "installed-reader/stdout.txt").read_bytes())


def run_extra(profile: Path, output: Path, revision: str,
              environment: dict[str, str] | None = None,
              selected_contract: str | None = None) -> list[dict[str, Any]]:
    rows = []
    for contract, case in own_cases(profile):
        if selected_contract and selected_contract != contract:
            continue
        path = output / case["id"]
        path.mkdir(parents=True)
        save(path / "input.json", case)
        invocation = capture(path / "native", command(profile, revision) + [
            "--input", str(path / "input.json"), "--contract", contract
        ], environment)
        observed = load_raw((path / "native/stdout.txt").read_bytes())
        rows.append({"case_id": case["id"], "contract": contract,
                     "exit_status": invocation["exit_status"], "observed": observed})
    return rows


def malformed_controls(profile: Path, output: Path, revision: str) -> list[dict[str, Any]]:
    inputs = {
        "duplicate-key": b'{"id":"x","id":"y"}',
        "escaped-duplicate-key": b'{"id":"x","i\\u0064":"y"}',
        "non-json-number": b'{"id":NaN}',
        "non-utf8": b'\xff',
        "unpaired-surrogate": b'{"id":"\\ud800"}',
        "above-byte-budget": b' ' * 1_048_577,
        "wrong-subject-shape": b'{"id":"bad","authorization":null}',
    }
    case = next(case for contract, case in own_cases(profile)
                if contract == "fresh-authority-v1")
    case["authorization"]["expires_at"] = case["authorization"]["issued_at"]
    inputs["empty-validity-window"] = wire(case)
    rows = []
    for name, raw in inputs.items():
        path = output / name
        path.mkdir(parents=True)
        (path / "input.json").write_bytes(raw)
        contract = "fresh-authority-v1" if name == "empty-validity-window" else (
            "exact-call-binding-v1"
        )
        invocation = capture(path / "native", command(profile, revision) + [
            "--input", str(path / "input.json"), "--contract", contract
        ])
        stdout = (path / "native/stdout.txt").read_bytes()
        rows.append({"control": name, "exit_status": invocation["exit_status"],
                     "no_verdict": not stdout, "input_sha256": digest(raw),
                     "matches_expected": invocation["exit_status"] == 2 and not stdout})
    return rows


def source_faults(profile: Path, output: Path, revision: str) -> list[dict[str, Any]]:
    rows = []
    expiry = ("include-expiry-endpoint", "fresh.py", "if at >= expires:",
              "if at > expires:", "fresh-authority-v1")
    for name, filename, original, mutation, contract in (*SOURCE_FAULTS, expiry):
        path = output / name
        source = path / "source/remora_boundary"
        shutil.copytree(profile / "remora_boundary", source,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        file = source / filename
        text = file.read_text()
        if text.count(original) != 1:
            raise ValueError("fault replacement is not uniquely bound to executed source")
        file.write_text(text.replace(original, mutation))
        identity = reader_identity(path / "source")
        fault_revision = "local-fault-sha256:" + identity["source_sha256"]
        env = {"PYTHONPATH": str(path / "source")}
        invocation = capture(path / "frozen", command(profile, fault_revision) + [
            "--output", str(path / "frozen-result"), "--contract", contract
        ], env)
        report = load_raw((path / "frozen-result/native-decisions.json").read_bytes())
        extra = run_extra(profile, path / "own", fault_revision, env, contract)
        contradicted = [row["case_id"] for report in report["contracts"]
                        for row in report["cases"] if not row["matches_expected"]]
        own_failed = [row["case_id"] for row in extra if row["exit_status"] != 0]
        rows.append({"fault": name, "base_revision": revision,
                     "executed_revision": fault_revision, "source_identity": identity,
                     "frozen_exit_status": invocation["exit_status"],
                     "frozen_contradicted": contradicted, "own_contradicted": own_failed,
                     "caught": bool(contradicted or own_failed)})
    return rows


def validate_records(profile: Path, native: dict[str, Any]) -> None:
    schema = load_raw((profile / "source/artifacts/interop/schemas/interop-result-v1.schema.json")
                      .read_bytes())
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    for report in native["contracts"]:
        for record in report["claims"]:
            validator.validate(record)
    path = profile / "source/artifacts/interop/schemas/external-run-record-v1.schema.json"
    schema = load_raw(path.read_bytes())
    validator = jsonschema.Draft202012Validator(schema)
    for report in native["contracts"]:
        validator.validate(report["run_record"])


def manifest(output: Path) -> None:
    rows = [{"path": path.relative_to(output).as_posix(), "bytes": len(path.read_bytes()),
             "sha256": digest(path.read_bytes())}
            for path in sorted(output.rglob("*")) if path.is_file()]
    save(output / "ARTIFACT-MANIFEST.json", {"members": rows})


def run(args: argparse.Namespace) -> int:
    profile, output = args.profile.resolve(), args.output.resolve()
    if output.exists():
        raise ValueError("qualification output already exists")
    identity = reader_identity(profile)
    verify_identity = source_identity(args.verify_source.resolve())
    if verify_identity["revision"] != "e835ce2bd6a960e7a1cc2fa6522f16d55dce728a":
        raise ValueError("Verify source pin changed")
    output.mkdir(parents=True)
    installed = installed_identity(output)
    if installed["location_kind"] != "site-packages" or installed["files"] != identity["files"]:
        raise ValueError("installed reader bytes differ from the selected source")
    native_invocation = capture(output / "baseline", command(profile, args.revision) + [
        "--output", str(output / "baseline-result"), "--run-ref", args.run_ref
    ])
    native = load_raw((output / "baseline-result/native-decisions.json").read_bytes())
    validate_records(profile, native)
    before = digest((output / "baseline-result/native-decisions.json").read_bytes())
    duplicate = capture(output / "existing-output", command(profile, args.revision) + [
        "--output", str(output / "baseline-result")
    ])
    unchanged = before == digest((output / "baseline-result/native-decisions.json").read_bytes())
    duplicate_okay = duplicate["exit_status"] == 2 and not (
        output / "existing-output/stdout.txt"
    ).read_bytes() and unchanged
    extra = run_extra(profile, output / "own-cases", args.revision)
    malformed = malformed_controls(profile, output / "malformed", args.revision)
    faults = source_faults(profile, output / "faults", args.revision)
    verify = verify_qualify(output / "verify", native, args.verify_executable.resolve())
    check = all(row["exit_status"] == 0 for row in extra) and all(
        row["matches_expected"] for row in malformed
    ) and all(row["caught"] for row in faults) and all(row["matches_expected"] for row in verify)
    check = check and native_invocation["exit_status"] == 0 and duplicate_okay
    summary = {"status": "passed" if check else "failed", "revision": args.revision,
               "reader_source": identity, "verify_source": verify_identity,
               "installed_reader": installed,
               "reader_distribution_version": importlib.metadata.version(
                   "probity-remora-boundary-reader"
               ), "verify_distribution_version": importlib.metadata.version("probity-verify"),
               "python": platform.python_version(), "platform": platform.platform(),
               "native_contracts": [{"contract": row["contract_id"], "cases": row["case_count"],
                                     "passing_expectations": row["passing_expectations"]}
                                    for row in native["contracts"]],
               "existing_output_refusal": {**duplicate, "matches_expected": duplicate_okay,
                                           "prior_native_report_unmodified": duplicate_okay},
               "own_cases": extra, "malformed_controls": malformed,
               "source_faults": faults, "verify_bridge": verify,
               "scope": "Implementation-owned finite qualification; no REMORA runtime or "
                        "reference imports, real target effects, outside custody "
                        "or lifecycle upgrade"}
    save(output / "summary.json", summary)
    shutil.copytree(profile / "source", output / "producer-inputs")
    shutil.copytree(args.verify_source / "src", output / "verify-source/src")
    for name in ("LICENSE", "pyproject.toml", "uv.lock"):
        shutil.copy2(args.verify_source / name, output / "verify-source" / name)
    shutil.copy2(profile / "source-lock.json", output / "source-lock.json")
    save(output / "reader-source-identity.json", identity)
    manifest(output)
    print(json.dumps({"status": summary["status"], "native_cases": sum(
        row["case_count"] for row in native["contracts"]
    ), "own_cases": len(extra), "malformed_controls": len(malformed),
        "source_faults": len(faults), "verify_decisions": len(verify)}))
    return 0 if check else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--verify-source", type=Path, required=True)
    parser.add_argument("--verify-executable", type=Path, required=True)
    parser.add_argument("--run-ref", default="qualification-pending-review")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())

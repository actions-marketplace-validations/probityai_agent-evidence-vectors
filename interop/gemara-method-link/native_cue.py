"""Validate pinned Gemara documents with the official native CUE binary.

Schema acceptance is separate from method-link relationships. The historical
profile retains the recorded inputs; the current profile is a migration sample.
Neither author-produced profile authenticates an actor or proves execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast

import method_link

Record = dict[str, Any]
LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).parent


class NativeError(ValueError):
    """A pin, runtime, or observed schema verdict did not meet the contract."""


def _sha256(path: Path) -> str:
    """Return the digest of the exact on-disk file bytes.

    Parameters
    ----------
    path : Path
        File whose bytes form the pin, without text or newline normalization.

    Returns
    -------
    str
        Lowercase SHA-256 hexadecimal digest."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _file(root: Path, relative: str) -> Path:
    """Resolve a pinned file inside the corpus boundary.

    Parameters
    ----------
    root : Path
        Corpus directory; symlink resolution cannot move a file outside it.
    relative : str
        Manifest path interpreted only relative to that directory.

    Returns
    -------
    Path
        Existing resolved file inside the corpus.

    Raises
    ------
    NativeError
        The resolved path escapes the corpus or the file is missing."""
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise NativeError(f"path escapes corpus: {relative}")
    if not candidate.is_file():
        raise NativeError(f"missing pinned file: {relative}")
    return candidate


def _json(path: Path) -> Record:
    """Read an object without accepting malformed or non-object JSON.

    Parameters
    ----------
    path : Path
        Verified file containing a manifest, input bundle, or expectation record.

    Returns
    -------
    dict
        Parsed JSON object. Nested values retain their original JSON types.

    Raises
    ------
    NativeError
        Reading or JSON parsing fails, or the root value is not an object."""
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise NativeError(f"cannot read JSON: {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise NativeError(f"JSON must be an object: {path.name}")
    return cast(Record, value)


def _verify_pins(root: Path, entries: list[Record]) -> None:
    """Verify source and input hashes before native execution.

    Parameters
    ----------
    root : Path
        Corpus boundary used for every resolved path.
    entries : list
        Source, input and expectation declarations with SHA-256 pins. Sources
        also carry upstream Git blob identities, checked against the same bytes.

    Raises
    ------
    NativeError
        A file is absent, escapes the corpus, or differs from either digest.
    """
    for entry in entries:
        path = _file(root, entry["path"])
        if _sha256(path) != entry["sha256"]:
            raise NativeError(f"digest mismatch: {entry['path']}")
        if "git_blob" in entry:
            data = path.read_bytes()
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if blob != entry["git_blob"]:
                raise NativeError(f"Git blob mismatch: {entry['path']}")


def _verify_profile(
    profile: Record, manifest: Record, expected: Record, cases: list[Record]
) -> None:
    """Require complete package and case declarations for a native profile.

    Parameters
    ----------
    profile : dict
        Exact package files and whether original recorded inputs are included.
    manifest : dict
        Verified native source and additional-case declarations.
    expected : dict
        Separate native verdicts; no expectations are passed to the CUE command.
    cases : list
        Original cases already checked by their unchanged corpus loader.

    Raises
    ------
    NativeError
        A package path is invalid or duplicated, or expected case coverage is
        missing or duplicated. This checks coverage, not schema acceptance.
    """
    source_by_id = {entry["id"]: entry for entry in manifest["sources"]}
    names = [source_by_id[identifier]["name"] for identifier in profile["schema_sources"]]
    if len(set(names)) != len(names):
        raise NativeError(f"duplicate package file: {profile['id']}")
    if any(Path(name).is_absolute() or ".." in Path(name).parts for name in names):
        raise NativeError(f"invalid package file name: {profile['id']}")
    actual_ids = [case["id"] for case in cases] if profile["recorded_cases"] else []
    actual_ids.extend(
        case["id"] for case in manifest["additional_cases"] if case["profile"] == profile["id"]
    )
    declared = [case["id"] for case in expected["profiles"][profile["id"]]]
    if (
        len(set(actual_ids)) != len(actual_ids)
        or len(set(declared)) != len(declared)
        or set(actual_ids) != set(declared)
    ):
        raise NativeError(f"expected case declarations differ: {profile['id']}")


def load_contract(root: Path) -> tuple[Record, Record, list[Record]]:
    """Verify original and native inputs before constructing a CUE package.

    Parameters
    ----------
    root : Path
        The complete published method-link corpus directory. Original inputs
        remain bound to their recorded manifest, including their license pin.

    Returns
    -------
    tuple
        Native manifest, expected native verdicts, and original recorded cases.

    Raises
    ------
    NativeError
        A file, digest, package name, or case declaration differs. Missing
        inputs cannot be counted as successful or expected-rejection evidence.
    """
    manifest = _json(_file(root, "native/MANIFEST.json"))
    if _sha256(_file(root, "MANIFEST.json")) != manifest["original_manifest_sha256"]:
        raise NativeError("original manifest digest mismatch")
    try:
        _, cases = method_link.load_cases(root)
    except method_link.CorpusError as exc:
        raise NativeError(str(exc)) from exc
    _verify_pins(
        root,
        [
            *manifest["sources"],
            *manifest["additional_cases"],
            manifest["expected"],
            manifest["license"],
        ],
    )
    expected = _json(_file(root, manifest["expected"]["path"]))
    source_ids = [entry["id"] for entry in manifest["sources"]]
    if len(set(source_ids)) != len(source_ids):
        raise NativeError("duplicate source declaration")
    profile_ids = {profile["id"] for profile in manifest["profiles"]}
    if set(expected["profiles"]) != profile_ids:
        raise NativeError("expected profile declarations differ")
    if any(case["profile"] not in profile_ids for case in manifest["additional_cases"]):
        raise NativeError("case names an unknown profile")
    for profile in manifest["profiles"]:
        _verify_profile(profile, manifest, expected, cases)
    return manifest, expected, cases


def _invoke(cue: Path, arguments: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run native CUE with explicit arguments and bounded execution.

    Parameters
    ----------
    cue : Path
        Verified release executable, passed directly without a shell.
    arguments : list of str
        Command arguments; input documents never become shell text.
    cwd : Path
        Assembled schema package directory, or the version-command directory.

    Returns
    -------
    subprocess.CompletedProcess
        Exit status and decoded standard streams for contract checks.

    Raises
    ------
    NativeError
        The executable cannot run or the command exceeds its timeout."""
    try:
        return subprocess.run(
            [str(cue), *arguments],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NativeError(f"CUE command did not run: {exc}") from exc


def validate_tool(cue: Path, tool: Record) -> None:
    """Require the official binary and its recorded native runtime.

    Parameters
    ----------
    cue : Path
        Official release executable; alternative builds are refused even when
        they print the same version because their bytes are not the release pin.
    tool : dict
        Manifest fields for the binary digest, CUE version, and Go runtime.

    Raises
    ------
    NativeError
        The binary is absent, differs, cannot execute, or reports another runtime.
    """
    if not cue.is_file():
        raise NativeError(f"missing CUE binary: {cue}")
    if _sha256(cue) != tool["binary_sha256"]:
        raise NativeError("CUE binary digest mismatch")
    proc = _invoke(cue, ["version"], ROOT)
    required = [
        f"cue version {tool['version']}",
        f"Go version {tool['go_version']}",
        f"GOARCH {tool['goarch']}",
        f"GOOS {tool['goos']}",
    ]
    if proc.returncode != 0 or proc.stderr or any(token not in proc.stdout for token in required):
        raise NativeError("CUE version or runtime differs from the pin")


def _vet(cue: Path, schema: Path, definition: str, document: Path, expected: Record) -> Record:
    """Validate a document and distinguish rejection from infrastructure error.

    Parameters
    ----------
    cue : Path
        Verified native executable.
    schema : Path
        Complete package already compiled with positive upstream sentinels.
    definition : str
        Definition selected explicitly for this document.
    document : Path
        JSON or YAML input; expectations are never supplied to CUE.
    expected : dict
        Observed acceptance and required diagnostic markers. Rejections must have
        the expected status and paths; arbitrary command failures cannot satisfy it.

    Returns
    -------
    dict
        Actual acceptance and the diagnostic markers verified in native output.

    Raises
    ------
    NativeError
        Exit status, streams, acceptance, or rejection diagnostics differ."""
    proc = _invoke(cue, ["vet", "-c", "-d", definition, ".", str(document)], schema)
    if proc.returncode not in (0, 1) or proc.stdout:
        raise NativeError(f"unexpected CUE command result: {definition}: {proc.returncode}")
    valid = proc.returncode == 0
    markers = expected["error_contains"]
    if valid != expected["valid"]:
        raise NativeError(f"schema verdict drift: {definition}: {document.name}: {proc.stderr}")
    if valid and proc.stderr:
        raise NativeError(f"CUE warning on a passing document: {proc.stderr}")
    if not valid and (not markers or any(marker not in proc.stderr for marker in markers)):
        raise NativeError(f"schema rejection diagnostic drift: {definition}: {proc.stderr}")
    return {"valid": valid, "diagnostic_markers": markers}


def _case_documents(
    cue: Path, schema: Path, bundle: Record, expected: Record
) -> tuple[Record, list[Record]]:
    """Validate the log and each separately bound Policy in a bundle.

    Parameters
    ----------
    cue : Path
        Verified native executable.
    schema : Path
        Profile package where a temporary document file can be written.
    bundle : dict
        One complete log and all caller-supplied Policy bindings. Bindings are not
        resolved remotely or unified with one another.
    expected : dict
        Native log and Policy verdicts covering exactly those bindings.

    Returns
    -------
    tuple
        Log verdict and individual Policy verdicts, each retaining its binding.

    Raises
    ------
    NativeError
        A Policy binding is omitted from expectations or a native verdict differs."""
    if set(bundle["policies"]) != set(expected["policies"]):
        raise NativeError("expected Policy bindings differ")
    document = schema / "document.json"
    document.write_text(json.dumps(bundle["log"], sort_keys=True) + "\n", encoding="utf-8")
    log_result = _vet(cue, schema, "#EvaluationLog", document, expected["log"])
    policies = []
    for binding, policy in sorted(bundle["policies"].items()):
        document.write_text(json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8")
        result = _vet(cue, schema, "#Policy", document, expected["policies"][binding])
        policies.append({"binding": binding, **result})
    return log_result, policies


def _build_schema(
    root: Path, directory: Path, profile: Record, manifest: Record, cue: Path
) -> Path:
    """Assemble the exact profile package and prove it is usable.

    Parameters
    ----------
    root : Path
        Corpus directory whose source pins have already been verified.
    directory : Path
        Isolated temporary parent for the package. No source file is modified.
    profile : dict
        Exact upstream package members and positive sentinel declarations.
    manifest : dict
        Verified source paths, package names, and revision provenance.
    cue : Path
        Verified native executable.

    Returns
    -------
    Path
        Complete compiled package that accepts its positive upstream fixtures.

    Raises
    ------
    NativeError
        Compilation or a sentinel fails, preventing infrastructure failure from
        being mistaken for expected document rejection."""
    source_by_id = {source["id"]: source for source in manifest["sources"]}
    schema: Path = directory / str(profile["id"])
    schema.mkdir()
    for identifier in profile["schema_sources"]:
        source = source_by_id[identifier]
        destination = schema / source["name"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_file(root, source["path"]), destination)
    compiled = _invoke(cue, ["vet", "-c=false", "."], schema)
    if compiled.returncode or compiled.stdout or compiled.stderr:
        raise NativeError(f"schema package did not compile: {compiled.stderr}")
    for sentinel in profile["sentinels"]:
        _vet(
            cue,
            schema,
            sentinel["definition"],
            _file(root, sentinel["path"]),
            {"valid": True, "error_contains": []},
        )
    return schema


def _profile_cases(
    root: Path, profile: Record, manifest: Record, recorded: list[Record]
) -> list[Record]:
    """Select recorded or migration inputs without altering either revision.

    Parameters
    ----------
    root : Path
        Corpus directory containing the verified input files.
    profile : dict
        Revision and declaration of whether recorded inputs are included.
    manifest : dict
        Additional-case identities, origins, paths, and byte digests.
    recorded : list
        Original bundles loaded under their unchanged manifest.

    Returns
    -------
    list
        Input bundles with their case identities, origins, and original byte pins."""
    cases: list[Record] = []
    if profile["recorded_cases"]:
        original = _json(root / "MANIFEST.json")
        pins = {case["id"]: case["sha256"] for case in original["cases"]}
        cases.extend(
            {
                "id": case["id"],
                "input": case["input"],
                "origin": "recorded",
                "sha256": pins[case["id"]],
            }
            for case in recorded
        )
    cases.extend(
        {**case, "input": _json(_file(root, case["path"]))}
        for case in manifest["additional_cases"]
        if case["profile"] == profile["id"]
    )
    return cases


def _run_case(cue: Path, schema: Path, case: Record, answer: Record) -> Record:
    """Record native verdicts and the explicitly separate identity comparison.

    Parameters
    ----------
    cue : Path
        Verified native executable.
    schema : Path
        Compiled profile package with successful positive sentinels.
    case : dict
        Pinned input bundle and its revision-specific case metadata.
    answer : dict
        Observed native verdicts. Only the historical identity case also declares
        the original reader's shape-error expectation.

    Returns
    -------
    dict
        Individual native document verdicts and, where declared, the author reader
        comparison. That comparison is not an independently written reader.

    Raises
    ------
    NativeError
        A native verdict or the recorded reader identity comparison differs."""
    log_result, policies = _case_documents(cue, schema, case["input"], answer)
    row = {
        "id": case["id"],
        "origin": case["origin"],
        "case_sha256": case["sha256"],
        "log": log_result,
        "policies": policies,
    }
    if "reader_shape_errors" in answer:
        reader = method_link.check_links(case["input"])
        if reader["shape_errors"] != answer["reader_shape_errors"]:
            raise NativeError("reader identity comparison drift")
        row["reader_comparison"] = reader
    return row


def run(root: Path, cue: Path) -> Record:
    """Reproduce native schema verdicts without changing any reader answer.

    Parameters
    ----------
    root : Path
        Corpus directory containing the original recorded inputs and separately
        versioned native migration inputs. No document is rewritten or fetched.
    cue : Path
        Official Linux AMD64 CUE executable named by the native tool pin.

    Returns
    -------
    dict
        Deterministic author-produced evidence containing each Policy binding
        and log verdict. Native acceptance does not resolve their relationships.

    Raises
    ------
    NativeError
        Integrity, runtime, compilation, positive sentinel, or observed schema
        evidence differs. An unrelated failure cannot satisfy a rejected case.
    """
    root, cue = root.resolve(), cue.resolve()
    manifest, expected, recorded = load_contract(root)
    validate_tool(cue, manifest["tool"])
    profiles = []
    with tempfile.TemporaryDirectory(prefix="gemara-native-cue-") as temporary:
        for profile in manifest["profiles"]:
            schema = _build_schema(root, Path(temporary), profile, manifest, cue)
            answers = {case["id"]: case for case in expected["profiles"][profile["id"]]}
            rows = [
                _run_case(cue, schema, case, answers[case["id"]])
                for case in _profile_cases(root, profile, manifest, recorded)
            ]
            profiles.append(
                {"id": profile["id"], "schema_revision": profile["schema_revision"], "cases": rows}
            )
    return {
        "status": manifest["status"],
        "tool": manifest["tool"],
        "original_manifest_sha256": manifest["original_manifest_sha256"],
        "native_manifest_sha256": _sha256(root / "native/MANIFEST.json"),
        "expected_sha256": manifest["expected"]["sha256"],
        "profiles": profiles,
    }


def separate_reports(report: Record) -> dict[str, Record]:
    """Separate recorded, migration, and identity evidence with derived totals.

    Parameters
    ----------
    report : dict
        Successfully reproduced native profile report. Each bound Policy has
        already been validated independently; bindings are not silently merged.

    Returns
    -------
    dict
        Reports keyed by filename, each with totals computed from its actual
        document verdicts. Expected schema rejections are not conformance faults.
    """
    historical, current = report["profiles"]
    groups = [
        ("historical-result.json", historical, "recorded"),
        ("current-result.json", current, None),
        ("identity-result.json", historical, "identity-comparison"),
    ]
    common = {key: value for key, value in report.items() if key != "profiles"}
    results = {}
    for filename, profile, origin in groups:
        rows = [row for row in profile["cases"] if origin is None or row["origin"] == origin]
        policies = [policy for row in rows for policy in row["policies"]]
        logs = [row["log"] for row in rows]
        documents = [*policies, *logs]
        results[filename] = {
            **common,
            "profile": profile["id"],
            "schema_revision": profile["schema_revision"],
            "cases": rows,
            "totals": {
                "cases": len(rows),
                "policies": len(policies),
                "logs": len(logs),
                "documents": len(documents),
                "accepted": sum(doc["valid"] for doc in documents),
                "rejected": sum(not doc["valid"] for doc in documents),
            },
            "rejected_logs": [row["id"] for row in rows if not row["log"]["valid"]],
        }
    return results


def main() -> int:
    """Run the native contract and emit reproducible profile evidence.

    Returns
    -------
    int
        Success after every pin and verdict check, or failure after logging the
        exact cause. Expected schema rejections remain successful contract checks;
        missing tools and unrelated failures are never reported as passing.

    Notes
    -----
    The executable path is required. Optional output writes separate reports while
    standard output retains the combined JSON record."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--cue", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    arguments = parser.parse_args()
    try:
        report = run(arguments.root, arguments.cue)
        if arguments.output_dir is not None:
            arguments.output_dir.mkdir(parents=True, exist_ok=True)
            for filename, evidence in separate_reports(report).items():
                (arguments.output_dir / filename).write_text(
                    json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
    except (NativeError, KeyError, TypeError, OSError) as exc:
        LOGGER.error("native CUE validation failed: %s", exc)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

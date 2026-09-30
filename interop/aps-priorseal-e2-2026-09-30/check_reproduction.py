"""Reproduce the pinned E2 reports and preserve their stated limits."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn, cast

LOGGER = logging.getLogger(__name__)
SUITE = Path(__file__).resolve().parent
ROW_COUNT = 96
REFERENCE_TIME = "2026-09-19T10:05:00.000Z"
STATES = frozenset({"pass", "fail", "inconclusive", "not-exercised", "void"})
CAUSE_STATES = frozenset({"inconclusive", "not-exercised", "void"})
CAUSES = frozenset(
    {
        "not_applicable",
        "disabled_by_policy",
        "unsupported_input",
        "resource_exhausted",
        "failed",
        "unavailable",
        "out_of_scope",
        "withheld",
        "evidence-does-not-hold",
        "integrity-failure",
        "availability-failure",
        "precondition-unsatisfiable",
    }
)
CAUSE_RULE = "cause required on inconclusive, not-exercised and void; absent on pass and fail"
CONTROL_OUTCOMES: dict[str, dict[str, Any]] = {
    "signature-invalid": {"killed": True, "targetedFlips": 1},
    "wrong-key": {"killed": True, "targetedFlips": 1},
    "altered-authorization": {"killed": True, "targetedFlips": 1},
    "altered-authorization-rehashed": {"killed": False, "targetedFlips": 0},
    "decision-ref-unbound": {"killed": True, "targetedFlips": 2},
    "positive-control": {"verdict": "caught"},
    "inert-control": {"verdict": "inert"},
}
REHASHED_CHANGES = [
    {
        "input": "priorseal/over",
        "claim": "e2.aps_call_vs_signed_call",
        "twin": "pass",
        "variant": "fail",
    },
    {
        "input": "priorseal/over",
        "claim": "e2.exact_call_vs_observation",
        "twin": "fail",
        "variant": "pass",
    },
]


class ReproductionError(RuntimeError):
    """A report or output path violates the pinned reproduction contract."""


def fail(message: str) -> NoReturn:
    """Log a contract refusal and raise :class:`ReproductionError` with that text."""
    LOGGER.error(message)
    raise ReproductionError(message)


def require(condition: bool, message: str) -> None:
    """Require one condition; fail records the refusal and raises ReproductionError."""
    if not condition:
        fail(message)


def _object(value: object, message: str) -> dict[str, Any]:
    """Require a JSON object before callers access its fields."""
    require(isinstance(value, dict), message)
    return cast(dict[str, Any], value)


def _identity(row: dict[str, Any], report_name: str) -> tuple[str, str]:
    """Require claim identifiers before de-duplication or scope checks."""
    values = (row.get("input"), row.get("claim"))
    require(
        all(isinstance(value, str) and bool(value) for value in values),
        f"{report_name} contains a claim without string input and claim identifiers.",
    )
    return cast(tuple[str, str], values)


def _vocabulary_members(value: object, expected: frozenset[str], label: str) -> None:
    """Require each declared vocabulary member exactly once."""
    require(
        isinstance(value, list) and all(isinstance(member, str) for member in value),
        f"RESULTS.json vocabulary {label} must be a list of strings.",
    )
    members = cast(list[str], value)
    require(
        len(members) == len(expected) and set(members) == expected,
        f"RESULTS.json changed the closed {label} vocabulary.",
    )


def validate_row(value: object) -> None:
    """Require identifiers, a closed state, and a cause exactly when needed.

    Args:
        value: A decoded RESULTS.json row, checked before field access.

    Raises:
        ReproductionError: The row shape or state/cause is invalid. fail logs
            the same diagnostic at ERROR.
    """
    row = _object(value, "RESULTS.json rows must be JSON objects.")
    _identity(row, "RESULTS.json")
    state = row.get("state")
    require(
        isinstance(state, str) and state in STATES,
        "RESULTS.json contains an unknown state.",
    )
    if state not in CAUSE_STATES:
        require("cause" not in row, "RESULTS.json contains a state with an invalid cause.")
        return
    cause = row.get("cause")
    require(
        isinstance(cause, str) and cause in CAUSES,
        "RESULTS.json contains a state with an invalid cause.",
    )


def validate_results(value: object) -> None:
    """Check coverage, vocabulary, time, and unexercised PriorSeal signatures.

    Args:
        value: Decoded e2check.py output. compare_bytes checks byte parity later.

    Raises:
        ReproductionError: Report shape, coverage, vocabulary, or scope changed.
    """
    report = _object(value, "RESULTS.json must contain a JSON object.")
    vocabulary = _object(report.get("vocabulary"), "RESULTS.json requires a vocabulary object.")
    _vocabulary_members(vocabulary.get("states"), STATES, "states")
    _vocabulary_members(vocabulary.get("causes"), CAUSES, "causes")
    require(vocabulary.get("rule") == CAUSE_RULE, "RESULTS.json changed the cause rule.")
    rows = report.get("rows")
    require(isinstance(rows, list), "RESULTS.json rows must be a list.")
    rows = cast(list[Any], rows)
    require(len(rows) == ROW_COUNT, "RESULTS.json must contain 96 rows.")
    for row in rows:
        validate_row(row)
    keys = [_identity(row, "RESULTS.json") for row in rows]
    require(len(set(keys)) == ROW_COUNT, "RESULTS.json contains duplicate claim rows.")
    require(
        report.get("referenceTime") == REFERENCE_TIME,
        "RESULTS.json changed the reference time.",
    )
    signatures = {
        row["input"]: (row["state"], row.get("cause"))
        for row in rows
        if row["claim"] == "ps.signatures"
    }
    require(
        signatures
        == dict.fromkeys(("priorseal/within", "priorseal/over"), ("not-exercised", "out_of_scope")),
        "RESULTS.json must leave both PriorSeal signature claims not-exercised.",
    )


def _control_changes(value: object) -> list[dict[str, Any]]:
    """Validate changed-claim records without importing the original checker."""
    require(isinstance(value, list), "NEGATIVES.json changed must be a list.")
    changes = cast(list[dict[str, Any]], value)
    for value in changes:
        row = _object(value, "NEGATIVES.json changed entries must be JSON objects.")
        _identity(row, "NEGATIVES.json")
        require(
            all(
                isinstance(row.get(key), str) and row[key] in STATES for key in ("twin", "variant")
            ),
            "NEGATIVES.json changed contains an unknown state.",
        )
    return changes


def _control(value: object) -> dict[str, Any]:
    """Check one named control before indexing its outcome."""
    case = _object(value, "NEGATIVES.json cases must be JSON objects.")
    name = case.get("name")
    require(
        isinstance(name, str) and bool(name),
        "NEGATIVES.json controls require a non-empty string name.",
    )
    _control_changes(case.get("changed"))
    return case


def _control_outcome(case: dict[str, Any], expected: dict[str, Any]) -> None:
    """Compare outcomes with strict types so booleans cannot stand in for counts."""
    name = case["name"]
    require(
        all(
            type(case.get(key)) is type(value) and case[key] == value
            for key, value in expected.items()
        ),
        f"NEGATIVES.json changed the outcome of {name}.",
    )


def validate_controls(value: object) -> None:
    """Preserve seven controls and the surviving rehashed signature negative.

    Args:
        value: Decoded build_and_run.py output. compare_bytes checks all fields.

    Raises:
        ReproductionError: Control coverage, report shape, or an outcome changed.
    """
    report = _object(value, "NEGATIVES.json must contain a JSON object.")
    require(
        type(report.get("baselineRows")) is int and report["baselineRows"] == ROW_COUNT,
        "NEGATIVES.json changed baselineRows.",
    )
    cases = report.get("cases")
    require(isinstance(cases, list), "NEGATIVES.json cases must be a list.")
    cases = cast(list[Any], cases)
    checked = [_control(case) for case in cases]
    by_name = {case["name"]: case for case in checked}
    require(
        len(cases) == len(CONTROL_OUTCOMES) and set(by_name) == set(CONTROL_OUTCOMES),
        "NEGATIVES.json must contain each of the seven named controls exactly once.",
    )
    for name, expected in CONTROL_OUTCOMES.items():
        _control_outcome(by_name[name], expected)
    require(
        by_name["inert-control"]["changed"] == [],
        "NEGATIVES.json changed a claim under the inert control.",
    )
    require(
        bool(by_name["positive-control"]["changed"]),
        "NEGATIVES.json positive control must change at least one claim.",
    )
    require(
        by_name["altered-authorization-rehashed"]["changed"] == REHASHED_CHANGES,
        "NEGATIVES.json changed the surviving rehashed negative's cross-checks.",
    )


def compare_bytes(expected: Path, actual: Path) -> None:
    """Require byte equality and log both SHA-256 digests on a mismatch.

    Neither path is written. Missing or unreadable files raise a logged
    ReproductionError, as does any difference, including formatting.
    """
    try:
        expected_bytes, actual_bytes = expected.read_bytes(), actual.read_bytes()
    except OSError as error:
        fail(f"Could not compare {expected.name}: {error}")
    if expected_bytes != actual_bytes:
        LOGGER.error(
            "%s: committed SHA-256 %s; reproduced SHA-256 %s",
            expected.name,
            hashlib.sha256(expected_bytes).hexdigest(),
            hashlib.sha256(actual_bytes).hexdigest(),
        )
        fail(f"{expected.name} differs from the committed output.")


def _resolve(path: Path) -> Path:
    """Resolve aliases before checking containment, refusing symlink loops."""
    try:
        return path.resolve()
    except (OSError, RuntimeError) as error:
        fail(f"Could not resolve {path}: {error}")


def _overlap(first: Path, second: Path) -> bool:
    """Return whether either resolved directory contains the other."""
    return first.is_relative_to(second) or second.is_relative_to(first)


def _output_target(path: Path, output: Path) -> None:
    """Refuse aliases that could redirect writes or variant deletion."""
    require(not path.is_symlink(), "Generated output paths must not be symbolic links.")
    require(
        _resolve(path).is_relative_to(output),
        "Generated output paths must stay inside the output directory.",
    )
    if path.is_file():
        require(path.stat().st_nlink == 1, "Generated output files must not have hard links.")


def validate_paths(inputs: Path, output: Path) -> tuple[Path, Path]:
    """Resolve paths and keep writes and variant deletion away from source data.

    Args:
        inputs: Existing directory containing the hash-checked inputs.
        output: Report and variant directory outside inputs and the suite.
            Generated targets cannot redirect writes or share file inodes.

    Returns:
        Resolved input and output paths for reproduce.

    Raises:
        ReproductionError: A path is missing, overlapping, or redirects writes.
    """
    inputs, output = _resolve(inputs), _resolve(output)
    require(inputs.is_dir(), "The input path must be an existing directory.")
    require(not _overlap(inputs, output), "Input and output directories must not overlap.")
    require(
        not _overlap(_resolve(SUITE), output),
        "The output directory must not overlap the committed E2 suite.",
    )
    require(not output.exists() or output.is_dir(), "The output path must be a directory.")
    for name in ("RESULTS.json", "NEGATIVES.json", "variants"):
        _output_target(output / name, output)
    for name in CONTROL_OUTCOMES:
        _output_target(output / "variants" / name, output)
    return inputs, output


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse repeated JSON keys rather than silently taking their last value."""
    result: dict[str, Any] = {}
    for name, value in pairs:
        require(name not in result, f"Report JSON contains a duplicate key: {name}.")
        result[name] = value
    return result


def read_report(path: Path) -> dict[str, Any]:
    """Decode one UTF-8 JSON object without silently accepting duplicate keys.

    Invalid JSON, unreadable files, and non-object roots produce logged
    ReproductionError diagnostics for main.
    """
    try:
        report = json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError):
        fail(f"{path.name} must contain valid UTF-8 JSON.")
    except OSError as error:
        fail(f"Could not read {path.name}: {error}")
    return _object(report, f"{path.name} must contain a JSON object.")


def run_report(script: str, arguments: list[str], destination: Path) -> dict[str, Any]:
    """Run a checker with the active interpreter and retain its complete stdout.

    The caller first checks destination paths with validate_paths. Execution
    uses no shell and has a 120-second timeout. Subprocess failures and invalid
    output become logged ReproductionError refusals.
    """
    try:
        with destination.open("wb") as stream:
            subprocess.run(
                [sys.executable, str(SUITE / script), *arguments],
                check=True,
                stdout=stream,
                timeout=120,
            )
    except subprocess.TimeoutExpired:
        fail(f"{script} exceeded the 120-second timeout.")
    except subprocess.CalledProcessError as error:
        fail(f"{script} exited with status {error.returncode}.")
    except OSError as error:
        fail(f"Could not execute {script} or write {destination.name}: {error}")
    return read_report(destination)


def reproduce(inputs: Path, output: Path) -> None:
    """Recompute both reports, validate their scope, and compare committed bytes.

    requirements-ci.txt pins the dependency environment by version/hash.
    The gate preserves the original checkers and their offline fixture scope.

    Args:
        inputs: Inputs fetched and SHA-256 checked by fetch_inputs.sh.
        output: Destination checked by validate_paths. Committed reports stay
            read-only; generated outputs never replace them.
    """
    inputs, output = validate_paths(inputs, output)
    output.mkdir(parents=True, exist_ok=True)
    pins = str(SUITE / "pins.json")
    results = run_report("e2check.py", [str(inputs), pins], output / "RESULTS.json")
    validate_results(results)
    negatives = run_report(
        "build_and_run.py",
        [str(inputs), pins, str(SUITE / "e2check.py"), str(output / "variants")],
        output / "NEGATIVES.json",
    )
    validate_controls(negatives)
    for name in ("RESULTS.json", "NEGATIVES.json"):
        compare_bytes(SUITE / name, output / name)
    LOGGER.info("96 claim rows and seven controls reproduced byte for byte.")


def main() -> int:
    """Run the gate; return zero on parity and one on a logged refusal or failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=SUITE / "inputs")
    parser.add_argument("--output", type=Path, default=SUITE.parents[1] / ".build/e2-reproduction")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        reproduce(args.inputs, args.output)
    except ReproductionError:
        return 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        LOGGER.error("E2 reproduction could not complete: %s", error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Refusal tests for the E2 gate, using committed reports as the baseline."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import check_reproduction as gate
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

COMMITTED_SUITE = gate.SUITE
PROPERTY_SETTINGS = settings(
    max_examples=30,
    derandomize=True,
    database=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
BAD_VALUES = [None, False, 1, 1.5, "", [], {}]


@pytest.fixture(autouse=True)
def isolated_suite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Separate protected paths from pytest's temporary root on every platform."""
    suite = tmp_path / "reference" / "suite"
    suite.mkdir(parents=True)
    monkeypatch.setattr(gate, "SUITE", suite)


@pytest.fixture
def results() -> dict[str, Any]:
    """Load a fresh copy of the committed 96-row report for each test."""
    return json.loads((COMMITTED_SUITE / "RESULTS.json").read_bytes())


@pytest.fixture
def controls() -> dict[str, Any]:
    """Load a fresh copy of all seven committed negative/control outcomes."""
    return json.loads((COMMITTED_SUITE / "NEGATIVES.json").read_bytes())


@pytest.fixture
def inputs(tmp_path: Path) -> Path:
    """Make a real input directory for isolated path and orchestration tests."""
    path = tmp_path / "inputs"
    path.mkdir()
    return path


def refused(
    function: Callable[..., Any],
    *arguments: Any,
    message: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Require one exact exception diagnostic and the matching ERROR record."""
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger=gate.LOGGER.name):
        with pytest.raises(gate.ReproductionError, match=f"^{re.escape(message)}$") as caught:
            function(*arguments)
    assert str(caught.value) == message
    assert caplog.messages[-1] == message
    assert caplog.records[-1].levelno == logging.ERROR


class TestReportValidation:
    class TestPassingCases:
        def test_committed_reports_preserve_the_ceiling(
            self,
            results: dict[str, Any],
            controls: dict[str, Any],
        ) -> None:
            gate.validate_results(results)
            gate.validate_controls(controls)
            signatures = [row for row in results["rows"] if row["claim"] == "ps.signatures"]
            assert len(signatures) == 2
            assert {(row["state"], row["cause"]) for row in signatures} == {
                ("not-exercised", "out_of_scope")
            }
            rehashed = next(
                case
                for case in controls["cases"]
                if case["name"] == "altered-authorization-rehashed"
            )
            assert rehashed["killed"] is False
            assert rehashed["targetedFlips"] == 0

        @given(
            state=st.sampled_from(sorted(gate.STATES)), cause=st.sampled_from(sorted(gate.CAUSES))
        )
        def test_declared_state_cause_combinations(self, state: str, cause: str) -> None:
            row = {"input": "fixture", "claim": "bounded.claim", "state": state}
            if state in gate.CAUSE_STATES:
                row["cause"] = cause
            gate.validate_row(row)

    class TestFailingCases:
        @pytest.mark.parametrize("value", BAD_VALUES[:-1])
        @pytest.mark.parametrize(
            ("validator", "name"),
            [(gate.validate_results, "RESULTS.json"), (gate.validate_controls, "NEGATIVES.json")],
        )
        def test_non_object_roots(
            self,
            validator: Callable[..., Any],
            name: str,
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            refused(validator, value, message=f"{name} must contain a JSON object.", caplog=caplog)

        @pytest.mark.parametrize("value", BAD_VALUES)
        def test_malformed_rows_container(
            self,
            results: dict[str, Any],
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            results["rows"] = value
            message = "RESULTS.json rows must be a list."
            if isinstance(value, list):
                message = "RESULTS.json must contain 96 rows."
            refused(gate.validate_results, results, message=message, caplog=caplog)

        @pytest.mark.parametrize("value", BAD_VALUES[:-1])
        def test_malformed_row(
            self,
            results: dict[str, Any],
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            results["rows"][0] = value
            refused(
                gate.validate_results,
                results,
                message="RESULTS.json rows must be JSON objects.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("field", ["input", "claim"])
        @pytest.mark.parametrize("value", BAD_VALUES)
        def test_bad_row_identity(
            self,
            results: dict[str, Any],
            field: str,
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            results["rows"][0][field] = value
            refused(
                gate.validate_results,
                results,
                message="RESULTS.json contains a claim without string input and claim identifiers.",
                caplog=caplog,
            )

        @PROPERTY_SETTINGS
        @given(state=st.text().filter(lambda value: value not in gate.STATES))
        def test_unknown_state(self, state: str, caplog: pytest.LogCaptureFixture) -> None:
            refused(
                gate.validate_row,
                {"input": "i", "claim": "c", "state": state},
                message="RESULTS.json contains an unknown state.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("value", BAD_VALUES)
        def test_unhashable_or_non_string_state(
            self,
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            refused(
                gate.validate_row,
                {"input": "i", "claim": "c", "state": value},
                message="RESULTS.json contains an unknown state.",
                caplog=caplog,
            )

        @PROPERTY_SETTINGS
        @given(cause=st.text().filter(lambda value: value not in gate.CAUSES))
        def test_unknown_cause(self, cause: str, caplog: pytest.LogCaptureFixture) -> None:
            refused(
                gate.validate_row,
                {"input": "i", "claim": "c", "state": "void", "cause": cause},
                message="RESULTS.json contains a state with an invalid cause.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("state", sorted(gate.STATES))
        @pytest.mark.parametrize("cause", BAD_VALUES)
        def test_missing_or_invalid_cause(
            self,
            state: str,
            cause: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            refused(
                gate.validate_row,
                {"input": "i", "claim": "c", "state": state, "cause": cause},
                message="RESULTS.json contains a state with an invalid cause.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("state", sorted(gate.CAUSE_STATES))
        def test_cause_required(self, state: str, caplog: pytest.LogCaptureFixture) -> None:
            refused(
                gate.validate_row,
                {"input": "i", "claim": "c", "state": state},
                message="RESULTS.json contains a state with an invalid cause.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("label", ["states", "causes"])
        @pytest.mark.parametrize("value", [None, {}, "", [None], [{}]])
        def test_malformed_vocabulary(
            self,
            results: dict[str, Any],
            label: str,
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            results["vocabulary"][label] = value
            refused(
                gate.validate_results,
                results,
                message=f"RESULTS.json vocabulary {label} must be a list of strings.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("label", ["states", "causes"])
        @pytest.mark.parametrize("change", ["missing", "duplicate", "unknown"])
        def test_vocabulary_is_closed(
            self,
            results: dict[str, Any],
            label: str,
            change: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            values = results["vocabulary"][label]
            replacement = {"missing": [], "duplicate": [values[0]], "unknown": ["invented"]}
            results["vocabulary"][label] = values[:-1] + replacement[change]
            refused(
                gate.validate_results,
                results,
                message=f"RESULTS.json changed the closed {label} vocabulary.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("field", ["vocabulary", "referenceTime"])
        def test_missing_metadata(
            self,
            results: dict[str, Any],
            field: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            del results[field]
            message = {
                "vocabulary": "RESULTS.json requires a vocabulary object.",
                "referenceTime": "RESULTS.json changed the reference time.",
            }[field]
            refused(gate.validate_results, results, message=message, caplog=caplog)

        def test_changed_cause_rule(
            self,
            results: dict[str, Any],
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            results["vocabulary"]["rule"] = "cause optional"
            refused(
                gate.validate_results,
                results,
                message="RESULTS.json changed the cause rule.",
                caplog=caplog,
            )

        def test_duplicate_rows(
            self,
            results: dict[str, Any],
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            results["rows"][-1] = results["rows"][0].copy()
            refused(
                gate.validate_results,
                results,
                message="RESULTS.json contains duplicate claim rows.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("state", ["pass", "fail", "void"])
        def test_signature_verification_cannot_be_implied(
            self,
            results: dict[str, Any],
            state: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            row = next(row for row in results["rows"] if row["claim"] == "ps.signatures")
            row["state"] = state
            row.pop("cause")
            if state == "void":
                row["cause"] = "integrity-failure"
            refused(
                gate.validate_results,
                results,
                message="RESULTS.json must leave both PriorSeal signature claims not-exercised.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("name", sorted(gate.CONTROL_OUTCOMES))
        @pytest.mark.parametrize("change", ["missing", "duplicate"])
        def test_each_control_is_required_once(
            self,
            controls: dict[str, Any],
            name: str,
            change: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            case = next(case for case in controls["cases"] if case["name"] == name)
            controls["cases"].remove(case)
            if change == "duplicate":
                controls["cases"].append(controls["cases"][0].copy())
            refused(
                gate.validate_controls,
                controls,
                message=(
                    "NEGATIVES.json must contain each of the seven named controls exactly once."
                ),
                caplog=caplog,
            )

        @pytest.mark.parametrize("field", ["baselineRows", "cases"])
        @pytest.mark.parametrize("value", BAD_VALUES + [96.0])
        def test_control_report_schema(
            self,
            controls: dict[str, Any],
            field: str,
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            controls[field] = value
            message = "NEGATIVES.json changed baselineRows."
            if field == "cases":
                message = "NEGATIVES.json cases must be a list."
            if field == "cases" and isinstance(value, list):
                message = (
                    "NEGATIVES.json must contain each of the seven named controls exactly once."
                )
            refused(gate.validate_controls, controls, message=message, caplog=caplog)

        @pytest.mark.parametrize("value", BAD_VALUES[:-1])
        def test_control_entry_schema(
            self,
            controls: dict[str, Any],
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            controls["cases"][0] = value
            refused(
                gate.validate_controls,
                controls,
                message="NEGATIVES.json cases must be JSON objects.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("value", BAD_VALUES)
        def test_control_name_schema(
            self,
            controls: dict[str, Any],
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            controls["cases"][0]["name"] = value
            refused(
                gate.validate_controls,
                controls,
                message="NEGATIVES.json controls require a non-empty string name.",
                caplog=caplog,
            )

        @pytest.mark.parametrize(("field", "value"), [("killed", 1), ("targetedFlips", True)])
        def test_control_outcomes_have_strict_types(
            self,
            controls: dict[str, Any],
            field: str,
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            controls["cases"][0][field] = value
            refused(
                gate.validate_controls,
                controls,
                message="NEGATIVES.json changed the outcome of signature-invalid.",
                caplog=caplog,
            )

        def test_rehashed_negative_must_survive(
            self,
            controls: dict[str, Any],
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            case = next(
                case
                for case in controls["cases"]
                if case["name"] == "altered-authorization-rehashed"
            )
            case["killed"] = True
            refused(
                gate.validate_controls,
                controls,
                message="NEGATIVES.json changed the outcome of altered-authorization-rehashed.",
                caplog=caplog,
            )

        @pytest.mark.parametrize(
            "name", ["inert-control", "positive-control", "altered-authorization-rehashed"]
        )
        def test_control_changes_preserve_the_measured_result(
            self,
            controls: dict[str, Any],
            name: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            case = next(case for case in controls["cases"] if case["name"] == name)
            case["changed"] = []
            if name == "inert-control":
                case["changed"] = gate.REHASHED_CHANGES
            messages = {
                "inert-control": "NEGATIVES.json changed a claim under the inert control.",
                "positive-control": (
                    "NEGATIVES.json positive control must change at least one claim."
                ),
                "altered-authorization-rehashed": (
                    "NEGATIVES.json changed the surviving rehashed negative's cross-checks."
                ),
            }
            refused(gate.validate_controls, controls, message=messages[name], caplog=caplog)

        @pytest.mark.parametrize("value", [None, "", {}, [None], [{}]])
        def test_changed_claims_have_a_schema(
            self,
            controls: dict[str, Any],
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            controls["cases"][0]["changed"] = value
            message = "NEGATIVES.json changed must be a list."
            if value == [None]:
                message = "NEGATIVES.json changed entries must be JSON objects."
            if value == [{}]:
                message = (
                    "NEGATIVES.json contains a claim without string input and claim identifiers."
                )
            refused(gate.validate_controls, controls, message=message, caplog=caplog)

        @pytest.mark.parametrize("field", ["twin", "variant"])
        @pytest.mark.parametrize("value", ["unknown", None, []])
        def test_changed_claim_states_are_closed(
            self,
            controls: dict[str, Any],
            field: str,
            value: object,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            controls["cases"][0]["changed"][0][field] = value
            refused(
                gate.validate_controls,
                controls,
                message="NEGATIVES.json changed contains an unknown state.",
                caplog=caplog,
            )


class TestOutputPaths:
    class TestPassingCases:
        def test_separate_destination(
            self,
            inputs: Path,
            tmp_path: Path,
        ) -> None:
            output = tmp_path / "output"
            assert gate.validate_paths(inputs, output) == (inputs.resolve(), output.resolve())
            assert not output.exists()

        def test_existing_generated_directory_can_be_reused(
            self,
            inputs: Path,
            tmp_path: Path,
        ) -> None:
            output = tmp_path / "output"
            (output / "variants" / "signature-invalid").mkdir(parents=True)
            (output / "RESULTS.json").write_text("{}\n")
            assert gate.validate_paths(inputs, output) == (inputs.resolve(), output.resolve())

    class TestFailingCases:
        @pytest.mark.parametrize("relation", ["same", "inside", "outside"])
        def test_input_output_overlap(
            self,
            inputs: Path,
            relation: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output = {"same": inputs, "inside": inputs / "generated", "outside": inputs.parent}
            refused(
                gate.validate_paths,
                inputs,
                output[relation],
                message="Input and output directories must not overlap.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("relation", ["same", "inside", "outside"])
        def test_output_cannot_overlap_committed_suite(
            self,
            inputs: Path,
            relation: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output = {
                "same": gate.SUITE,
                "inside": gate.SUITE / "generated",
                "outside": gate.SUITE.parent,
            }
            refused(
                gate.validate_paths,
                inputs,
                output[relation],
                message="The output directory must not overlap the committed E2 suite.",
                caplog=caplog,
            )

        def test_missing_input_directory(
            self,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            refused(
                gate.validate_paths,
                tmp_path / "absent",
                tmp_path / "output",
                message="The input path must be an existing directory.",
                caplog=caplog,
            )

        def test_output_is_a_file(
            self,
            inputs: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output = tmp_path / "output"
            output.write_bytes(b"retain")
            refused(
                gate.validate_paths,
                inputs,
                output,
                message="The output path must be a directory.",
                caplog=caplog,
            )
            assert output.read_bytes() == b"retain"

        def test_output_alias_resolves_to_inputs(
            self,
            inputs: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            alias = tmp_path / "alias"
            alias.symlink_to(inputs, target_is_directory=True)
            refused(
                gate.validate_paths,
                inputs,
                alias,
                message="Input and output directories must not overlap.",
                caplog=caplog,
            )

        @pytest.mark.parametrize(
            "name", ["RESULTS.json", "NEGATIVES.json", "variants", "variants/signature-invalid"]
        )
        def test_generated_targets_cannot_redirect(
            self,
            inputs: Path,
            tmp_path: Path,
            name: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output = tmp_path / "output"
            target = output / name
            target.parent.mkdir(parents=True)
            target.symlink_to(inputs, target_is_directory=True)
            refused(
                gate.validate_paths,
                inputs,
                output,
                message="Generated output paths must not be symbolic links.",
                caplog=caplog,
            )
            assert inputs.is_dir()

        @pytest.mark.parametrize("name", ["RESULTS.json", "NEGATIVES.json"])
        def test_shared_report_inode_is_not_overwritten(
            self,
            inputs: Path,
            tmp_path: Path,
            name: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            original = inputs / "original.json"
            original.write_bytes(b"retain")
            output = tmp_path / "output"
            output.mkdir()
            (output / name).hardlink_to(original)
            refused(
                gate.validate_paths,
                inputs,
                output,
                message="Generated output files must not have hard links.",
                caplog=caplog,
            )
            assert original.read_bytes() == b"retain"


class TestReportExecution:
    class TestPassingCases:
        @PROPERTY_SETTINGS
        @given(data=st.binary(max_size=1024))
        def test_byte_comparison_is_read_only(self, tmp_path: Path, data: bytes) -> None:
            expected, actual = tmp_path / "expected", tmp_path / "actual"
            expected.write_bytes(data)
            actual.write_bytes(data)
            gate.compare_bytes(expected, actual)
            assert expected.read_bytes() == actual.read_bytes() == data

        def test_subprocess_uses_interpreter_and_timeout(
            self,
            tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            destination = tmp_path / "RESULTS.json"
            calls = []

            def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
                calls.append((command, kwargs["check"], kwargs["timeout"]))
                kwargs["stdout"].write(b'{"rows": []}\n')
                return subprocess.CompletedProcess(command, 0)

            monkeypatch.setattr(gate.subprocess, "run", run)
            assert gate.run_report("e2check.py", ["input path"], destination) == {"rows": []}
            assert calls == [
                ([sys.executable, str(gate.SUITE / "e2check.py"), "input path"], True, 120)
            ]

    class TestFailingCases:
        @PROPERTY_SETTINGS
        @given(data=st.binary(max_size=1024))
        def test_one_byte_difference_is_refused(
            self,
            tmp_path: Path,
            data: bytes,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            expected, actual = tmp_path / "RESULTS.json", tmp_path / "actual"
            expected.write_bytes(data)
            actual.write_bytes(data + b"\0")
            refused(
                gate.compare_bytes,
                expected,
                actual,
                message="RESULTS.json differs from the committed output.",
                caplog=caplog,
            )
            assert caplog.messages[-2] == (
                f"RESULTS.json: committed SHA-256 {hashlib.sha256(data).hexdigest()}; "
                f"reproduced SHA-256 {hashlib.sha256(data + b'\0').hexdigest()}"
            )
            assert expected.read_bytes() == data

        @pytest.mark.parametrize("payload", [b"not JSON", b"\xff", b""])
        def test_report_must_be_utf8_json(
            self,
            tmp_path: Path,
            payload: bytes,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            path = tmp_path / "RESULTS.json"
            path.write_bytes(payload)
            refused(
                gate.read_report,
                path,
                message="RESULTS.json must contain valid UTF-8 JSON.",
                caplog=caplog,
            )

        @pytest.mark.parametrize("payload", [b"[]", b"null", b"false", b"1", b'""'])
        def test_report_must_be_an_object(
            self,
            tmp_path: Path,
            payload: bytes,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            path = tmp_path / "RESULTS.json"
            path.write_bytes(payload)
            refused(
                gate.read_report,
                path,
                message="RESULTS.json must contain a JSON object.",
                caplog=caplog,
            )

        @pytest.mark.parametrize(
            "payload",
            [
                b'{"rows": [], "rows": []}',
                b'{"rows": [{"state": "pass", "state": "fail"}]}',
            ],
        )
        def test_duplicate_json_keys_are_refused(
            self,
            tmp_path: Path,
            payload: bytes,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            path = tmp_path / "RESULTS.json"
            path.write_bytes(payload)
            key = "rows" if payload.startswith(b'{"rows": []') else "state"
            refused(
                gate.read_report,
                path,
                message=f"Report JSON contains a duplicate key: {key}.",
                caplog=caplog,
            )

        @pytest.mark.parametrize(
            ("error", "message"),
            [
                (subprocess.CalledProcessError(3, ["checker"]), "e2check.py exited with status 3."),
                (
                    subprocess.TimeoutExpired(["checker"], 120),
                    "e2check.py exceeded the 120-second timeout.",
                ),
                (
                    OSError("access denied"),
                    "Could not execute e2check.py or write RESULTS.json: access denied",
                ),
            ],
        )
        def test_execution_errors_are_logged_refusals(
            self,
            tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch,
            error: Exception,
            message: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            def run(*_args: Any, **_kwargs: Any) -> None:
                raise error

            monkeypatch.setattr(gate.subprocess, "run", run)
            refused(
                gate.run_report,
                "e2check.py",
                [],
                tmp_path / "RESULTS.json",
                message=message,
                caplog=caplog,
            )


class TestReproduction:
    class TestPassingCases:
        def test_orchestration_preserves_committed_reports(
            self,
            inputs: Path,
            tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            suite, output = tmp_path / "suite", tmp_path / "output"
            suite.mkdir()
            originals = {}
            for name in ("RESULTS.json", "NEGATIVES.json"):
                originals[name] = (COMMITTED_SUITE / name).read_bytes()
                (suite / name).write_bytes(originals[name])
            monkeypatch.setattr(gate, "SUITE", suite)
            calls = []

            def report(script: str, arguments: list[str], destination: Path) -> dict[str, Any]:
                calls.append((script, arguments))
                destination.write_bytes(originals[destination.name])
                return json.loads(originals[destination.name])

            monkeypatch.setattr(gate, "run_report", report)
            with caplog.at_level(logging.INFO, logger=gate.LOGGER.name):
                gate.reproduce(inputs, output)
            assert [call[0] for call in calls] == ["e2check.py", "build_and_run.py"]
            assert calls[1][1][-1] == str(output / "variants")
            assert (
                caplog.messages[-1] == "96 claim rows and seven controls reproduced byte for byte."
            )
            assert all((suite / name).read_bytes() == data for name, data in originals.items())

    class TestFailingCases:
        def test_unsafe_paths_fail_before_a_checker_or_write(
            self,
            inputs: Path,
            monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            calls = []
            monkeypatch.setattr(gate, "run_report", lambda *args: calls.append(args))
            output = inputs / "output"
            refused(
                gate.reproduce,
                inputs,
                output,
                message="Input and output directories must not overlap.",
                caplog=caplog,
            )
            assert calls == []
            assert not output.exists()

        def test_results_refusal_stops_before_negative_generation(
            self,
            results: dict[str, Any],
            inputs: Path,
            tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            results["rows"] = []
            calls = []

            def report(script: str, _arguments: list[str], _destination: Path) -> dict[str, Any]:
                calls.append(script)
                return results

            monkeypatch.setattr(gate, "run_report", report)
            refused(
                gate.reproduce,
                inputs,
                tmp_path / "output",
                message="RESULTS.json must contain 96 rows.",
                caplog=caplog,
            )
            assert calls == ["e2check.py"]

        def test_cli_returns_failure_for_a_contract_refusal(
            self,
            monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            def reproduce(_inputs: Path, _output: Path) -> None:
                gate.fail("fixture refusal")

            monkeypatch.setattr(gate, "reproduce", reproduce)
            monkeypatch.setattr(sys, "argv", ["check_reproduction.py"])
            assert gate.main() == 1
            assert caplog.messages[-1] == "fixture refusal"

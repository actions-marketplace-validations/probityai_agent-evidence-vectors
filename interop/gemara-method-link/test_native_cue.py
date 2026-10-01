"""Native profile reproduction and refusal controls."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import method_link
import native_cue
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

ROOT = Path(__file__).parent


@pytest.fixture(scope="module")
def cue() -> Path:
    """Resolve the executable supplied by the pinned native CI installation.

    Returns
    -------
    Path
        Native release binary path. Absence is a test failure, never a skip.
    """
    value = os.environ.get("GEMARA_CUE_BINARY")
    if not value:
        pytest.fail("GEMARA_CUE_BINARY must name the pinned native CUE binary")
    return Path(value)


@pytest.fixture(scope="module")
def report(cue: Path) -> dict[str, Any]:
    """Execute the native profiles once for the observed-verdict tests.

    Parameters
    ----------
    cue : Path
        Executable whose integrity is checked by the native runner.

    Returns
    -------
    dict
        Actual native verdicts for all original and migration inputs.
    """
    return native_cue.run(ROOT, cue)


def _copy(tmp_path: Path) -> Path:
    """Copy corpus inputs into an isolated refusal-test directory.

    Parameters
    ----------
    tmp_path : Path
        External test workspace. Generated output and bytecode are excluded.

    Returns
    -------
    Path
        Complete copy whose pins can be altered without touching the source.
    """
    root = tmp_path / "corpus"
    shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".build", "__pycache__"))
    return root


@pytest.fixture(scope="module")
def current_schema(cue: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the verified current package outside the repository for properties.

    Parameters
    ----------
    cue : Path
        Native executable with verified release bytes and runtime.
    tmp_path_factory : pytest.TempPathFactory
        External test workspace, keeping generated inputs out of type coverage.

    Returns
    -------
    Path
        Complete current CUE package after compilation and positive sentinels.
    """
    manifest, _, _ = native_cue.load_contract(ROOT)
    native_cue.validate_tool(cue, manifest["tool"])
    return native_cue._build_schema(
        ROOT,
        tmp_path_factory.mktemp("current-native-schema"),
        manifest["profiles"][1],
        manifest,
        cue,
    )


class TestNativeCue:
    """Pinned native evidence and controls against false passing results."""

    class TestPassingCases:
        """Schema results match the explicitly versioned observations."""

        def test_native_report_is_byte_reproducible(self, report: dict[str, Any]) -> None:
            for filename, evidence in native_cue.separate_reports(report).items():
                serialized = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()
                assert serialized == (ROOT / "native" / filename).read_bytes()

        def test_schema_and_reader_relationships_are_separate(self, report: dict[str, Any]) -> None:
            historical = report["profiles"][0]
            rows = {case["id"]: case for case in historical["cases"]}
            assert rows["unknown-method"]["log"]["valid"] is True
            original = json.loads((ROOT / "cases/unknown-method.json").read_bytes())
            reader = method_link.check_links(original["input"])
            assert reader["rows"][0]["method"] == "unknown_method"
            assert rows["same-name-other-executor-id"]["log"]["valid"] is True
            assert rows["two-method-conflict-retained"]["log"]["valid"] is True
            duplicate = rows["duplicate-full-reference"]
            assert duplicate["log"]["valid"] is False
            assert duplicate["reader_comparison"]["shape_errors"] == []
            assert [row["method"] for row in duplicate["reader_comparison"]["rows"]] == [
                "matched",
                "matched",
            ]

        def test_current_migration_contract_is_observed(self, report: dict[str, Any]) -> None:
            current = report["profiles"][1]
            assert {case["id"]: case["log"]["valid"] for case in current["cases"]} == {
                "execution-with-plan": True,
                "plan-without-method": False,
                "execution-without-plan": True,
                "settings-without-method-or-plan": True,
                "executor-mismatch-preserved": True,
                "duplicate-full-reference": False,
            }
            assert all(policy["valid"] for case in current["cases"] for policy in case["policies"])

        @settings(max_examples=20, deadline=None)
        @given(identifier=st.text(max_size=30))
        def test_unplanned_method_text_does_not_claim_policy_resolution(
            self, cue: Path, current_schema: Path, identifier: str
        ) -> None:
            bundle = json.loads(
                (ROOT / "native/cases/current-settings-without-method-or-plan.json").read_bytes()
            )
            assessment = bundle["log"]["evaluations"][0]["assessment-logs"][0]
            assessment["execution-context"]["method-id"] = identifier
            expected = {
                "log": {"valid": True, "error_contains": []},
                "policies": {
                    name: {"valid": True, "error_contains": []} for name in bundle["policies"]
                },
            }
            log, policies = native_cue._case_documents(cue, current_schema, bundle, expected)
            assert log["valid"] is True
            assert all(policy["valid"] for policy in policies)

    class TestFailingCases:
        """Broken inputs, incomplete coverage, and unrelated errors fail closed."""

        @pytest.mark.parametrize(
            "relative",
            [
                "native/schema/metadata.cue",
                "native/current/evaluationlog.cue",
                "native/cases/current-execution-with-plan.json",
                "native/EXPECTED.json",
            ],
        )
        def test_changed_native_file_is_refused(self, tmp_path: Path, relative: str) -> None:
            root = _copy(tmp_path)
            path = root / relative
            path.write_bytes(path.read_bytes() + b" ")
            with pytest.raises(native_cue.NativeError) as error:
                native_cue.load_contract(root)
            assert str(error.value) == f"digest mismatch: {relative}"

        def test_changed_original_fixture_is_refused(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            root = _copy(tmp_path)
            path = root / "cases/matched-method.json"
            path.write_bytes(path.read_bytes() + b" ")
            message = "fixture digest mismatch: cases/matched-method.json"
            with caplog.at_level(logging.ERROR, logger="method_link"):
                with pytest.raises(native_cue.NativeError) as error:
                    native_cue.load_contract(root)
            assert str(error.value) == message
            assert caplog.messages == [message]

        def test_original_manifest_revision_cannot_be_changed(self, tmp_path: Path) -> None:
            root = _copy(tmp_path)
            path = root / "MANIFEST.json"
            path.write_bytes(path.read_bytes() + b" ")
            with pytest.raises(native_cue.NativeError) as error:
                native_cue.load_contract(root)
            assert str(error.value) == "original manifest digest mismatch"

        def test_native_path_cannot_escape_corpus(self, tmp_path: Path) -> None:
            root = _copy(tmp_path)
            path = root / "native/MANIFEST.json"
            manifest = json.loads(path.read_bytes())
            manifest["sources"][0]["path"] = "../outside.cue"
            path.write_text(json.dumps(manifest))
            with pytest.raises(native_cue.NativeError) as error:
                native_cue.load_contract(root)
            assert str(error.value) == "path escapes corpus: ../outside.cue"

        @pytest.mark.parametrize("edit", ["delete", "duplicate"])
        def test_expected_case_coverage_cannot_be_shortened_or_duplicated(
            self, tmp_path: Path, edit: str
        ) -> None:
            root = _copy(tmp_path)
            path = root / "native/EXPECTED.json"
            expected = json.loads(path.read_bytes())
            cases = expected["profiles"]["historical-1f"]
            if edit == "delete":
                cases.pop()
            else:
                cases.append(cases[0])
            path.write_text(json.dumps(expected))
            manifest_path = root / "native/MANIFEST.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["expected"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            with pytest.raises(native_cue.NativeError) as error:
                native_cue.load_contract(root)
            assert str(error.value) == "expected case declarations differ: historical-1f"

        def test_missing_native_tool_is_a_failure(self, tmp_path: Path) -> None:
            manifest, _, _ = native_cue.load_contract(ROOT)
            with pytest.raises(native_cue.NativeError) as error:
                native_cue.validate_tool(tmp_path / "absent", manifest["tool"])
            assert str(error.value) == f"missing CUE binary: {tmp_path / 'absent'}"

        def test_alternate_binary_is_refused(self, tmp_path: Path) -> None:
            binary = tmp_path / "cue"
            binary.write_bytes(b"an unpinned executable")
            manifest, _, _ = native_cue.load_contract(ROOT)
            with pytest.raises(native_cue.NativeError) as error:
                native_cue.validate_tool(binary, manifest["tool"])
            assert str(error.value) == "CUE binary digest mismatch"

        def test_accept_all_native_results_cannot_pass(
            self, cue: Path, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            invoke = native_cue._invoke

            def accept_all(
                binary: Path, arguments: list[str], cwd: Path
            ) -> subprocess.CompletedProcess[str]:
                if arguments[0] == "vet":
                    return subprocess.CompletedProcess(arguments, 0, "", "")
                return invoke(binary, arguments, cwd)

            monkeypatch.setattr(native_cue, "_invoke", accept_all)
            with pytest.raises(native_cue.NativeError) as error:
                native_cue.run(ROOT, cue)
            assert str(error.value) == "schema verdict drift: #EvaluationLog: document.json: "

        def test_compiler_failure_cannot_count_as_document_rejection(
            self, cue: Path, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            invoke = native_cue._invoke

            def broken_package(
                binary: Path, arguments: list[str], cwd: Path
            ) -> subprocess.CompletedProcess[str]:
                if arguments == ["vet", "-c=false", "."]:
                    return subprocess.CompletedProcess(arguments, 1, "", "unresolved schema symbol")
                return invoke(binary, arguments, cwd)

            monkeypatch.setattr(native_cue, "_invoke", broken_package)
            with pytest.raises(native_cue.NativeError) as error:
                native_cue.run(ROOT, cue)
            assert str(error.value) == "schema package did not compile: unresolved schema symbol"

        def test_unrelated_native_error_is_not_an_expected_rejection(
            self, cue: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            def unrelated_error(
                binary: Path, arguments: list[str], cwd: Path
            ) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(arguments, 1, "", "tool runtime failure")

            monkeypatch.setattr(native_cue, "_invoke", unrelated_error)
            manifest, expected, _ = native_cue.load_contract(ROOT)
            answer = next(
                case
                for case in expected["profiles"][manifest["profiles"][0]["id"]]
                if case["id"] == "duplicate-assessment"
            )
            with pytest.raises(native_cue.NativeError) as error:
                native_cue._vet(
                    cue, tmp_path, "#EvaluationLog", tmp_path / "document.json", answer["log"]
                )
            assert (
                str(error.value)
                == "schema rejection diagnostic drift: #EvaluationLog: tool runtime failure"
            )

        def test_positive_warning_is_refused(
            self, cue: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            def warning(
                binary: Path, arguments: list[str], cwd: Path
            ) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(arguments, 0, "", "warning")

            monkeypatch.setattr(native_cue, "_invoke", warning)
            with pytest.raises(native_cue.NativeError) as error:
                native_cue._vet(
                    cue,
                    tmp_path,
                    "#Policy",
                    tmp_path / "document.json",
                    cast(dict[str, Any], {"valid": True, "error_contains": []}),
                )
            assert str(error.value) == "CUE warning on a passing document: warning"

        def test_cli_failure_logs_the_exact_reason(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
        ) -> None:
            missing = tmp_path / "absent-cue"
            monkeypatch.setattr(sys, "argv", ["native_cue.py", "--cue", str(missing)])
            message = f"native CUE validation failed: missing CUE binary: {missing}"
            with caplog.at_level(logging.ERROR, logger="native_cue"):
                assert native_cue.main() == 2
            assert caplog.messages == [message]

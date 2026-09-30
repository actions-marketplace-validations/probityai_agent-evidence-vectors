"""Conformance, mutation, and reader-contract checks for the draft profile."""

from copy import deepcopy
import json
import logging
from pathlib import Path
import shlex
import shutil
import sys

from hypothesis import given, strategies as st
import pytest

import method_link

ROOT = Path(__file__).parent
_, CASES = method_link.load_cases(ROOT)
BY_ID = {case["id"]: case for case in CASES}
PASS_IDS = {
    "matched-method",
    "omitted-executor-author-matches",
    "unconstrained-executor",
    "two-method-conflict-retained",
    "two-method-agreement",
    "unplanned-assessment",
}
PASS_CASES = [case for case in CASES if case["id"] in PASS_IDS]
FAIL_CASES = [case for case in CASES if case["id"] not in PASS_IDS]


def bundle(identifier: str = "matched-method") -> dict:
    """Return a fresh fixture input so tests cannot contaminate later cases."""
    return deepcopy(BY_ID[identifier]["input"])


def first_assessment(data: dict) -> dict:
    """Locate the first assessment in the single-control base fixture."""
    return data["log"]["evaluations"][0]["assessment-logs"][0]


class TestMethodLinkProfile:
    class TestPassingCases:
        @pytest.mark.parametrize("case", PASS_CASES, ids=lambda case: case["id"])
        def test_expected_findings_and_unchanged_input(self, case: dict) -> None:
            data = deepcopy(case["input"])
            before = deepcopy(data)
            assert method_link.check_links(data) == case["expected"]
            assert data == before

        @given(st.text(max_size=80))
        def test_display_name_does_not_change_id_comparison(self, name: str) -> None:
            data = bundle()
            first_assessment(data)["executor"]["name"] = name
            assert method_link.check_links(data) == BY_ID["matched-method"]["expected"]

        @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_", min_size=1, max_size=30))
        def test_renamed_method_resolves_only_with_matching_plan_input(self, identifier: str) -> None:
            data = bundle()
            identifier = "generated-" + identifier
            first_assessment(data)["plan-inputs"]["method-id"] = identifier
            data["policies"]["security-policy"]["adherence"]["assessment-plans"][0]["evaluation-methods"][0]["id"] = identifier
            assert method_link.check_links(data) == BY_ID["matched-method"]["expected"]

        def test_conflict_retains_both_events_without_selecting_a_winner(self) -> None:
            result = method_link.check_links(bundle("two-method-conflict-retained"))
            assert result["conflicts"] == [["e0.a0", "e0.a1"]]
            assert [row["reported_result"] for row in result["rows"]] == ["Passed", "Failed"]
            assert "winner" not in result

        def test_self_adapter_reproduces_corpus(self) -> None:
            command = shlex.join([sys.executable, str(ROOT / "method_link.py"), "--stdin"])
            report = method_link.run(ROOT, command)
            assert report["matched"] == report["total"] == 20

        def test_reader_receives_input_without_expected_answers(self, tmp_path: Path) -> None:
            capture = tmp_path / "received.json"
            reader = tmp_path / "capture_reader.py"
            reader.write_text(
                "import json,sys\n"
                "from pathlib import Path\n"
                f"sys.path.insert(0, {str(ROOT)!r})\n"
                "from method_link import check_links\n"
                "value=json.load(sys.stdin)\n"
                f"Path({str(capture)!r}).write_text(json.dumps(value))\n"
                "print(json.dumps(check_links(value)))\n",
                encoding="ascii",
            )
            command = shlex.join([sys.executable, str(reader)])
            result = method_link._adapter(command, bundle())
            assert result == BY_ID["matched-method"]["expected"]
            assert set(json.loads(capture.read_text())) == {"log", "policies"}

    class TestFailingCases:
        @pytest.mark.parametrize("case", FAIL_CASES, ids=lambda case: case["id"])
        def test_bad_link_or_shape_has_the_expected_finding(self, case: dict) -> None:
            assert method_link.check_links(case["input"]) == case["expected"]

        @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", max_size=30))
        def test_unknown_method_never_borrows_from_another_plan(self, suffix: str) -> None:
            data = bundle()
            method_id = "unselected-" + suffix
            first_assessment(data)["plan-inputs"]["method-id"] = method_id
            plans = data["policies"]["security-policy"]["adherence"]["assessment-plans"]
            other = deepcopy(plans[0])
            other["id"] = "AP-OTHER"
            other["evaluation-methods"][0]["id"] = method_id
            plans.append(other)
            assert method_link.check_links(data)["rows"][0]["method"] == "unknown_method"

        @given(st.text(max_size=80))
        def test_same_display_name_never_reconciles_different_executor_ids(self, name: str) -> None:
            data = bundle("same-name-other-executor-id")
            first_assessment(data)["executor"]["name"] = name
            methods = data["policies"]["security-policy"]["adherence"]["assessment-plans"][0]["evaluation-methods"]
            methods[0]["executor"]["name"] = name
            result = method_link.check_links(data)
            assert result["shape_errors"] == []
            assert result["rows"][0]["executor"] == "mismatch"
            assert result["rows"][0]["reported_result"] == "Passed"

        def test_accept_all_negative_control_is_rejected(self) -> None:
            command = shlex.join([sys.executable, str(ROOT / "controls/accept_all.py")])
            report = method_link.run(ROOT, command)
            assert report["matched"] < report["total"]
            by_id = {row["id"]: row for row in report["rows"]}
            for identifier in ["unknown-method", "swapped-method", "two-method-conflict-retained", "plan-without-inputs"]:
                assert by_id[identifier]["matches"] is False

        @pytest.mark.parametrize("path", ["cases/matched-method.json", "sources/evaluationlog.cue"])
        def test_changed_fixture_or_source_is_refused(self, tmp_path: Path, caplog: pytest.LogCaptureFixture, path: str) -> None:
            root = tmp_path / "corpus"
            shutil.copytree(ROOT, root)
            (root / path).write_bytes((root / path).read_bytes() + b" ")
            message = f"fixture digest mismatch: {path}"
            with caplog.at_level(logging.ERROR, logger=method_link.__name__):
                with pytest.raises(method_link.CorpusError, match=message):
                    method_link.load_cases(root)
            assert caplog.messages == [message]

        def test_manifest_path_cannot_escape_corpus(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            root = tmp_path / "corpus"
            shutil.copytree(ROOT, root)
            manifest_path = root / "MANIFEST.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["cases"][0]["path"] = "../outside.json"
            manifest_path.write_text(json.dumps(manifest))
            message = "fixture path escapes corpus: ../outside.json"
            with caplog.at_level(logging.ERROR, logger=method_link.__name__):
                with pytest.raises(method_link.CorpusError, match=r"fixture path escapes corpus: \.\./outside\.json"):
                    method_link.load_cases(root)
            assert caplog.messages == [message]

        def test_reader_failure_records_the_error(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            reader = tmp_path / "broken_reader.py"
            reader.write_text("import sys\nprint('reader failed', file=sys.stderr)\nraise SystemExit(7)\n")
            command = shlex.join([sys.executable, str(reader)])
            message = "adapter exited 7: reader failed"
            with caplog.at_level(logging.ERROR, logger=method_link.__name__):
                with pytest.raises(method_link.CorpusError, match=message):
                    method_link.run(ROOT, command)
            assert caplog.messages == [message]

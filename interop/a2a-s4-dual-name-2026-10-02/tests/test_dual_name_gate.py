"""Native signed controls and generated schema-context alias refusals."""

from __future__ import annotations

import copy
import json
import logging
import re
import shutil
from pathlib import Path

import pytest
from dual_name_gate import ROOT, SCHEMA, admit_with_policy, check_names
from hypothesis import given
from hypothesis import strategies as st
from retain_gate import PolicyError, admit, canonicalize, load_json
from run_dual_name import CASE_IDS, run

KEY = load_json((ROOT / "upstream/testkey_jwks.json").read_bytes())["keys"][0]
VECTORS = [load_json((ROOT / f"upstream/{case}.json").read_bytes()) for case in CASE_IDS]
ALIASES = [
    (message, field["json_name"], field["proto_name"])
    for message, fields in SCHEMA["messages"].items()
    for field in fields
    if field["json_name"] != field["proto_name"]
]


class TestDualNameGate:
    class TestPassingCases:
        @pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["id"])
        def test_retained_signature_axis(self, vector: dict) -> None:
            assert admit(vector["served_card"], KEY).admitted == (vector["id"] != "S4-REJECT-005")
            assert canonicalize(vector["served_card"]) == bytes.fromhex(
                vector["canonical_utf8_hex"]
            )

        def test_single_spelling_control_admits_without_mutation(self) -> None:
            candidate = copy.deepcopy(VECTORS[3]["served_card"])
            before = copy.deepcopy(candidate)
            assert admit_with_policy(candidate, KEY, "dual-name-refuse").admitted
            assert candidate == before

        @pytest.mark.parametrize("message,json_name,proto_name", ALIASES)
        @pytest.mark.parametrize("spelling", [0, 1])
        def test_single_null_spelling_is_unambiguous(
            self, message: str, json_name: str, proto_name: str, spelling: int
        ) -> None:
            check_names({(json_name, proto_name)[spelling]: None}, message)

        def test_unknown_and_struct_names_are_not_schema_aliases(self) -> None:
            candidate = {
                "x-future": {"inputModes": [], "input_modes": ["other"]},
                "capabilities": {
                    "extensions": [{"params": {"bearerFormat": "a", "bearer_format": "b"}}]
                },
            }
            before = copy.deepcopy(candidate)
            check_names(candidate)
            assert candidate == before
            assert json.loads(canonicalize(candidate)) == candidate

        def test_native_report_has_both_readings_and_exact_population(self) -> None:
            report = run()
            assert report["passed"]
            assert [item["id"] for item in report["results"]] == list(CASE_IDS)
            assert [
                item["readings"]["dual-name-tolerate"]["admitted"] for item in report["results"]
            ] == [True, True, True, True, False]
            assert [
                item["readings"]["dual-name-refuse"]["admitted"] for item in report["results"]
            ] == [False, False, False, True, False]

    class TestFailingCases:
        @pytest.mark.parametrize("vector", VECTORS[:3], ids=lambda vector: vector["id"])
        def test_signed_native_aliases_refuse_with_exact_reason(
            self, vector: dict, caplog: pytest.LogCaptureFixture
        ) -> None:
            reasons = {
                "S4-001": "dual schema names at $: defaultInputModes and default_input_modes",
                "S4-002": "dual schema names at $/skills/0: inputModes and input_modes",
                "S4-003": "dual schema names at $/securitySchemes/0/httpAuthSecurityScheme/0: "
                "bearerFormat and bearer_format",
            }
            message = reasons[vector["id"]]
            with (
                caplog.at_level(logging.WARNING),
                pytest.raises(PolicyError, match=f"^{re.escape(message)}$"),
            ):
                admit_with_policy(vector["served_card"], KEY, "dual-name-refuse")
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize("message,json_name,proto_name", ALIASES)
        def test_equal_null_aliases_refuse_in_every_schema_message(
            self, message: str, json_name: str, proto_name: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            reason = f"dual schema names at $: {json_name} and {proto_name}"
            with pytest.raises(PolicyError, match=f"^{re.escape(reason)}$"):
                check_names({json_name: None, proto_name: None}, message)
            assert caplog.messages[-1] == reason

        @given(st.sampled_from(ALIASES), st.booleans(), st.text(max_size=30))
        def test_value_and_member_order_cannot_hide_aliases(
            self, alias: tuple[str, str, str], reverse: bool, value: str
        ) -> None:
            message, json_name, proto_name = alias
            pairs = [(json_name, value), (proto_name, value)]
            candidate = dict(reversed(pairs) if reverse else pairs)
            reason = f"dual schema names at $: {json_name} and {proto_name}"
            with pytest.raises(PolicyError, match=f"^{re.escape(reason)}$"):
                check_names(candidate, message)

        @pytest.mark.parametrize(
            "candidate,reason",
            [
                ({"skills": {}}, "schema message array must be an array"),
                ({"securitySchemes": []}, "schema message map must be an object"),
                ({"skills": ["bad"]}, "schema message must be an object at $/skills/0"),
            ],
        )
        def test_wrong_message_shapes_refuse(
            self, candidate: dict, reason: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            with pytest.raises(PolicyError, match=f"^{re.escape(reason)}$"):
                check_names(candidate)
            assert caplog.messages[-1] == reason

        def test_unknown_policy_refuses(self, caplog: pytest.LogCaptureFixture) -> None:
            with pytest.raises(PolicyError, match="^unsupported dual-name policy$"):
                admit_with_policy(VECTORS[3]["served_card"], KEY, "normalize-first")
            assert caplog.messages[-1] == "unsupported dual-name policy"

        @pytest.mark.parametrize("name", ["schema-aliases.json", "upstream/S4-004.json"])
        def test_changed_source_refuses(
            self, name: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            shutil.copytree(ROOT, tmp_path / "s4")
            shutil.copytree(
                ROOT.parent / "a2a-s3-retain-2026-10-01", tmp_path / "a2a-s3-retain-2026-10-01"
            )
            (tmp_path / "s4" / name).write_text("changed")
            reason = f"source digest mismatch: {name}"
            with pytest.raises(PolicyError, match=f"^{re.escape(reason)}$"):
                run(tmp_path / "s4")
            assert caplog.messages[-1] == reason

        def test_extra_native_case_refuses(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            shutil.copytree(ROOT, tmp_path / "s4")
            (tmp_path / "s4/upstream/S4-EXTRA.json").write_text("{}")
            reason = "corpus membership differs from the frozen five-case set"
            with pytest.raises(PolicyError, match=f"^{reason}$"):
                run(tmp_path / "s4")
            assert caplog.messages[-1] == reason

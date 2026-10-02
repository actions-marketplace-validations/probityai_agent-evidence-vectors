"""Adversarial tests of JEP signatures, raw input and persistent acceptance."""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
import rfc8785
from adapter import exchange
from hypothesis import given, settings
from hypothesis import strategies as st
from run import differences, pinned_inputs
from state import accept, initialize, observe
from validator import PROFILE, SIGNATURE_CLASS, parse, produce, validate

ROOT = Path(__file__).parent
UPSTREAM = ROOT / "upstream"
MANIFEST = json.loads((UPSTREAM / "manifest.json").read_text())
KEYS = json.loads((UPSTREAM / "keys.json").read_text())
TEMPLATE = json.loads((UPSTREAM / "templates/J.json").read_text())


class TestValidator:
    class TestPassingCases:
        @pytest.mark.parametrize(
            "assertion", MANIFEST["assertions"], ids=lambda row: row["assertion_id"]
        )
        def test_pinned_native_assertions(self, assertion: dict) -> None:
            actual, _ = validate(
                (UPSTREAM / assertion["input"]).read_text(),
                json.loads((UPSTREAM / assertion["keys"]).read_text()),
            )
            errors = actual.get("errors", [])
            actual["error_code"] = errors[0]["code"] if errors else None
            assert differences(assertion["expected"], actual) == []

        @settings(max_examples=40)
        @given(text=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=80))
        def test_produced_unicode_claim_round_trip(self, text: str) -> None:
            event = copy.deepcopy(TEMPLATE)
            event["what"] = {"claim": text}
            produced = produce(event)
            result, parsed = validate(produced["event_json"], produced["keys"])
            assert result["status"] == "valid"
            assert parsed["what"] == event["what"]
            assert (
                result["event_hash"]
                == "sha256:" + hashlib.sha256(rfc8785.dumps(parsed)).hexdigest()
            )
            assert result["checks"]["actor_binding"] == "not_checked"
            assert result["checks"]["freshness"] == "not_checked"

        def test_original_byte_order_independent_hash(self) -> None:
            first, _ = validate((UPSTREAM / "vectors/J-basic.json").read_text(), KEYS)
            second, _ = validate((UPSTREAM / "vectors/J-reordered.json").read_text(), KEYS)
            assert first["event_hash"] == second["event_hash"]

    class TestFailingCases:
        @pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"what":{"a":1,"a":2}}'])
        def test_duplicate_members(self, raw: str) -> None:
            result, event = validate(raw, KEYS)
            assert result["checks"]["syntax"] == "fail"
            assert result["errors"][0]["code"] == "ERR_DUPLICATE_MEMBER"
            assert event is None

        @pytest.mark.parametrize("raw", ["NaN", "Infinity", "[]", "{}", "{", "null"])
        def test_invalid_input(self, raw: str) -> None:
            result, event = validate(raw, KEYS)
            assert result["status"] == "invalid"
            assert event is None

        def test_signature_tampering_logs_stable_reason(
            self, caplog: pytest.LogCaptureFixture
        ) -> None:
            with caplog.at_level("INFO"):
                result, event = validate(
                    (UPSTREAM / "vectors/tampered-claim.json").read_text(), KEYS
                )
            assert result["errors"][0]["code"] == "ERR_SIGNATURE_INVALID"
            assert event is None
            assert "JEP refusal ERR_SIGNATURE_INVALID: signature does not verify" in caplog.text

        def test_unknown_signed_field_is_in_preimage(self) -> None:
            produced = produce(TEMPLATE)
            event = json.loads(produced["event_json"])
            event["unmodeled"] = "cannot be silently dropped"
            result, _ = validate(json.dumps(event), produced["keys"])
            assert result["checks"]["cryptographic"] == "fail"

        def test_empty_test_trust_store_is_indeterminate(self) -> None:
            result, event = validate((UPSTREAM / "vectors/J-basic.json").read_text(), {})
            assert result["status"] == "indeterminate"
            assert event is None

        def test_modified_trust_bytes_refuse_before_execution(self, tmp_path: Path) -> None:
            import shutil

            source = tmp_path / "upstream"
            shutil.copytree(UPSTREAM, source)
            (source / "keys.json").write_text("{}")
            with pytest.raises(ValueError, match="JEP input digest mismatch: keys.json"):
                pinned_inputs(source)

        def test_unrecognized_profile(self) -> None:
            request = {
                "adapter_protocol": "jep-byoi/1",
                "operation": "validate",
                "profile": "undeclared",
                "signature_class": SIGNATURE_CLASS,
            }
            with pytest.raises(ValueError, match="unsupported JEP profile"):
                exchange(request)


class TestAcceptance:
    class TestPassingCases:
        def test_retry_and_resign_identity(self, tmp_path: Path) -> None:
            root = tmp_path / "state"
            initialize(root)
            first = parse((UPSTREAM / "vectors/J-basic.json").read_text())
            second = parse((UPSTREAM / "stateful/resigned.json").read_text())
            assert first["sig"] != second["sig"]
            assert accept(root, "a", first) == {"outcome": "accepted", "effect_applied": True}
            assert accept(root, "a", second) == {
                "outcome": "already_accepted",
                "effect_applied": False,
            }
            assert observe(root, "a") == 1

        def test_probe_reads_ledger_after_adapter_flags_are_discarded(self, tmp_path: Path) -> None:
            root = tmp_path / "state"
            initialize(root)
            event = parse((UPSTREAM / "vectors/J-basic.json").read_text())
            result = accept(root, "a", event)
            result["effect_applied"] = False
            assert observe(root, "a") == 1
            with sqlite3.connect(root / "acceptance.sqlite") as connection:
                connection.execute("DELETE FROM effects")
            assert observe(root, "a") == 0

    class TestFailingCases:
        def test_conflict_preserves_committed_effect_count(self, tmp_path: Path) -> None:
            root = tmp_path / "state"
            initialize(root)
            first = parse((UPSTREAM / "vectors/J-basic.json").read_text())
            conflict = parse((UPSTREAM / "stateful/conflict.json").read_text())
            accept(root, "a", first)
            assert accept(root, "a", conflict) == {"outcome": "rejected", "effect_applied": False}
            assert observe(root, "a") == 1

        def test_missing_state_never_claims_a_fresh_acceptance(self, tmp_path: Path) -> None:
            event = parse((UPSTREAM / "vectors/J-basic.json").read_text())
            assert accept(tmp_path, "a", event) == {
                "outcome": "indeterminate",
                "effect_applied": False,
            }
            with pytest.raises(sqlite3.OperationalError, match="unable to open database file"):
                observe(tmp_path, "a")

        def test_invalid_signature_never_consumes_identity(self, tmp_path: Path) -> None:
            root = tmp_path / "state"
            initialize(root)
            request = {
                "adapter_protocol": "jep-byoi/1",
                "operation": "validate",
                "mode": "acceptance",
                "profile": PROFILE,
                "signature_class": SIGNATURE_CLASS,
                "keys": KEYS,
                "state_dir": str(root),
                "acceptance_domain": "a",
                "event_json": (UPSTREAM / "vectors/tampered-claim.json").read_text(),
            }
            result = exchange(request)["result"]
            assert result["acceptance"] == {"outcome": "rejected", "effect_applied": False}
            assert observe(root, "a") == 0

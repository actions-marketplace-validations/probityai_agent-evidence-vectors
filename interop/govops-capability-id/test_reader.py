"""Authority, scope, raw-input and source-custody failure controls."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import qualify
from fixtures import AUTHORITY, PUBLIC, SYNTAX_ID, cases, request, wire
from govops_ids import Admitter, Refused, evaluate, fingerprint

HERE = Path(__file__).resolve().parent
ADMITTER = HERE / "admission/target/release/govops-jcs-admission"


class NativeCases(unittest.TestCase):
    def test_all_native_cases(self) -> None:
        self.assertTrue(ADMITTER.is_file(), "build the native admission command before testing")
        for row in cases():
            with self.subTest(case=row["name"]):
                policy = Admitter(ADMITTER, row.get("profile", "ijson-integers"), row.get("max_depth", 32), row.get("max_bytes", 1048576))
                result = evaluate(row["request"], policy, qualify.trust(row), row.get("expected_authority", AUTHORITY))
                for key, expected in row["expected"].items():
                    self.assertEqual(result.get(key), expected)

    def test_input_cannot_install_its_own_trust(self) -> None:
        value = request()
        value["trusted_keys"] = {AUTHORITY: PUBLIC.hex()}
        result = evaluate(wire(value), Admitter(ADMITTER), {}, AUTHORITY)
        self.assertEqual(result["reason"], "UntrustedAuthority")

    def test_same_descriptor_does_not_collapse_distinct_calls(self) -> None:
        results = []
        for call in ("fixture:call:one", "fixture:call:two"):
            value = request()
            value["route"] = "ingestion"
            value["invocation"]["invocation_id"] = call
            results.append(evaluate(wire(value), Admitter(ADMITTER)))
        self.assertEqual(results[0]["descriptor"]["syntax_id"], results[1]["descriptor"]["syntax_id"])
        self.assertNotEqual(results[0]["identities"], results[1]["identities"])
        self.assertEqual({r["authority"] for r in results}, {"not-verified"})

    def test_syntax_identity_preserves_unicode_normalization_distinctions(self) -> None:
        base = '{"action":"invoke","resource":{"id":"%s"}}'
        left = fingerprint((base % "\u00e9").encode(), Admitter(ADMITTER))
        right = fingerprint((base % "e\u0301").encode(), Admitter(ADMITTER))
        self.assertNotEqual(left["syntax_id"], right["syntax_id"])

    def test_whitespace_is_raw_identity_only(self) -> None:
        value = request()
        text = value["invocation"]["descriptor_text"]
        left = fingerprint(text.encode(), Admitter(ADMITTER))
        right = fingerprint((" \n" + text + " \n").encode(), Admitter(ADMITTER))
        self.assertEqual(left["syntax_id"], SYNTAX_ID)
        self.assertEqual(left["syntax_id"], right["syntax_id"])
        self.assertNotEqual(left["raw_sha256"], right["raw_sha256"])


class FailureControls(unittest.TestCase):
    def test_source_tampering_is_refused(self) -> None:
        manifest = qualify.verify_sources()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for group in ("historical", "rawAdmission"):
                for entry in manifest[group]["files"]:
                    destination = root / entry["retainedPath"]
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes((qualify.REPO / entry["retainedPath"]).read_bytes())
            with patch.object(qualify, "REPO", root):
                qualify.verify_sources()
                altered = root / manifest["rawAdmission"]["files"][0]["retainedPath"]
                altered.write_bytes(altered.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "source changed"):
                    qualify.verify_sources()

    def test_admitter_absence_does_not_pass(self) -> None:
        result = evaluate(wire(request()), Admitter(HERE / ".build/missing-admitter"), {AUTHORITY: PUBLIC}, AUTHORITY)
        self.assertEqual(result["reason"], "AdmitterUnavailable")

    def test_admitter_protocol_failures_do_not_pass(self) -> None:
        outputs = [
            b"null",
            b"{}",
            b'{"status":"accepted","canonical_hex":"zz"}',
            b'{"status":"accepted","canonical_hex":""}',
            b'{"status":"accepted","canonical_hex":"7b7d","error_class":"DuplicateMember"}',
        ]
        for raw in outputs:
            with (
                self.subTest(output=raw),
                patch("govops_ids.reader.subprocess.run", return_value=subprocess.CompletedProcess([], 0, raw, b"")),
            ):
                with self.assertRaises(Refused) as refused:
                    Admitter(ADMITTER).admit(b"{}")
                self.assertEqual(refused.exception.reason, "AdmitterProtocol")

    def test_failed_admitter_and_timeout_do_not_pass(self) -> None:
        with patch("govops_ids.reader.subprocess.run", return_value=subprocess.CompletedProcess([], 1, b"{}", b"failure")):
            with self.assertRaises(Refused) as refused:
                Admitter(ADMITTER).admit(b"{}")
            self.assertEqual(refused.exception.reason, "AdmitterFailed")
        with patch("govops_ids.reader.subprocess.run", side_effect=subprocess.TimeoutExpired("admitter", 20)):
            with self.assertRaises(Refused) as refused:
                Admitter(ADMITTER).admit(b"{}")
            self.assertEqual(refused.exception.reason, "AdmitterUnavailable")

    def test_accept_all_reader_is_caught(self) -> None:
        row = next(r for r in cases() if r["name"] == "controls/invalid-signature")
        false = json.dumps({"verdict": "bound", "target_effect": "not-observed"}).encode()
        actual = qualify.subprocess.run

        def substitute(command, **options):
            if command[0] == "accept-all":
                return subprocess.CompletedProcess(command, 0, false, b"")
            return actual(command, **options)

        with patch("qualify.subprocess.run", side_effect=substitute):
            result = qualify.run_case(row, Path("accept-all"), ADMITTER, {}, HERE)
        self.assertFalse(result["matched"])
        self.assertFalse(result["api_cli_equal"])


if __name__ == "__main__":
    unittest.main()

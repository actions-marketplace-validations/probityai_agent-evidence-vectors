"""Boundary and mutation checks for the optional offline AgentID profile."""

from __future__ import annotations

import base64
import copy
import json
import re
from pathlib import Path
from typing import Any

import check_result
import pytest
import reader
import run
from hypothesis import given
from hypothesis import strategies as st

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"
RAW = tuple(
    (FIXTURES / name).read_bytes() for name in ("positive.raw.json", "request.json", "jwks.json")
)


def encode64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def encode(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def changed_header(**fields: Any) -> bytes:
    att = json.loads(RAW[0])
    parts = att["jws"].split(".")
    header = reader.load_json(reader.decode64(parts[0]))
    header.update(fields)
    parts[0] = encode64(encode(header))
    att["jws"] = ".".join(parts)
    return encode(att)


def arguments(destination: Path, request: Path | None = None) -> list[str]:
    return [
        "--attestation",
        str(FIXTURES / "positive.raw.json"),
        "--request",
        str(request or FIXTURES / "request.json"),
        "--jwks",
        str(FIXTURES / "jwks.json"),
        "--output-dir",
        str(destination),
    ]


class TestReader:
    class TestPassingCases:
        def test_retained_positive_has_eight_bounded_results(self) -> None:
            report = reader.evaluate(*RAW)
            assert report["all_comparisons_match"] is True
            assert len(report["claims"]) == 8
            assert set(report["claims"].values()) == {"established"}
            assert report["formal_pack_3"] == "not_run"
            assert "historical_revocation" in report["not_established"]
            assert "freshness" in report["not_established"]

        @given(st.integers(min_value=-reader.SAFE_INTEGER, max_value=reader.SAFE_INTEGER))
        def test_safe_integer_domain(self, number: int) -> None:
            assert reader.canonical({"value": number}) == b'{"value":' + str(number).encode() + b"}"

        @given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=80))
        def test_unicode_round_trip(self, value: str) -> None:
            payload = reader.canonical({"value": value})
            assert reader.load_json(payload) == {"value": value}

        def test_jwks_selects_matching_key_when_unrelated_key_precedes_it(self) -> None:
            jwks = json.loads(RAW[2])
            extra = copy.deepcopy(jwks["keys"][0])
            extra["kid"] = "unrelated"
            jwks["keys"].insert(0, extra)
            assert reader.evaluate(RAW[0], RAW[1], encode(jwks))["all_comparisons_match"] is True

        def test_full_key_budget_and_documentation(self) -> None:
            jwks = json.loads(RAW[2])
            original = jwks["keys"][0]
            jwks["keys"] += [
                {**original, "kid": f"unrelated-{index}"} for index in range(reader.MAX_KEYS - 1)
            ]
            assert len(jwks["keys"]) == reader.MAX_KEYS
            assert reader.evaluate(RAW[0], RAW[1], encode(jwks))["all_comparisons_match"] is True
            readme = (HERE / "README.md").read_text(encoding="utf-8")
            match = re.search(r"Its key count is bounded at (\d+)", readme)
            assert match is not None
            assert int(match[1]) == reader.MAX_KEYS
            docstring = reader.select_key.__doc__ or ""
            match = re.search(r"from at most (\d+) entries", docstring)
            assert match is not None
            assert int(match[1]) == reader.MAX_KEYS

        def test_utf16_key_order(self) -> None:
            assert reader.canonical({"\ufffd": 1, "\U0001f600": 2}) == '{"😀":2,"�":1}'.encode()

        def test_native_action_ref_does_not_establish_tuple_uniqueness(self) -> None:
            request = json.loads(RAW[1])
            request.update(action_type="rea", scope="dconformance-fixture")
            report = reader.evaluate(RAW[0], encode(request), RAW[2])
            assert report["all_comparisons_match"] is True
            assert "action_tuple_uniqueness" in report["not_established"]

    class TestFailingCases:
        @pytest.mark.parametrize(
            ("payload", "message"),
            [
                (b'{"a":1,"a":2}', "duplicate JSON object member"),
                (b'{"x":{"a":1,"a":2}}', "duplicate JSON object member"),
                (b'{"a":NaN}', "floating-point values are outside this profile"),
                (b'{"a":Infinity}', "floating-point values are outside this profile"),
                (b'{"a":0.5}', "floating-point values are outside this profile"),
                (b'{"a":9007199254740992}', "integer is outside the safe range"),
                (b'{"a":"\\ud800"}', "invalid Unicode scalar"),
                (b"\xff", "malformed JSON input"),
                (b"\xef\xbb\xbf{}", "malformed JSON input"),
                (b"[]", "JSON root must be an object"),
                (b"{", "malformed JSON input"),
                (b"{} trailing", "malformed JSON input"),
                (b" " * (reader.MAX_BYTES + 1), "JSON byte budget exceeded"),
            ],
        )
        def test_json_refusal(
            self, payload: bytes, message: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            with pytest.raises(reader.InputError, match=f"^{message}$"):
                reader.load_json(payload)
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize(
            "payload",
            [
                b'{"x":' + b"[" * 34 + b"0" + b"]" * 34 + b"}",
                encode({"x": [0] * reader.MAX_NODES}),
            ],
        )
        def test_resource_budgets(self, payload: bytes, caplog: pytest.LogCaptureFixture) -> None:
            with pytest.raises(reader.InputError, match="^JSON resource budget exceeded$"):
                reader.load_json(payload)
            assert caplog.messages[-1] == "JSON resource budget exceeded"

        @pytest.mark.parametrize("fields", [{"alg": "none"}, {"alg": "HS256"}, {"typ": "other"}])
        def test_algorithm_confusion(
            self, fields: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            message = "unsupported protected header algorithm or type"
            with pytest.raises(reader.InputError, match=f"^{message}$"):
                reader.evaluate(changed_header(**fields), RAW[1], RAW[2])
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize(
            "fields",
            [
                {"crit": ["x"]},
                {"b64": False},
                {"jku": "https://invalid.example/key"},
                {"jwk": {"kty": "OKP"}},
            ],
        )
        def test_unsupported_header_extensions(
            self, fields: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            with pytest.raises(reader.InputError, match="^unsupported protected header members$"):
                reader.evaluate(changed_header(**fields), RAW[1], RAW[2])
            assert caplog.messages[-1] == "unsupported protected header members"

        @pytest.mark.parametrize(
            ("value", "message"),
            [
                ("", "invalid base64url encoding"),
                ("AA=", "invalid base64url encoding"),
                ("+A", "invalid base64url encoding"),
                ("A", "invalid base64url encoding"),
                ("AB", "noncanonical base64url encoding"),
            ],
        )
        def test_base64url(
            self, value: str, message: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            with pytest.raises(reader.InputError, match=f"^{message}$"):
                reader.decode64(value)
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize(
            ("keys", "message"),
            [
                ([], "JWKS must contain between 1 and 32 keys"),
                ([{}] * 33, "JWKS must contain between 1 and 32 keys"),
                ([1], "JWKS key must be an object"),
                ([{"kid": "x"}, {"kid": "x"}], "duplicate JWKS kid"),
                ([{"kid": "unknown"}], "signing kid is absent from retained JWKS"),
            ],
        )
        def test_key_selection(
            self, keys: list[Any], message: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            with pytest.raises(reader.InputError, match=f"^{message}$"):
                reader.evaluate(RAW[0], RAW[1], encode({"keys": keys}))
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize(
            ("field", "value", "message"),
            [
                ("kty", "RSA", "unsupported JWKS key parameters"),
                ("crv", "X25519", "unsupported JWKS key parameters"),
                ("alg", "HS256", "unsupported JWKS key parameters"),
                ("use", "enc", "unsupported JWKS key parameters"),
                ("key_ops", ["sign"], "JWKS key is not public verification-only material"),
                ("d", "secret", "JWKS key is not public verification-only material"),
                ("x", "AA", "Ed25519 public key must be 32 bytes"),
            ],
        )
        def test_key_domain(
            self, field: str, value: Any, message: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            jwks = json.loads(RAW[2])
            jwks["keys"][0][field] = value
            with pytest.raises(reader.InputError, match=f"^{message}$"):
                reader.evaluate(RAW[0], RAW[1], encode(jwks))
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize("field", ["subject_did", "charge_ref", "nonce", "amount_usd"])
        def test_request_substitution_is_not_binding_success(self, field: str) -> None:
            request = json.loads(RAW[1])
            request[field] = 1 if field == "amount_usd" else request[field] + "-changed"
            report = reader.evaluate(RAW[0], encode(request), RAW[2])
            assert report["claims"]["request_binding_matches"] == "contradicted"
            assert report["claims"]["binding_digest"] == "established"
            assert report["all_comparisons_match"] is False

        @pytest.mark.parametrize("field", ["action_type", "scope"])
        def test_action_tuple_substitution(self, field: str) -> None:
            request = json.loads(RAW[1])
            request[field] += "-changed"
            report = reader.evaluate(RAW[0], encode(request), RAW[2])
            assert report["claims"]["action_ref"] == "contradicted"
            assert report["claims"]["signature_under_retained_key"] == "established"

        def test_changed_core_preserves_signature_but_breaks_binding(self) -> None:
            att = json.loads(RAW[0])
            att["binding"]["charge_ref"] += "-changed"
            report = reader.evaluate(encode(att), RAW[1], RAW[2])
            assert report["claims"]["signature_under_retained_key"] == "established"
            for claim in (
                "core_digest",
                "signed_payload_equals_core",
                "binding_digest",
                "request_binding_matches",
            ):
                assert report["claims"][claim] == "contradicted"

        def test_unknown_payload_member_is_integrity_covered(self) -> None:
            att = json.loads(RAW[0])
            att["extension"] = "changed"
            report = reader.evaluate(encode(att), RAW[1], RAW[2])
            assert report["claims"]["core_digest"] == "contradicted"
            assert report["claims"]["signed_payload_equals_core"] == "contradicted"

        @pytest.mark.parametrize(
            ("field", "message"),
            [
                ("binding", "required object: binding"),
                ("verifier", "required object: verifier"),
                ("jws", "required string: jws"),
                ("type", "unsupported attestation profile"),
            ],
        )
        def test_missing_required_input(
            self, field: str, message: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            att = json.loads(RAW[0])
            del att[field]
            with pytest.raises(reader.InputError, match=f"^{message}$"):
                reader.evaluate(encode(att), RAW[1], RAW[2])
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize(
            ("jws", "message"),
            [
                ("x.y", "compact JWS must have three segments"),
                ("x.y.z.w", "compact JWS must have three segments"),
                (
                    encode64(
                        b'{"alg":"none","alg":"EdDSA","typ":"VerifierAttestation",'
                        b'"kid":"agentid-2026-03"}'
                    )
                    + ".e30.AA",
                    "duplicate JSON object member",
                ),
            ],
        )
        def test_compact_and_header_malformed(
            self, jws: str, message: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            att = json.loads(RAW[0])
            att["jws"] = jws
            with pytest.raises(reader.InputError, match=f"^{message}$"):
                reader.evaluate(encode(att), RAW[1], RAW[2])
            assert caplog.messages[-1] == message

        def test_short_signature(self, caplog: pytest.LogCaptureFixture) -> None:
            att = json.loads(RAW[0])
            parts = att["jws"].split(".")
            parts[2] = "AA"
            att["jws"] = ".".join(parts)
            with pytest.raises(reader.InputError, match="^Ed25519 signature must be 64 bytes$"):
                reader.evaluate(encode(att), RAW[1], RAW[2])
            assert caplog.messages[-1] == "Ed25519 signature must be 64 bytes"

        @given(
            st.binary(min_size=32, max_size=32).filter(
                lambda b: b != reader.decode64(json.loads(RAW[2])["keys"][0]["x"])
            )
        )
        def test_unrelated_public_keys_cannot_verify(self, public: bytes) -> None:
            jwks = json.loads(RAW[2])
            jwks["keys"][0]["x"] = encode64(public)
            report = reader.evaluate(RAW[0], RAW[1], encode(jwks))
            assert report["claims"]["signature_under_retained_key"] == "contradicted"


class TestRun:
    class TestPassingCases:
        def test_fresh_report_required_for_success(self, tmp_path: Path) -> None:
            destination = tmp_path / "attempt"
            assert run.main(arguments(destination)) == 0
            report = json.loads((destination / "report.json").read_bytes())
            assert report["all_comparisons_match"] is True
            assert len(report["reader_sha256"]) == 64

    class TestFailingCases:
        def test_existing_report_is_never_reused(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            destination = tmp_path / "attempt"
            destination.mkdir()
            sentinel = destination / "report.json"
            sentinel.write_bytes(b"old report")
            assert run.main(arguments(destination)) == 2
            assert sentinel.read_bytes() == b"old report"
            assert caplog.messages[-1].startswith("run failed: [Errno 17] File exists:")

        def test_contradiction_produces_nonzero_and_fresh_report(self, tmp_path: Path) -> None:
            request = json.loads(RAW[1])
            request["scope"] += "-changed"
            path = tmp_path / "request.json"
            path.write_bytes(encode(request))
            destination = tmp_path / "attempt"
            assert run.main(arguments(destination, path)) == 1
            assert (
                json.loads((destination / "report.json").read_bytes())["claims"]["action_ref"]
                == "contradicted"
            )

        def test_missing_input_has_no_report(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            destination = tmp_path / "attempt"
            assert run.main(arguments(destination, tmp_path / "missing")) == 2
            assert not (destination / "report.json").exists()
            assert caplog.messages[-1].startswith("run failed: [Errno 2] No such file")

        def test_malformed_input_has_no_report(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            path = tmp_path / "request.json"
            path.write_bytes(b"{")
            destination = tmp_path / "attempt"
            assert run.main(arguments(destination, path)) == 2
            assert not (destination / "report.json").exists()
            assert caplog.messages[-1] == "run failed: malformed JSON input"


class TestCheckResult:
    class TestPassingCases:
        def test_fresh_result_accepted(self, tmp_path: Path) -> None:
            destination = tmp_path / "attempt"
            assert run.main(arguments(destination)) == 0
            check_result.check_report(destination / "report.json")

    class TestFailingCases:
        @pytest.mark.parametrize(
            ("field", "value"),
            [
                ("profile", "unrelated-profile"),
                ("not_established", []),
                ("request_binding_fields", []),
                ("action_reference_fields", []),
                ("formal_pack_3", "passed"),
                ("all_comparisons_match", 1),
                ("unexpected", "claim"),
            ],
        )
        def test_classification_cannot_be_promoted(
            self, tmp_path: Path, field: str, value: Any, caplog: pytest.LogCaptureFixture
        ) -> None:
            destination = tmp_path / "attempt"
            assert run.main(arguments(destination)) == 0
            path = destination / "report.json"
            report = json.loads(path.read_bytes())
            report[field] = value
            path.write_bytes(encode(report))
            with pytest.raises(reader.InputError, match="^report classification differs$"):
                check_result.check_report(path)
            assert caplog.messages[-1] == "report classification differs"

        def test_zero_exit_without_report_is_not_a_result(self, tmp_path: Path) -> None:
            path = tmp_path / "absent.json"
            with pytest.raises(FileNotFoundError) as caught:
                check_result.check_report(path)
            assert str(caught.value) == f"[Errno 2] No such file or directory: '{path}'"

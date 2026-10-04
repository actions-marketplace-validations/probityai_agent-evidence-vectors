"""Adversarial native-signature checks for the provisional retained-field gate."""

from __future__ import annotations

import copy
import json
import logging
import shutil
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from retain_gate import (
    PolicyError,
    admit,
    canonicalize,
    decode_base64url,
    encode_base64url,
    load_json,
    public_key,
)
from run_regression import run, verify_sources

ROOT = Path(__file__).resolve().parents[1]
VECTORS = [load_json(path.read_bytes()) for path in sorted((ROOT / "upstream").glob("S3*.json"))]
KEY = load_json((ROOT / "upstream/testkey_jwks.json").read_bytes())["keys"][0]


def card(case: str = "S3-D-012") -> dict:
    """Return a fresh served-card object so test mutations stay isolated."""
    return copy.deepcopy(next(vector["served_card"] for vector in VECTORS if vector["id"] == case))


class TestRetainGate:
    class TestPassingCases:
        @pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["id"])
        def test_native_corpus(self, vector: dict) -> None:
            result = admit(vector["served_card"], KEY)
            assert result.admitted == ("unknown-retain" in vector["accept_under"])

        def test_dual_signing_selects_only_retained_form(self) -> None:
            assert admit(card(), KEY).signature_results == (False, True)

        def test_signature_order_does_not_change_admission(self) -> None:
            candidate = card()
            candidate["signatures"].reverse()
            assert admit(candidate, KEY).signature_results == (True, False)

        def test_unknown_field_preserved_without_mutation(self) -> None:
            candidate = card("S3-009")
            before = copy.deepcopy(candidate)
            assert json.loads(canonicalize(candidate))["x-reserved"] == []
            assert candidate == before

        @given(st.binary(min_size=1, max_size=128))
        def test_base64url_round_trip(self, value: bytes) -> None:
            assert decode_base64url(encode_base64url(value)) == value

        def test_report_recomputes_counterexample(self) -> None:
            report = run()
            assert report["passed"] and len(report["results"]) == 13
            assert report["unsafe_fallback_control"]["excluded_signature_results"] == [True, False]

    class TestFailingCases:
        @pytest.mark.parametrize("case", ["S3-T-011", "S3-D-013"])
        def test_mutated_url_cannot_use_excluded_signature(self, case: str) -> None:
            assert not admit(card(case), KEY).admitted

        @given(
            st.text(
                alphabet=st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=80
            ).filter(lambda value: value != "https://example.com/a2a/v1")
        )
        def test_arbitrary_url_mutation_is_rejected(self, value: str) -> None:
            candidate = card()
            candidate["url"] = value
            assert not admit(candidate, KEY).admitted

        @pytest.mark.parametrize(
            "case,path",
            [("S3-003", ("provider", "legalEntity")), ("S3-007", ("skills", 0, "costHint"))],
        )
        def test_nested_unknown_mutation_is_rejected(self, case: str, path: tuple) -> None:
            candidate = card(case)
            target = candidate
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = "changed after signing"
            assert not admit(candidate, KEY).admitted

        @pytest.mark.parametrize("value", [None, [], {}, ["bad"]])
        def test_malformed_signature_collection(self, value, caplog) -> None:
            candidate = card()
            candidate["signatures"] = value
            message = (
                "each signature must be an object"
                if value == ["bad"]
                else "card must contain a nonempty signatures array"
            )
            with caplog.at_level(logging.WARNING), pytest.raises(PolicyError, match=f"^{message}$"):
                admit(candidate, KEY)
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize(
            "raw,message",
            [
                (b'{"x":1,"x":2}', "duplicate JSON member"),
                (b'{"x":{"y":1,"y":2}}', "duplicate JSON member"),
                (b"[]", "JSON root must be an object"),
                (b"{", "invalid JSON encoding"),
            ],
        )
        def test_invalid_json(self, raw: bytes, message: str, caplog) -> None:
            with pytest.raises(PolicyError, match=f"^{message}$"):
                load_json(raw)
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize("value", ["", "a", "AA=", "A+", "AB", None])
        def test_invalid_base64url(self, value, caplog) -> None:
            with pytest.raises(PolicyError, match="^invalid base64url encoding$"):
                decode_base64url(value)
            assert caplog.messages[-1] == "invalid base64url encoding"

        @pytest.mark.parametrize(
            "header_patch,message",
            [
                ({"alg": "none"}, "signature algorithm or key id does not match pinned key"),
                ({"kid": "other"}, "signature algorithm or key id does not match pinned key"),
                ({"crit": ["b64"]}, "unsupported JOSE header extension"),
                ({"b64": False}, "unsupported JOSE header extension"),
            ],
        )
        def test_header_extension_and_key_confusion(
            self, header_patch: dict, message: str, caplog
        ) -> None:
            candidate = card()
            signature = candidate["signatures"][0]
            header = load_json(decode_base64url(signature["protected"]))
            header.update(header_patch)
            signature["protected"] = encode_base64url(json.dumps(header).encode())
            with pytest.raises(PolicyError, match=f"^{message}$"):
                admit(candidate, KEY)
            assert caplog.messages[-1] == message

        def test_signature_wrong_length(self, caplog) -> None:
            candidate = card()
            candidate["signatures"][0]["signature"] = encode_base64url(b"short")
            with pytest.raises(PolicyError, match="^ES256 signature must contain 64 bytes$"):
                admit(candidate, KEY)
            assert caplog.messages[-1] == "ES256 signature must contain 64 bytes"

        def test_wrong_key_shape(self, caplog) -> None:
            with pytest.raises(PolicyError, match="^unsupported test key$"):
                public_key({"kty": "RSA"})
            assert caplog.messages[-1] == "unsupported test key"

        def test_source_tampering(self, tmp_path, caplog) -> None:
            (tmp_path / "input.json").write_text("changed")
            (tmp_path / "source-lock.json").write_text(
                json.dumps({"files": [{"file": "input.json", "sha256": "bad"}]})
            )
            with pytest.raises(ValueError, match="^source digest mismatch: input.json$"):
                verify_sources(tmp_path)
            assert caplog.messages[-1] == "source digest mismatch: input.json"

        def test_unpinned_extra_case(self, tmp_path, caplog) -> None:
            shutil.copytree(ROOT / "upstream", tmp_path / "upstream")
            shutil.copyfile(ROOT / "source-lock.json", tmp_path / "source-lock.json")
            shutil.copyfile(
                tmp_path / "upstream/S3-D-012.json", tmp_path / "upstream/S3-UNPINNED.json"
            )
            message = "corpus membership differs from the frozen 13-case set"
            with pytest.raises(PolicyError, match=f"^{message}$"):
                run(tmp_path)
            assert caplog.messages[-1] == message

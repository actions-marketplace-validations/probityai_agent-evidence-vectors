from __future__ import annotations

import copy
import json
import unittest

import gen_fixture
import run
from prior_witness import (
    ProcessingFailure,
    action_outcome,
    evaluate,
    property_result,
    verify_witness,
)


class CandidateProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record, cls.files = run.read_pinned()
        cls.claimed = json.loads(cls.files["claimed-policy.json"])
        cls.witnessed = json.loads(cls.files["witnessed-policy.json"])
        cls.log = cls.files["witness.jsonl"]
        cls.after = json.loads(cls.files["action-after-window.json"])

    def test_cases_and_reproducible_fixtures(self) -> None:
        results = run.run_cases()
        self.assertEqual(len(results), 3)
        expected = json.loads((run.ROOT / "EXPECTED.json").read_text())
        self.assertTrue(
            all(
                result["binding"]
                == {**expected["binding"], "witnessHead": expected["witnessHeads"][name]}
                for name, result in results.items()
            )
        )
        self.assertEqual(gen_fixture.content(), self.files)

    def test_claim_does_not_supply_its_own_witness(self) -> None:
        self.assertEqual(
            property_result(self.record, self.claimed, None),
            {"verdict": "not_established", "unmet_obligation": "invocation_binding"},
        )
        changed = copy.deepcopy(self.claimed)
        changed["claimedCommitmentDigest"] = "f" * 64
        self.assertEqual(property_result(self.record, changed, None)["verdict"], "not_established")
        self.assertEqual(property_result(self.record, self.witnessed, self.log)["verdict"], "pass")

    def test_wrong_key_head_nonce_and_replay(self) -> None:
        trusted = self.witnessed["trustedWitness"]
        claim = self.witnessed["claimRef"]
        commitment = self.claimed["claimedCommitmentDigest"]
        self.assertEqual(verify_witness(self.log, trusted, claim, commitment), trusted["openHead"])
        for changed in (
            {**trusted, "witnessKey": "00" * 32},
            {**trusted, "openHead": "00" * 32},
            {**trusted, "invocationNonce": "other-invocation"},
        ):
            with self.subTest(change=changed), self.assertRaises(ProcessingFailure):
                verify_witness(self.log, changed, claim, commitment)
        with self.assertRaises(ProcessingFailure):
            verify_witness(self.log, trusted, "another-claim", commitment)
        with self.assertRaises(ProcessingFailure):
            verify_witness(self.log, trusted, claim, "00" * 32)
        with self.assertRaises(ProcessingFailure):
            verify_witness(42, trusted, claim, commitment)  # type: ignore[arg-type]

    def test_missing_extra_mutated_and_duplicate_witness_lines(self) -> None:
        trusted = self.witnessed["trustedWitness"]
        claim = self.witnessed["claimRef"]
        commitment = self.claimed["claimedCommitmentDigest"]
        first, second = self.log.splitlines(keepends=True)
        variants = (
            first,
            second + first,
            self.log + first,
            self.log.replace(b"prior-commitment", b"later-commitment"),
            self.log.replace(b'"sequence":1', b'"sequence":1,"sequence":1'),
            self.log.rstrip(b"\n"),
        )
        for index, variant in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ProcessingFailure):
                verify_witness(variant, trusted, claim, commitment)

    def test_record_capability_and_action_axes(self) -> None:
        with self.assertRaises(ProcessingFailure):
            property_result(self.record + b" ", self.witnessed, self.log)
        narrowed = copy.deepcopy(self.witnessed)
        narrowed["producerCapability"]["visibleWritePaths"] = ["/srv/app/src/"]
        self.assertEqual(
            property_result(self.record, narrowed, self.log),
            {"verdict": "not_established", "unmet_obligation": "producer_capability_coverage"},
        )
        sibling = copy.deepcopy(self.witnessed)
        sibling["producerCapability"]["visibleWritePaths"] = ["/srv/application/"]
        self.assertEqual(
            property_result(self.record, sibling, self.log),
            {"verdict": "not_established", "unmet_obligation": "producer_capability_coverage"},
        )
        sibling["scope"] = "/srv/application/"
        self.assertEqual(
            property_result(self.record, sibling, self.log),
            {"verdict": "not_established", "unmet_obligation": "observation_coverage"},
        )
        narrowed_scope = copy.deepcopy(self.witnessed)
        narrowed_scope["scope"] = "/srv/app/src/"
        self.assertEqual(property_result(self.record, narrowed_scope, self.log)["verdict"], "pass")
        root_visibility = copy.deepcopy(self.witnessed)
        root_visibility["producerCapability"]["visibleWritePaths"] = ["/"]
        self.assertEqual(property_result(self.record, root_visibility, self.log)["verdict"], "pass")
        other_invocation = copy.deepcopy(self.witnessed)
        other_invocation["producerCapability"]["claimRef"] = "another-claim"
        self.assertEqual(
            property_result(self.record, other_invocation, self.log),
            {"verdict": "not_established", "unmet_obligation": "producer_capability_coverage"},
        )
        for bad in ("/srv/app/../secret", "/srv/app/\x00secret", "/srv/app//secret", "/srv/app/./"):
            with self.subTest(path=bad), self.assertRaises(ProcessingFailure):
                property_result(self.record, {**self.witnessed, "scope": bad}, self.log)
            with self.subTest(visibility=bad), self.assertRaises(ProcessingFailure):
                bad_visibility = copy.deepcopy(self.witnessed)
                bad_visibility["producerCapability"]["visibleWritePaths"] = [bad]
                property_result(self.record, bad_visibility, self.log)
        with self.assertRaises(ProcessingFailure):
            property_result(
                self.record, {**self.witnessed, "claimedCommitmentDigest": "00" * 32}, self.log
            )
        with self.assertRaises(ProcessingFailure):
            property_result(self.record, {**self.witnessed, "producerCapability": {}}, self.log)
        self.assertEqual(
            evaluate(self.record, self.witnessed, self.log, self.after)["actionOutcome"], "pending"
        )
        with self.assertRaises(ProcessingFailure):
            action_outcome(
                {**self.after, "authenticatedTerminal": {"result": "complete"}},
                self.witnessed["claimRef"],
            )
        with self.assertRaises(ProcessingFailure):
            action_outcome(self.after, "another-claim")
        self.assertEqual(
            action_outcome(
                {**self.after, "checkedAt": "2026-09-19T00:00:09Z"},
                self.witnessed["claimRef"],
            ),
            "pending",
        )
        for bad in (
            {**self.after, "windowEnd": 1},
            {**self.after, "checkedAt": None},
            {**self.after, "checkedAt": "not-a-time"},
        ):
            with self.subTest(action=bad), self.assertRaises(ProcessingFailure):
                action_outcome(bad, self.witnessed["claimRef"])


if __name__ == "__main__":
    unittest.main()

"""Execute the five pinned native S4 cases under both explicit readings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from dual_name_gate import POLICIES, ROOT, admit_with_policy
from retain_gate import PolicyError, admit, canonicalize, load_json, refuse

CASE_IDS = ("S4-001", "S4-002", "S4-003", "S4-004", "S4-REJECT-005")


def verify_sources(root: Path) -> dict:
    """Require frozen source bytes and exact five-case membership before use.

    The lock covers corpus, test key, native protocol text, schema projection
    and the shared retained-field verifier. No unpinned fixture is swept into
    the comparison. Source mismatches refuse before signature evaluation.
    """
    lock = load_json((root / "source-lock.json").read_bytes())
    wanted = sorted(f"upstream/{case}.json" for case in CASE_IDS)
    locked = sorted(item["file"] for item in lock["files"] if "/S4" in item["file"])
    actual = sorted(str(p.relative_to(root)) for p in (root / "upstream").glob("S4*.json"))
    if locked != wanted or actual != wanted:
        refuse("corpus membership differs from the frozen five-case set")
    for item in lock["files"]:
        if hashlib.sha256((root / item["file"]).read_bytes()).hexdigest() != item["sha256"]:
            refuse(f"source digest mismatch: {item['file']}")
    return lock


def evaluate(card: dict, jwk: dict, policy: str) -> dict:
    """Retain admission and its precise refusal separately from signature validity."""
    try:
        result = admit_with_policy(card, jwk, policy)
    except PolicyError as error:
        return {"admitted": False, "refusal": str(error)}
    return {"admitted": result.admitted, "refusal": None}


def run(root: Path = ROOT) -> dict:
    """Recompute every selected signature and both policy verdicts offline.

    Expected readings are consulted after the independent calculations. The
    three valid signed dual-name cards distinguish semantic refusal from an
    accidental signature failure. The single-spelling control must pass, and
    the added-after-signing member must fail the retained-byte signature.
    """
    lock = verify_sources(root)
    jwk = load_json((root / "upstream/testkey_jwks.json").read_bytes())["keys"][0]
    results = []
    for case in CASE_IDS:
        vector = load_json((root / f"upstream/{case}.json").read_bytes())
        if vector["id"] != case:
            refuse("fixture id does not match its pinned filename")
        card = vector["served_card"]
        signature = admit(card, jwk)
        readings = {policy: evaluate(card, jwk, policy) for policy in POLICIES}
        matches = all(
            readings[policy]["admitted"] == (policy in vector["accept_under"])
            for policy in POLICIES
        )
        results.append(
            {
                "id": case,
                "signature_valid": signature.admitted,
                "signature_results": signature.signature_results,
                "canonical_sha256": hashlib.sha256(canonicalize(card)).hexdigest(),
                "readings": readings,
                "matches": matches,
            }
        )
    return {
        "profile": "probity-a2a-s4-retained-dual-name-v1-candidate",
        "classification": "Probity-operated native-corpus regression",
        "corpus_revision": lock["revision"],
        "readings": lock["readings"],
        "passed": all(item["matches"] for item in results),
        "results": results,
        "scope": "five S4 cases; received fields retained; aliases in 21 frozen message types",
    }


if __name__ == "__main__":
    report = run()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)

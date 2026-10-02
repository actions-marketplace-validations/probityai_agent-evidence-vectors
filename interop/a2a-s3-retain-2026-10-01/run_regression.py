"""Execute the pinned S3 consumer-policy comparison and retain raw verdicts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from retain_gate import POLICY, admit, canonicalize, load_json, refuse, verify_signature

ROOT = Path(__file__).resolve().parent
CASE_IDS = tuple(
    [f"S3-{number:03}" for number in range(1, 11)] + ["S3-D-012", "S3-D-013", "S3-T-011"]
)


def verify_sources(root: Path = ROOT) -> dict:
    """Check every vendored source digest before executing any corpus case.

    Parameters
    ----------
    root : pathlib.Path
        Package directory containing ``source-lock.json`` and vendor data.

    Returns
    -------
    dict
        The verified source lock used to annotate the retained run.

    Raises
    ------
    ValueError
        If any file differs from the independently retained source capture.
    """
    lock = load_json((root / "source-lock.json").read_bytes())
    for item in lock["files"]:
        actual = hashlib.sha256((root / item["file"]).read_bytes()).hexdigest()
        if actual != item["sha256"]:
            refuse(f"source digest mismatch: {item['file']}")
    return lock


def corpus_paths(root: Path, lock: dict) -> list[Path]:
    """Require the exact 13-case population in both the lock and directory.

    This rejects unpinned additions, duplicate lock entries, and missing cases
    before any signature is evaluated; it prevents a truthful digest check from
    being followed by a broader, unverified directory sweep.
    """
    expected = sorted(f"upstream/{case}.json" for case in CASE_IDS)
    locked = sorted(
        item["file"] for item in lock["files"] if Path(item["file"]).name.startswith("S3")
    )
    actual = sorted(str(path.relative_to(root)) for path in (root / "upstream").glob("S3*.json"))
    if locked != expected or actual != expected:
        refuse("corpus membership differs from the frozen 13-case set")
    return [root / filename for filename in expected]


def run(root: Path = ROOT) -> dict:
    """Recompute signature verdicts independently from the pinned served cards.

    The corpus's expected outcomes are compared only after signature evaluation;
    supplied canonical hex is never an input to admission. The unsafe-fallback
    counterexample is explicitly isolated as a diagnostic control.
    """
    lock = verify_sources(root)
    jwk = load_json((root / "upstream/testkey_jwks.json").read_bytes())["keys"][0]
    results = []
    for path in corpus_paths(root, lock):
        vector = load_json(path.read_bytes())
        if vector["id"] != path.stem:
            refuse("fixture id does not match its pinned filename")
        card = vector["served_card"]
        result = admit(card, jwk)
        expected = "unknown-retain" in vector["accept_under"]
        results.append(
            {
                "id": vector["id"],
                "admitted": result.admitted,
                "expected": expected,
                "matches": result.admitted == expected,
                "signature_results": result.signature_results,
                "canonical_sha256": hashlib.sha256(canonicalize(card)).hexdigest(),
            }
        )
    dual = load_json((root / "upstream/S3-D-013.json").read_bytes())["served_card"]
    excluded = {
        key: value
        for key, value in dual.items()
        if key not in {"url", "protocolVersion", "preferredTransport"}
    }
    unsafe_results = [
        verify_signature(signature, canonicalize(excluded), jwk) for signature in dual["signatures"]
    ]
    return {
        "policy": POLICY,
        "source_revision": lock["revision"],
        "classification": "Probity-operated reproduction with independently written checker",
        "scope": "13 frozen S3 cases; default-value and absent-field axes excluded",
        "passed": all(result["matches"] for result in results),
        "results": results,
        "unsafe_fallback_control": {
            "id": "S3-D-013",
            "excluded_signature_results": unsafe_results,
            "would_accept": any(unsafe_results),
        },
    }


if __name__ == "__main__":
    report = run()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)

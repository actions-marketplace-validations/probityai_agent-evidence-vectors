"""Require pinned fixture bytes and a complete matching offline-reader report."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from reader import (
    ACTION_FIELDS,
    PROFILE,
    REQUEST_FIELDS,
    UNESTABLISHED,
    InputError,
    load_json,
    refuse,
)
from run import read_bounded

HERE = Path(__file__).parent
CLAIMS = {
    "core_digest",
    "signed_payload_equals_core",
    "signature_under_retained_key",
    "header_kid_matches_signed_verifier",
    "binding_digest",
    "request_binding_matches",
    "action_ref",
    "attestation_ref",
}


def classification(report: dict[str, object]) -> None:
    """Require the exact profile and explicit claim ceilings in every accepted report."""
    expected = {
        "profile": PROFILE,
        "formal_pack_3": "not_run",
        "not_established": UNESTABLISHED,
        "request_binding_fields": REQUEST_FIELDS,
        "action_reference_fields": ACTION_FIELDS,
    }
    keys = set(expected) | {"claims", "all_comparisons_match", "input_sha256", "reader_sha256"}
    if set(report) != keys or report.get("all_comparisons_match") is not True:
        refuse("report classification differs")
    if any(report.get(field) != value for field, value in expected.items()):
        refuse("report classification differs")


def check_report(path: Path) -> None:
    """Check fixture pins, all eight outcomes, and the executed reader source digest.

    Parameters
    ----------
    path : pathlib.Path
        Report emitted by run.py into its newly created attempt directory.

    Raises
    ------
    InputError
        If the report is missing required positive outcomes or its inputs/source
        differ from this checkout. File errors propagate; neither is success.

    Notes
    -----
    This verifies the retained positive fixture result, not arbitrary claims or
    external operator custody. Freshness is enforced by run.py's output contract.
    """
    pins = json.loads((HERE / "INPUTS.json").read_bytes())
    expected: dict[str, str] = {}
    for item in pins["files"]:
        observed = hashlib.sha256(read_bounded(HERE / item["path"])).hexdigest()
        if observed != item["sha256"]:
            refuse("fixture bytes differ from the source pin")
        expected[item["role"]] = observed
    report = load_json(read_bounded(path))
    if report.get("input_sha256") != expected:
        refuse("report inputs differ from pinned fixtures")
    if report.get("claims") != dict.fromkeys(CLAIMS, "established"):
        refuse("report does not establish all eight bounded comparisons")
    classification(report)
    source_digest = hashlib.sha256((HERE / "reader.py").read_bytes()).hexdigest()
    if report.get("reader_sha256") != source_digest:
        refuse("report reader digest differs from this checkout")


def main() -> int:
    """Exit zero only after the retained report and pinned inputs pass every check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        check_report(args.report)
    except (OSError, InputError) as exc:
        print(f"report refused: {exc}", file=sys.stderr)
        return 2
    print("Pinned AgentID fixture: eight bounded comparisons reproduced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

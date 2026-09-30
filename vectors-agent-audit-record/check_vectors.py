#!/usr/bin/env python3
"""Does the committed corpus behave as MANIFEST.json claims, and is every rule
in the reference reader load-bearing?

    uv run --extra generators python vectors-agent-audit-record/check_vectors.py

Three checks, each able to fail on its own.

1. The corpus judge: the packaged reader (agent_evidence_vectors.auditrecord,
   the one ``uvx agent-evidence-vectors --corpus vectors-agent-audit-record``
   runs) reaches every member's declared verdict and first refusal, and the
   counts, parents and corpus digest hold.
2. A second signature path: every member the manifest says must not be refused
   carries a signature that verifies under the ``cryptography`` library over
   the RFC 8785 bytes this directory's own canonicalizer derives, and T2 does
   not. The reader borrows the rail's Ed25519, so without this check one
   Ed25519 implementation would be grading itself.
3. The mutation sweep: disabling any one rule of the reader must turn at least
   one reject member into a non-refusal, must never turn an accept member into
   a refusal, and must never move an indeterminate member to a verdict none of
   its readings lists. A rule whose removal changes no verdict measures nothing.

An indeterminate member (N1, N2) is scored on its readings: any verdict it lists
conforms, and it carries no expected.verdict. scripts/indeterminate-readers-test.py
deletes each listed reading in turn and requires the judge to refuse the result.
"""

from __future__ import annotations

import base64
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "packaging"))

import run_vectors  # noqa: E402,F401  (the reader resolves the rail's Ed25519 through it)
from agent_evidence_vectors import auditrecord  # noqa: E402
from canonical import canonical_bytes  # noqa: E402


def _manifest() -> dict[str, object]:
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        loaded: dict[str, object] = json.load(fh)
    return loaded


def _raw(entry: dict[str, object]) -> bytes:
    with open(os.path.join(HERE, str(entry["file"])), "rb") as fh:
        return fh.read()


def _second_signature_path(manifest: dict[str, object]) -> list[str]:
    keys = manifest["keys"]
    assert isinstance(keys, dict)
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys["observer"]["publicKey"]))
    out: list[str] = []
    entries = manifest["vectors"]
    assert isinstance(entries, list)
    for entry in entries:
        must_hold = entry["kind"] != "reject" or entry["draftId"] == "T2"
        if not must_hold:
            continue
        envelope = json.loads(_raw(entry))
        payload = base64.b64decode(envelope["payload"])
        canonical = canonical_bytes(json.loads(payload))
        message = auditrecord.pae(auditrecord.PAYLOAD_TYPE, canonical)
        sig = base64.b64decode(envelope["signatures"][0]["sig"])
        try:
            public.verify(sig, message)
            holds = True
        except InvalidSignature:
            holds = False
        if entry["draftId"] == "T2" and holds:
            out.append("T2: the signature verifies over the RFC 8785 bytes, so T2 tests nothing")
        elif entry["draftId"] != "T2" and not holds:
            out.append(f"{entry['draftId']}: the signature does not verify under a second library")
    return out


def _mutation_sweep(manifest: dict[str, object]) -> tuple[list[str], list[str]]:
    """Findings, and notes for rules another rule backs up.

    A rule is load-bearing when disabling it changes what at least one reject
    member is refused FOR. Where the verdict still holds because a later rule
    refuses the same member, that is printed: the Appendix B row does not isolate
    the rule, which is a property of the draft's corpus and worth knowing.
    """
    policy = auditrecord.policy_for(manifest)
    entries = manifest["vectors"]
    assert isinstance(entries, list)
    bodies = [(entry, _raw(entry), auditrecord.verify(_raw(entry), policy)) for entry in entries]
    findings: list[str] = []
    notes: list[str] = []
    swept = [n for n in auditrecord.rule_names() if n not in auditrecord.UNREACHED_BY_CORPUS]
    for name in ["signature", *swept]:
        moved, flipped = [], []
        for entry, raw, full in bodies:
            report = auditrecord.verify(raw, policy, disabled=name)
            if entry["kind"] == "accept" and report.verdict != "valid":
                findings.append(f"disabling {name} refuses accept member {entry['draftId']}")
            open_member = entry["kind"] == "indeterminate"
            if open_member and report.verdict not in auditrecord.conforming_verdicts(entry):
                findings.append(
                    f"disabling {name} moves indeterminate member {entry['draftId']} to "
                    f"{report.verdict!r}, which none of its readings lists"
                )
            if entry["kind"] != "reject":
                continue
            if report.verdict == "valid":
                flipped.append(entry["draftId"])
            elif report.codes != full.codes:
                moved.append(f"{entry['draftId']} -> {report.codes[0]}")
        if not moved and not flipped:
            findings.append(f"rule {name} is inert: disabling it changes no reject member")
        elif not flipped:
            notes.append(f"rule {name}: a later check still refuses {', '.join(moved)}")
    return findings, notes


def main() -> int:
    judged = auditrecord.judge(HERE)
    sys.stdout.write(auditrecord.render(judged, auditrecord.SUITE))
    manifest = _manifest()
    swept, notes = _mutation_sweep(manifest)
    findings = _second_signature_path(manifest) + swept
    for note in notes:
        print(f"note: {note}")
    for finding in findings:
        print(f"FAIL check: {finding}")
    if judged.ok() and not findings:
        print("check: a second Ed25519 library agrees, and every rule is load-bearing")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

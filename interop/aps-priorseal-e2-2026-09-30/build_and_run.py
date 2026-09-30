"""Negatives and controls for the E2 pair, and their run against e2check.

The thread's fault table (aeoess/agent-governance-vocabulary#177, comment 5892629762)
marks four fault classes "no pinned negative": signature verification removed, wrong
verification key accepted, altered authorization accepted, decision-ref binding removed.
Each negative below is ONE semantic change to the pinned E2 bytes, materialized as a
self-consistent variant: the APS manifest is regenerated and our pins name the new
bytes, so the only defect in the variant is the one declared. Its conformant twin is the
unmodified pinned input.

Two controls, as the thread requires: a positive control that must be caught, and an
inert control (a re-serialization with identical JSON meaning) that must change no
per-claim state.

Usage: python build_and_run.py <inputs-dir> <pins.json> <checker.py> <work-dir> > RUN.json
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from typing import Any, Callable

from agent_evidence_vectors.run_vectors import jcs_dumps
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def rjson(p: str) -> Any:
    return json.load(open(p))


def wjson(p: str, v: Any, pretty: bool = False) -> None:
    with open(p, "w") as fh:
        if pretty:
            json.dump(v, fh, indent=4, sort_keys=True)
        else:
            json.dump(v, fh, indent=2)
        fh.write("\n")


def regen_manifest(aps_dir: str) -> str:
    lines = open(os.path.join(aps_dir, "MANIFEST.sha256")).read().splitlines()
    out = []
    for ln in lines:
        if not ln.strip():
            continue
        _, name = ln.split(None, 1)
        name = name.lstrip("*").strip()
        out.append(f"{sha(open(os.path.join(aps_dir, name), 'rb').read())}  {name}")
    data = ("\n".join(out) + "\n").encode()
    open(os.path.join(aps_dir, "MANIFEST.sha256"), "wb").write(data)
    return sha(data)


def label_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def resign_receipt(receipt: dict[str, Any], key: Ed25519PrivateKey) -> None:
    s = receipt["signatures"][0]
    form = {"receipt": {k: v for k, v in receipt.items() if k != "signatures"},
            "signer": {"signer": s["signer"], "key_id": s["key_id"], "alg": "Ed25519"}}
    s["value"] = key.sign(b"APS-RECEIPT-SIG-V1" + b"\x00" + jcs_dumps(form)).hex()


def m_signature_invalid(d: str) -> None:
    p = os.path.join(d, "aps/cases/permit/policy-decision-receipt.json")
    r = rjson(p)
    v = r["signatures"][0]["value"]
    r["signatures"][0]["value"] = ("0" if v[0] != "0" else "1") + v[1:]
    wjson(p, r)


def m_wrong_key(d: str) -> None:
    k = label_key("thread-177/e2/wrong-boundary-key")
    p = os.path.join(d, "aps/cases/permit/policy-decision-receipt.json")
    r = rjson(p)
    resign_receipt(r, k)
    wjson(p, r)
    # the adjacent keys.json offers the substituted key, so a checker that trusts it is fooled
    kp = os.path.join(d, "aps/keys.json")
    kj = rjson(kp)
    pub = k.public_key().public_bytes_raw().hex()
    for s in kj["receipt_signers"]:
        if s["signer"] == "did:example:boundary":
            s["public_key"] = pub
    wjson(kp, kj)


def _intent_mutate(d: str, rehash: bool) -> None:
    p = os.path.join(d, "ps/priorseal-inputs/payment-over-limit.json")
    f = rjson(p)
    auth = f["authorizationEvidence"]["authorization"]
    auth["intent"]["transactionValue"] = "6000000000000000"
    if rehash:
        h = sha(jcs_dumps({k: v for k, v in auth["intent"].items() if k != "intentHash"}))
        auth["intent"]["intentHash"] = h
        auth["intentHash"] = h
        f["intentHash"] = h
        f["authorizationEvidence"]["acceptance"]["intentHash"] = h
    wjson(p, f)


def m_altered_authorization(d: str) -> None:
    _intent_mutate(d, rehash=False)


def m_altered_authorization_rehashed(d: str) -> None:
    _intent_mutate(d, rehash=True)


def m_positive_control(d: str) -> None:
    p = os.path.join(d, "aps/cases/permit/policy-decision-receipt.json")
    r = rjson(p)
    r["issued_at"] = "2026-09-19T10:00:01.001Z"
    wjson(p, r)


def m_inert_control(d: str) -> None:
    p = os.path.join(d, "ps/priorseal-inputs/payment-within-limit.json")
    wjson(p, rjson(p), pretty=True)


CASES: list[dict[str, Any]] = [
    {"name": "signature-invalid", "faultClass": "signature verification removed", "mutate": m_signature_invalid,
     "mutation": "one hex digit of the permit policy-decision receipt's signature value changed",
     "target": [("aps/permit", "aps.decision.signature")]},
    {"name": "wrong-key", "faultClass": "wrong verification key accepted", "mutate": m_wrong_key,
     "mutation": "permit policy-decision receipt re-signed with an unpinned key derived from the label "
                 "'thread-177/e2/wrong-boundary-key'; the adjacent keys.json offers that key",
     "target": [("aps/permit", "aps.decision.signature")]},
    {"name": "altered-authorization", "faultClass": "altered authorization accepted", "mutate": m_altered_authorization,
     "mutation": "over-limit fixture: signed intent transactionValue changed from 1e15 to 6e15; hashes left as signed",
     "target": [("priorseal/over", "ps.intent_hash_consistency")]},
    {"name": "altered-authorization-rehashed", "faultClass": "altered authorization accepted",
     "mutate": m_altered_authorization_rehashed,
     "mutation": "as altered-authorization, and every carried intentHash recomputed; only the principal's "
                 "EIP-712 signature (entry 2) still covers the original",
     "target": [("priorseal/over", "ps.signatures")]},
    {"name": "decision-ref-unbound", "faultClass": "decision-ref binding removed", "mutate": None,
     "mutation": "the unmodified PriorSeal pair presented with the narrow case's APS receipt and evidence "
                 "instead of permit's", "pairCase": "narrow",
     "target": [("priorseal/within", "e2.decision_ref_correlation"), ("priorseal/over", "e2.decision_ref_correlation")]},
    {"name": "positive-control", "faultClass": "control", "mutate": m_positive_control,
     "mutation": "permit policy-decision receipt issued_at moved by 1 ms without re-signing", "target": "any"},
    {"name": "inert-control", "faultClass": "control", "mutate": m_inert_control,
     "mutation": "within-limit fixture re-serialized with sorted keys and 4-space indent; same JSON value",
     "target": "none"},
]


def run_checker(checker: str, inputs: str, pins: str, pair_case: str = "permit") -> list[dict[str, Any]]:
    out = subprocess.run([sys.executable, checker, inputs, pins, "--aps-case-for-pair", pair_case],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)["rows"]


def key(r: dict[str, Any]) -> tuple[str, str]:
    return (r["input"], r["claim"])


def main() -> int:
    inputs, pins_path, checker, work = sys.argv[1:5]
    os.makedirs(work, exist_ok=True)
    base_rows = run_checker(checker, inputs, pins_path)
    base = {key(r): r["state"] for r in base_rows}
    results = []
    for case in CASES:
        d = os.path.join(work, case["name"])
        if os.path.exists(d):
            shutil.rmtree(d)
        shutil.copytree(inputs, d)
        pins = rjson(pins_path)
        if case["mutate"] is not None:
            case["mutate"](d)
        pins["aps"]["manifest_sha256"] = regen_manifest(os.path.join(d, "aps"))
        for fn in list(pins["priorseal"]["fixtures"]):
            pins["priorseal"]["fixtures"][fn] = sha(open(os.path.join(d, "ps/priorseal-inputs", fn), "rb").read())
        pins["priorseal"]["report_sha256"] = None  # the report belongs to the original pair only
        pp = os.path.join(d, "pins.json")
        wjson(pp, pins)
        rows = run_checker(checker, d, pp, case.get("pairCase", "permit"))
        now = {key(r): r["state"] for r in rows}
        changed = sorted((k[0], k[1], base.get(k), now.get(k)) for k in now if base.get(k) != now.get(k))
        entry: dict[str, Any] = {"name": case["name"], "faultClass": case["faultClass"], "mutation": case["mutation"],
                                 "changed": [{"input": a, "claim": b, "twin": c, "variant": e} for a, b, c, e in changed]}
        if case["target"] == "any":
            entry["verdict"] = "caught" if any(e == "fail" for *_, e in changed) else "NOT CAUGHT: run void"
        elif case["target"] == "none":
            entry["verdict"] = "inert" if not changed else "NOT INERT: run void"
        else:
            hits = [t for t in case["target"] if base.get(t) == "pass" and now.get(t) == "fail"]
            voids = [c for c in changed if c[3] == "void"]
            others = [c for c in changed if (c[0], c[1]) not in case["target"] and c[3] != "void"]
            entry["killed"] = len(hits) == len(case["target"])
            entry["targetedFlips"] = len(hits)
            entry["dependentsVoided"] = len(voids)
            entry["otherChanges"] = [{"input": a, "claim": b, "twin": c, "variant": e} for a, b, c, e in others]
        results.append(entry)
    json.dump({"baselineRows": len(base_rows), "cases": results}, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

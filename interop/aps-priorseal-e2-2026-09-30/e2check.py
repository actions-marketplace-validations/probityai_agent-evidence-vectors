"""Independent checker for edge E2 of aeoess/agent-governance-vocabulary#177.

E2 is the APS decision evidence to PriorSeal exact-call authorization pair
(APS producer fixtures at 948f99b8, PriorSeal pair at d749d269, reference time
2026-09-19T10:05:00.000Z). This module was written from draft-pidlisnyi-aps-03
Sections 3.1, 4.1 and 5.1 to 5.6, the two fixture READMEs and PriorSeal's
claim-boundary document. It imports no APS or PriorSeal code. RFC 8785 and
Ed25519 come from the published agent-evidence-vectors package (its reference
rail's jcs_dumps and ed25519_verify); Keccak-256 comes from pycryptodome.

Every claim is judged on its own and reported in a closed vocabulary: state is
one of pass, fail, inconclusive, not-exercised, void; a cause is required on the
last three and absent on the first two. A producer's own stated result is
quoted beside ours verbatim and never mapped onto it.

Usage: python e2check.py <inputs-dir> <pins.json> [--pair within=<file>,over=<file>]
       [--aps-case-for-pair <case>] > RESULTS.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from agent_evidence_vectors.run_vectors import ed25519_verify, jcs_dumps
from Crypto.Hash import keccak

STATES = ("pass", "fail", "inconclusive", "not-exercised", "void")
CAUSES = (
    "not_applicable", "disabled_by_policy", "unsupported_input", "resource_exhausted",
    "failed", "unavailable", "out_of_scope", "withheld", "evidence-does-not-hold",
    "integrity-failure", "availability-failure", "precondition-unsatisfiable",
)
APS_CASES = ("permit", "narrow", "deny", "expired")


# ----------------------------------------------------------------------------
# Primitives
# ----------------------------------------------------------------------------


class DuplicateMember(ValueError):
    pass


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateMember(k)
        out[k] = v
    return out


def load_json(path: str) -> Any:
    """Parse bytes while refusing a duplicated member (draft-03 Section 5.6)."""
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"), object_pairs_hook=_no_dupes)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tagged(tag: str, value: Any) -> str:
    """lowercase-hex(SHA-256(ASCII(tag) || 0x00 || UTF8(JCS(value))))."""
    return sha256_hex(tag.encode("ascii") + b"\x00" + jcs_dumps(value))


def keccak256_hex(data: bytes) -> str:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.hexdigest()


def iso_ms(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def row(inp: str, claim: str, state: str, detail: str, cause: str | None = None,
        producer: Any = None, lab_entry: str | None = None) -> dict[str, Any]:
    if state not in STATES:
        raise ValueError(state)
    if state in ("pass", "fail"):
        if cause is not None:
            raise ValueError("a verdict state carries no cause")
    elif cause not in CAUSES:
        raise ValueError(f"state {state} needs a cause from the closed list, got {cause}")
    r: dict[str, Any] = {"input": inp, "claim": claim, "state": state}
    if cause is not None:
        r["cause"] = cause
    r["detail"] = detail
    if lab_entry is not None:
        r["labEntry"] = lab_entry
    if producer is not None:
        r["producerStated"] = producer
    return r


# ----------------------------------------------------------------------------
# APS side (draft-pidlisnyi-aps-03)
# ----------------------------------------------------------------------------


def receipt_id(receipt: dict[str, Any]) -> str:
    body = {k: v for k, v in receipt.items() if k not in ("receipt_id", "signatures")}
    return tagged("APS-RECEIPT-ID-V1", body)


def receipt_signature_ok(receipt: dict[str, Any], sig: dict[str, Any], pub_hex: str) -> bool:
    form = {
        "receipt": {k: v for k, v in receipt.items() if k != "signatures"},
        "signer": {"signer": sig["signer"], "key_id": sig["key_id"], "alg": "Ed25519"},
    }
    msg = b"APS-RECEIPT-SIG-V1" + b"\x00" + jcs_dumps(form)
    try:
        return bool(ed25519_verify(bytes.fromhex(pub_hex), msg, bytes.fromhex(sig["value"])))
    except ValueError:
        return False


def delegation_id(d: dict[str, Any]) -> str:
    body = {k: v for k, v in d.items() if k not in ("delegation_id", "signature")}
    return "sha256:" + tagged("APS-AUTHORITY-DELEGATION-ID-V1", body)


def delegation_signature_ok(d: dict[str, Any], pub_hex: str) -> bool:
    body = {k: v for k, v in d.items() if k != "signature"}
    msg = b"APS-AUTHORITY-DELEGATION-SIGNATURE-V1" + b"\x00" + jcs_dumps(body)
    try:
        return bool(ed25519_verify(bytes.fromhex(pub_hex), msg, bytes.fromhex(d["signature"])))
    except ValueError:
        return False


def decision_ref(action_ref: str, ev: dict[str, Any]) -> str:
    inp = {
        "profile": "aps-decision-ref-v1",
        "action_ref": action_ref,
        "authority_state_ref": tagged("APS-DECISION-AUTHORITY-V1", ev["authority_state"]),
        "policy_ref": tagged("APS-DECISION-POLICY-V1", ev["policy_input"]),
        "context_ref": tagged("APS-DECISION-CONTEXT-V1", ev["decision_context"]),
        "decision_output_ref": tagged("APS-DECISION-OUTPUT-V1", ev["decision_output"]),
    }
    return tagged("APS-DECISION-REF-V1", inp)


def signer_check(inp: str, claim: str, receipt: dict[str, Any], expected_signer: str,
                 pins: dict[str, Any], lab: str | None) -> dict[str, Any]:
    """Every signature must verify under OUR pinned key for its signer; one must be the issuer's."""
    keys = {(k["signer"], k["key_id"]): k["public_key"] for k in pins["aps"]["receipt_signers"]}
    sigs = receipt.get("signatures") or []
    if not sigs:
        return row(inp, claim, "fail", "no signatures", lab_entry=lab)
    bad = []
    for s in sigs:
        pub = keys.get((s.get("signer"), s.get("key_id")))
        if pub is None:
            bad.append(f"{s.get('signer')}#{s.get('key_id')}: no pinned key")
        elif s.get("alg") != "Ed25519":
            bad.append(f"{s.get('signer')}: alg {s.get('alg')}")
        elif not receipt_signature_ok(receipt, s, pub):
            bad.append(f"{s.get('signer')}#{s.get('key_id')}: signature does not verify under the pinned key")
    if bad:
        return row(inp, claim, "fail", "; ".join(bad), lab_entry=lab)
    if receipt.get("issuer") != expected_signer or not any(s["signer"] == receipt["issuer"] for s in sigs):
        return row(inp, claim, "fail", f"issuer {receipt.get('issuer')} did not sign, or is not {expected_signer}", lab_entry=lab)
    return row(inp, claim, "pass", f"{len(sigs)} signature(s) verify under the pinned key for {expected_signer}", lab_entry=lab)


def check_aps_case(base: str, case: str, pins: dict[str, Any], ref_time: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    d = os.path.join(base, "aps", "cases", case)
    rows: list[dict[str, Any]] = []
    tag = f"aps/{case}"
    lab1 = "1" if case == "permit" else None
    try:
        intent = load_json(os.path.join(d, "action-intent-receipt.json"))
        dec = load_json(os.path.join(d, "policy-decision-receipt.json"))
        ev = load_json(os.path.join(d, "decision-evidence.json"))
        cs = load_json(os.path.join(d, "case.json"))
    except DuplicateMember as e:
        rows.append(row(tag, "aps.parse", "fail", f"duplicate member {e}", lab_entry=lab1))
        return rows, {}
    agent = pins["aps"]["agent"]
    boundary = pins["aps"]["boundary"]

    # receipt_id (Section 5.2)
    for name, rc in (("intent", intent), ("decision", dec)):
        got = receipt_id(rc)
        rows.append(row(tag, f"aps.{name}.receipt_id", "pass" if got == rc.get("receipt_id") else "fail",
                        f"recomputed {got}, carried {rc.get('receipt_id')}", lab_entry=lab1))
    # signatures under our pins (Section 5.2)
    rows.append(signer_check(tag, "aps.intent.signature", intent, agent, pins, lab1))
    rows.append(signer_check(tag, "aps.decision.signature", dec, boundary, pins, lab1))

    # Section 5.3.1 intent rules
    probs = []
    if intent.get("receipt_type") != "aps:action-intent:v1": probs.append("receipt_type")
    if not (intent.get("issuer") == intent.get("subject_agent") == agent): probs.append("issuer/subject_agent not the agent")
    if "prev" in intent or "decision_ref" in intent: probs.append("prev or decision_ref present")
    if intent.get("result") != {"profile": "aps-action-intent-result-v1", "status": "declared"}: probs.append("result not exactly declared")
    rows.append(row(tag, "aps.intent.type_rules", "fail" if probs else "pass",
                    "; ".join(probs) or "Section 5.3.1 rules hold", lab_entry=lab1))

    # Section 5.3.2 decision rules and the cross-receipt link
    probs = []
    out = dec.get("result") or {}
    if dec.get("receipt_type") != "aps:policy-decision:v1": probs.append("receipt_type")
    if dec.get("issuer") == agent or dec.get("issuer") != boundary: probs.append("issuer is the agent or not the pinned boundary")
    if dec.get("prev") != intent.get("receipt_id"): probs.append("prev is not the intent receipt_id")
    for k in ("subject_agent", "action_ref", "delegation_ref"):
        if dec.get(k) != intent.get(k): probs.append(f"{k} differs from the intent")
    if out != ev.get("decision_output"): probs.append("result differs from decision_evidence.decision_output")
    if iso_ms(dec["issued_at"]) <= iso_ms(intent["issued_at"]): probs.append("decision not issued after the intent")
    verdict = out.get("verdict")
    if verdict == "deny":
        if out.get("valid_until") is not None or out.get("effective_authority_ref") is not None:
            probs.append("deny carries valid_until or effective_authority_ref")
    elif verdict in ("permit", "narrow"):
        if out.get("valid_until") is None or iso_ms(out["valid_until"]) <= iso_ms(dec["issued_at"]):
            probs.append("valid_until absent or not after issued_at")
    else:
        probs.append(f"unknown verdict {verdict}")
    rows.append(row(tag, "aps.decision.type_rules", "fail" if probs else "pass",
                    "; ".join(probs) or "Section 5.3.2 rules and the intent-decision link hold", lab_entry=lab1))

    # action_ref from the supplied input object (Section 4.1)
    ari = cs.get("action_reference_input")
    got_ar = tagged("APS-ACTION-REF-V2", ari)
    rows.append(row(tag, "aps.action_ref", "pass" if got_ar == intent.get("action_ref") == dec.get("action_ref") else "fail",
                    f"recomputed {got_ar} from case.json action_reference_input; receipts carry {intent.get('action_ref')}",
                    lab_entry=lab1))
    # payload_ref: the draft defines it over "the exact JSON value presented for authorization and dispatch".
    call = ev["policy_input"].get("requested_call")
    got_pr = tagged("APS-ACTION-PAYLOAD-V1", call)
    if got_pr == ari.get("payload_ref"):
        rows.append(row(tag, "aps.payload_ref", "pass",
                        "payload_ref equals the tagged digest of policy_input.requested_call", lab_entry=lab1))
    else:
        rows.append(row(tag, "aps.payload_ref", "inconclusive",
                        "the fixtures do not name which JSON value was the payload; the tagged digest of "
                        f"policy_input.requested_call is {got_pr}, carried {ari.get('payload_ref')}",
                        cause="unsupported_input", lab_entry=lab1))

    # decision_ref (Section 5.4)
    got_dr = decision_ref(dec["action_ref"], ev)
    rows.append(row(tag, "aps.decision_ref", "pass" if got_dr == dec.get("decision_ref") else "fail",
                    f"recomputed {got_dr}, carried {dec.get('decision_ref')}", lab_entry=lab1))

    # delegation (Section 3.1 and 3.3, one root, supplied state only)
    chain = ev["authority_state"]["selected_chain"]
    probs = []
    principal = {m["issuer"]: m for m in pins["aps"]["delegation_verification_methods"]}
    leaf = chain[-1] if chain else None
    if len(chain) != 1: probs.append(f"chain length {len(chain)}; this checker handles one root")
    for dg in chain:
        if delegation_id(dg) != dg.get("delegation_id"): probs.append("delegation_id does not recompute")
        m = principal.get(dg.get("issuer"))
        if m is None or m["verification_method"] != dg.get("verification_method"):
            probs.append("no pinned verification method for the issuer")
        elif not delegation_signature_ok(dg, m["public_key"]):
            probs.append("delegation signature does not verify under the pinned principal key")
        if dg.get("parent_delegation_id") is not None: probs.append("root has a parent")
    if leaf is not None:
        if leaf.get("subject") != agent: probs.append("leaf subject is not the agent")
        if intent.get("delegation_ref") != leaf.get("delegation_id"): probs.append("delegation_ref is not the leaf delegation_id")
        t = leaf["authority"]["time"]
        if not (iso_ms(t["not_before"]) <= iso_ms(dec["issued_at"]) < iso_ms(t["not_after"])):
            probs.append("decision time outside the delegation window")
        revs = [r for r in ev["authority_state"].get("revocation_observations", []) if r.get("delegation_id") == leaf.get("delegation_id")]
        if not revs or any(r.get("state") != "active" for r in revs): probs.append("no active revocation observation supplied")
    rows.append(row(tag, "aps.delegation", "fail" if probs else "pass",
                    "; ".join(probs) or "delegation_id and signature recompute under the pinned principal key; "
                    "delegation_ref binds the leaf; decision time inside the window; supplied revocation state active "
                    "(recorded state only, not live revocation)", lab_entry=lab1))

    # temporal validity at the reference time, its own claim
    vu = out.get("valid_until")
    exp = cs.get("expected", {}).get("unexpired_at_reference_time")
    if verdict == "deny":
        rows.append(row(tag, "aps.temporal_at_reference", "not-exercised",
                        "a deny has no validity window", cause="not_applicable", producer={"unexpired_at_reference_time": exp}))
    else:
        ok = iso_ms(vu) > ref_time
        rows.append(row(tag, "aps.temporal_at_reference", "pass" if ok else "fail",
                        f"valid_until {vu} against reference {pins['reference_time']}",
                        producer={"unexpired_at_reference_time": exp}, lab_entry=lab1))
    # the verdict as its own claim
    rows.append(row(tag, "aps.verdict_admits_dispatch", "pass" if verdict in ("permit", "narrow") else "fail",
                    f"verdict {verdict}", producer=cs.get("expected", {}).get("verifyReceiptWithDecisionV1")))
    facts = {"decision_ref": got_dr, "carried_decision_ref": dec.get("decision_ref"), "valid_until": vu,
             "verdict": verdict, "requested_call": call, "leaf": leaf, "decision": dec}
    return rows, facts


# ----------------------------------------------------------------------------
# PriorSeal side and the composition (the lab's entries 3 to 6)
# ----------------------------------------------------------------------------


DEPENDS = {
    # composition claim -> (APS claims on the paired case, PriorSeal claims on this fixture) it rests on
    "e2.decision_ref_correlation": (("aps.manifest", "aps.decision.receipt_id", "aps.decision.signature", "aps.decision_ref"),
                                    ("ps.fixture_pin", "ps.intent_hash_consistency")),
    "e2.aps_call_vs_signed_call": (("aps.manifest", "aps.decision.receipt_id", "aps.decision.signature", "aps.decision_ref"),
                                   ("ps.fixture_pin", "ps.intent_hash_consistency")),
    "e2.exact_call_vs_observation": ((), ("ps.fixture_pin", "ps.intent_hash_consistency", "ps.execution_hash_consistency")),
    "e2.aps_cap_compliance": (("aps.manifest", "aps.delegation"), ("ps.fixture_pin", "ps.execution_hash_consistency")),
    "e2.temporal_nesting": (("aps.manifest", "aps.decision.receipt_id", "aps.decision.signature"),
                            ("ps.fixture_pin", "ps.intent_hash_consistency")),
}


def gate(claim_row: dict[str, Any], aps_rows: list[dict[str, Any]], ps_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """A composition claim over bytes whose integrity failed is void, never a verdict."""
    aps_need, ps_need = DEPENDS[claim_row["claim"]]
    failed = [r["claim"] for r in aps_rows if r["claim"] in aps_need and r["state"] != "pass"]
    failed += [r["claim"] for r in ps_rows if r["claim"] in ps_need and r["state"] != "pass"]
    if not failed:
        return claim_row
    out = row(claim_row["input"], claim_row["claim"], "void",
              "rests on " + ", ".join(sorted(set(failed))) + ", which did not pass; the evaluation over those bytes "
              "would have been: " + claim_row["state"] + " (" + claim_row["detail"][:160] + ")",
              cause="integrity-failure", producer=claim_row.get("producerStated"), lab_entry=claim_row.get("labEntry"))
    return out


def check_payment(base: str, fname: str, label: str, pins: dict[str, Any], aps: dict[str, Any],
                  aps_rows: list[dict[str, Any]], ref_time: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = os.path.join(base, "ps", "priorseal-inputs", fname)
    tag = f"priorseal/{label}"
    rows: list[dict[str, Any]] = []
    raw = open(path, "rb").read()
    pinned = pins["priorseal"]["fixtures"].get(fname)
    rows.append(row(tag, "ps.fixture_pin", "pass" if pinned == sha256_hex(raw) else "fail",
                    f"sha256 {sha256_hex(raw)}, pinned {pinned}"))
    try:
        f = load_json(path)
    except DuplicateMember as e:
        rows.append(row(tag, "ps.parse", "fail", f"duplicate member {e}"))
        return rows, {}
    ae = f["authorizationEvidence"]
    auth = ae["authorization"]
    intent = auth["intent"]
    ex = f["execution"]

    # Claim 2 of the lab record: PriorSeal signatures. No public specification text defines the
    # authorization hash, the acceptance entry hash, the receipt signing input or the EIP-712 typed
    # data; only the SDK source does. Recorded, not guessed.
    rows.append(row(tag, "ps.signatures", "not-exercised",
                    "principal EIP-712 signature, issuer acceptance and receipt signatures: their signing inputs are "
                    "defined only in priorseal-sdk source, not in a specification this checker implements "
                    "(see SPEC-GAPS.md); the lab already holds an independent record for this entry",
                    cause="out_of_scope", lab_entry="2"))
    # Integrity of the signed intent: the hash the signatures cover must recompute from the intent.
    got_ih = sha256_hex(jcs_dumps({k: v for k, v in intent.items() if k != "intentHash"}))
    carried = {intent.get("intentHash"), auth.get("intentHash"), f.get("intentHash"), ae["acceptance"].get("intentHash")}
    rows.append(row(tag, "ps.intent_hash_consistency", "pass" if carried == {got_ih} else "fail",
                    f"SHA-256(JCS(intent without intentHash)) = {got_ih}; carried values {sorted(x for x in carried if x)}. "
                    "Construction recovered by trial against the bytes, not read from a specification."))
    got_eh = sha256_hex(jcs_dumps(ex))
    rows.append(row(tag, "ps.execution_hash_consistency", "pass" if got_eh == f.get("executionHash") else "fail",
                    f"SHA-256(JCS(execution)) = {got_eh}; carried {f.get('executionHash')}. Construction recovered by trial."))

    # Entry 3: decision_ref correlation
    cc = intent.get("contextCommitments") or []
    ns = [c for c in cc if c.get("namespace") == "aps.decision-ref.v1"]
    probs = []
    if len(ns) != 1: probs.append(f"{len(ns)} aps.decision-ref.v1 commitments, exactly one required")
    else:
        c = ns[0]
        if c.get("algorithm") != "sha256": probs.append(f"algorithm {c.get('algorithm')}")
        if c.get("digest") != "0x" + aps["decision_ref"]: probs.append("digest is not 0x + the recomputed APS decision_ref")
    if aps["decision_ref"] != aps["carried_decision_ref"]: probs.append("the APS receipt's decision_ref does not recompute")
    rows.append(row(tag, "e2.decision_ref_correlation", "fail" if probs else "pass",
                    "; ".join(probs) or f"one commitment, sha256, digest 0x{aps['decision_ref']}, equal to the decision_ref "
                    "recomputed from the APS evidence (Section 5.4) and carried in the signed APS receipt. That the "
                    "principal signed this intent rests on entry 2.", lab_entry="3"))

    # APS requested call against the PriorSeal signed call (the mapping the adapter makes)
    call = aps["requested_call"]
    probs = []
    if str(intent.get("chainId")) != call.get("chain_id"): probs.append("chain")
    if (intent.get("callTarget") or "").lower() != call.get("to", "").lower(): probs.append("target")
    if intent.get("transactionValue") != call.get("value_wei"): probs.append("value")
    data = call.get("data", "")
    want_cd = "0x" + keccak256_hex(bytes.fromhex(data[2:] if data.startswith("0x") else data))
    if (intent.get("calldataHash") or "").lower() != want_cd: probs.append("calldata hash")
    rows.append(row(tag, "e2.aps_call_vs_signed_call", "fail" if probs else "pass",
                    "; ".join(probs) or "chain, target, value and Keccak-256 of calldata in the signed intent equal the "
                    "APS policy_input.requested_call"))

    # Entry 4: exact call against the observation, field by field
    pairs = [("chainId", intent.get("chainId"), ex.get("chainId")),
             ("target", (intent.get("callTarget") or "").lower(), (ex.get("target") or "").lower()),
             ("calldataHash", (intent.get("calldataHash") or "").lower(), (ex.get("calldataHash") or "").lower()),
             ("value (transactionValue vs execution.nativeValue)", intent.get("transactionValue"), ex.get("nativeValue")),
             ("sender (delegate.executor vs execution.sender)", (auth.get("delegate", {}).get("executor") or "").lower(), (ex.get("sender") or "").lower()),
             ("nonce", intent.get("nonce"), ex.get("nonce"))]
    diff = [f"{n}: signed {a}, observed {b}" for n, a, b in pairs if a != b]
    rows.append(row(tag, "e2.exact_call_vs_observation", "fail" if diff else "pass",
                    "; ".join(diff) or "every field equal; value read from execution.nativeValue",
                    producer={"compliance": f.get("compliance"), "binding": f.get("binding")}, lab_entry="4"))

    # Entry 5: APS cap compliance, its own claim
    leaf = aps["leaf"]
    spend = leaf["authority"]["spend"]
    unit_note = (f"APS unit {spend.get('unit')} read as the native asset of chain {ex.get('chainId')} in wei, "
                 f"PriorSeal asset {ex.get('asset')}; neither project defines this mapping, it is ours")
    unit_ok = spend.get("unit") == f"eip155:{ex.get('chainId')}:native:wei" and ex.get("asset") == f"eip155:{ex.get('chainId')}/native"
    if not unit_ok:
        rows.append(row(tag, "e2.aps_cap_compliance", "inconclusive", unit_note + "; the units do not map",
                        cause="unsupported_input", lab_entry="5"))
    else:
        obs = int(ex["nativeValue"]); cap = int(spend["per_action"])
        rows.append(row(tag, "e2.aps_cap_compliance", "pass" if obs <= cap else "fail",
                        f"observed nativeValue {obs} against per_action {cap} from the delegation verified under the "
                        f"pinned principal key. {unit_note}. Cumulative spend is not evaluated: one supplied "
                        "spend_state, no ledger.", lab_entry="5"))

    # PriorSeal validity window inside the APS window, and live at the reference time
    aps_vu = iso_ms(aps["valid_until"]).timestamp()
    ref = ref_time.timestamp()
    probs = []
    if intent.get("validUntil") is None or intent["validUntil"] > aps_vu: probs.append("intent validUntil exceeds APS valid_until")
    if not (auth.get("notBefore", 0) <= ref < auth.get("expiresAt", 0)): probs.append("reference time outside notBefore..expiresAt")
    rows.append(row(tag, "e2.temporal_nesting", "fail" if probs else "pass",
                    "; ".join(probs) or f"intent validUntil {intent.get('validUntil')} <= APS valid_until {int(aps_vu)}; "
                    f"reference {int(ref)} inside [{auth.get('notBefore')}, {auth.get('expiresAt')})"))

    own = [r for r in rows if r["claim"].startswith("ps.")]
    rows = [gate(r, aps_rows, own) if r["claim"] in DEPENDS else r for r in rows]
    facts = {"sha256": sha256_hex(raw), "observed": ex.get("nativeValue"), "signedCall": intent.get("transactionValue"),
             "authorizationHash": f.get("authorizationHash"), "compliance": f.get("compliance", {}).get("status"),
             "reasonCodes": f.get("reasonCodes"), "cap": spend.get("per_action"), "unit": spend.get("unit"),
             "file": fname}
    return rows, facts


def check_report(base: str, pins: dict[str, Any], aps_rows_permit: list[dict[str, Any]], pay: dict[str, dict[str, Any]],
                 corr: dict[str, str]) -> list[dict[str, Any]]:
    """Entry 6. An independent implementation does not re-emit another tool's bytes; it verifies the
    committed report's digest and recomputes every value the report states."""
    path = os.path.join(base, "ps", "PAYMENT-LIMIT-REPORT.json")
    raw = open(path, "rb").read()
    tag = "priorseal/PAYMENT-LIMIT-REPORT.json"
    rows = [row(tag, "e2.report_pin", "pass" if sha256_hex(raw) == pins["priorseal"]["report_sha256"] else "fail",
                f"sha256 {sha256_hex(raw)}, pinned {pins['priorseal']['report_sha256']}", lab_entry="6")]
    rep = json.loads(raw)
    aps_dir = os.path.join(base, "aps")
    man = open(os.path.join(aps_dir, "MANIFEST.sha256"), "rb").read()
    n_files = len([ln for ln in man.decode().splitlines() if ln.strip()])
    permit_src = {n: sha256_hex(open(os.path.join(aps_dir, "cases", "permit", n), "rb").read())
                  for n in ("action-intent-receipt.json", "policy-decision-receipt.json", "decision-evidence.json")}
    aps_ok = all(r["state"] == "pass" for r in aps_rows_permit if r.get("labEntry") == "1")
    w, o = pay["within"], pay["over"]
    fields: list[tuple[str, Any, Any, str]] = [
        ("producer.manifestSha256", rep["producer"]["manifestSha256"], sha256_hex(man), "recomputed"),
        ("producer.manifestFiles", rep["producer"]["manifestFiles"], n_files, "recomputed"),
        ("producer.permitSourceSha256", rep["producer"]["permitSourceSha256"], permit_src, "recomputed"),
        ("referenceTime", rep["referenceTime"], pins["reference_time"], "recomputed"),
        ("payment.unit", rep["payment"]["unit"], w["unit"], "recomputed"),
        ("payment.apsPerActionCapWei", rep["payment"]["apsPerActionCapWei"], w["cap"], "recomputed"),
        ("payment.priorSealSignedCallWei", rep["payment"]["priorSealSignedCallWei"], w["signedCall"], "recomputed"),
        ("payment.sharedAuthorizationHash", rep["payment"]["sharedAuthorizationHash"],
         w["authorizationHash"] if w["authorizationHash"] == o["authorizationHash"] else "NOT SHARED", "recomputed"),
        ("payment.sharedDecisionRef", rep["payment"]["sharedDecisionRef"], corr["decision_ref"], "recomputed"),
        ("positive.sha256", rep["positive"]["sha256"], w["sha256"], "recomputed"),
        ("positive.observedNativeValueWei", rep["positive"]["observedNativeValueWei"], w["observed"], "recomputed"),
        ("positive.withinApsCap", rep["positive"]["withinApsCap"], int(w["observed"]) <= int(w["cap"]), "recomputed"),
        ("positive.matchesSignedCall", rep["positive"]["matchesSignedCall"], w["observed"] == w["signedCall"], "recomputed"),
        ("positive.aps", rep["positive"]["aps"], "APS_VERIFIED_AT_REFERENCE" if aps_ok else "APS_NOT_VERIFIED", "recomputed"),
        ("positive.composition", rep["positive"]["composition"],
         "DECISION_AUTHORIZATION_CORRELATED" if corr["within"] == "pass" else "NOT_CORRELATED", "recomputed"),
        ("overLimitNegative.sha256", rep["overLimitNegative"]["sha256"], o["sha256"], "recomputed"),
        ("overLimitNegative.observedNativeValueWei", rep["overLimitNegative"]["observedNativeValueWei"], o["observed"], "recomputed"),
        ("overLimitNegative.aboveApsCap", rep["overLimitNegative"]["aboveApsCap"], int(o["observed"]) > int(o["cap"]), "recomputed"),
        ("overLimitNegative.matchesSignedCall", rep["overLimitNegative"]["matchesSignedCall"], o["observed"] == o["signedCall"], "recomputed"),
        ("overLimitNegative.aps", rep["overLimitNegative"]["aps"], "APS_VERIFIED_AT_REFERENCE" if aps_ok else "APS_NOT_VERIFIED", "recomputed"),
        ("overLimitNegative.composition", rep["overLimitNegative"]["composition"],
         "DECISION_AUTHORIZATION_CORRELATED" if corr["over"] == "pass" else "NOT_CORRELATED", "recomputed"),
        ("positive.priorSealCompliance", rep["positive"]["priorSealCompliance"], w["compliance"], "quoted from the signed fixture, not recomputed"),
        ("overLimitNegative.priorSealCompliance", rep["overLimitNegative"]["priorSealCompliance"], o["compliance"], "quoted from the signed fixture, not recomputed"),
        ("overLimitNegative.reasonCodes", rep["overLimitNegative"]["reasonCodes"], o["reasonCodes"], "quoted from the signed fixture, not recomputed"),
    ]
    for name, stated, ours, how in fields:
        rows.append(row(tag, f"e2.report.{name}", "pass" if stated == ours else "fail",
                        f"report states {json.dumps(stated)}; ours {json.dumps(ours)} ({how})", lab_entry="6"))
    # stated values an independent implementation cannot recompute from these inputs
    for name, stated in (("apsRequestedCallWei", rep["payment"]["apsRequestedCallWei"]),):
        rows.append(row(tag, f"e2.report.payment.{name}", "pass" if stated == w.get("apsCall", stated) else "fail",
                        f"report states {json.dumps(stated)}; ours {json.dumps(w.get('apsCall'))} (recomputed from policy_input.requested_call)", lab_entry="6"))
    for name in ("positive.priorSealReceiptValid", "overLimitNegative.priorSealReceiptValid"):
        sect, key = name.split(".")
        rows.append(row(tag, f"e2.report.{name}", "not-exercised",
                        f"report states {json.dumps(rep[sect][key])}; PriorSeal receipt signatures are outside this "
                        "checker (entry 2)", cause="out_of_scope", lab_entry="6"))
    rows.append(row(tag, "e2.report.scope", "not-exercised",
                    f"scope flags {json.dumps(rep['scope'])} describe the run's limits and are not recomputable from "
                    "the inputs; quoted", cause="not_applicable", lab_entry="6"))
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs")
    ap.add_argument("pins")
    ap.add_argument("--within", default="payment-within-limit.json")
    ap.add_argument("--over", default="payment-over-limit.json")
    ap.add_argument("--aps-case-for-pair", default="permit")
    a = ap.parse_args(argv)
    pins = json.load(open(a.pins))
    ref_time = iso_ms(pins["reference_time"])
    rows: list[dict[str, Any]] = []
    # APS manifest, then the four cases
    aps_dir = os.path.join(a.inputs, "aps")
    man_raw = open(os.path.join(aps_dir, "MANIFEST.sha256"), "rb").read()
    probs = []
    if sha256_hex(man_raw) != pins["aps"]["manifest_sha256"]: probs.append("manifest digest differs from the pin")
    for ln in man_raw.decode().splitlines():
        if not ln.strip(): continue
        digest, name = ln.split(None, 1)
        name = name.lstrip("*").strip()
        if sha256_hex(open(os.path.join(aps_dir, name), "rb").read()) != digest: probs.append(f"{name} differs")
    rows.append(row("aps", "aps.manifest", "fail" if probs else "pass", "; ".join(probs) or "manifest pinned; every listed file matches", lab_entry="1"))
    facts: dict[str, Any] = {}
    for c in APS_CASES:
        r, fct = check_aps_case(a.inputs, c, pins, ref_time)
        rows += r
        facts[c] = fct
    aps = facts[a.aps_case_for_pair]
    permit_rows = [r for r in rows if r["input"] in ("aps", f"aps/{a.aps_case_for_pair}")]
    pay: dict[str, dict[str, Any]] = {}
    corr: dict[str, str] = {"decision_ref": aps.get("decision_ref", "")}
    for label, fname in (("within", a.within), ("over", a.over)):
        r, fct = check_payment(a.inputs, fname, label, pins, aps, permit_rows, ref_time)
        rows += r
        fct["apsCall"] = aps["requested_call"]["value_wei"]
        pay[label] = fct
        corr[label] = next(x["state"] for x in r if x["claim"] == "e2.decision_ref_correlation")
    if os.path.exists(os.path.join(a.inputs, "ps", "PAYMENT-LIMIT-REPORT.json")) and pins["priorseal"].get("report_sha256"):
        rows += check_report(a.inputs, pins, permit_rows, pay, corr)
    out = {
        "checker": "thread-177 e2check",
        "vocabulary": {"states": list(STATES), "causes": list(CAUSES),
                       "rule": "cause required on inconclusive, not-exercised and void; absent on pass and fail"},
        "referenceTime": pins["reference_time"],
        "rows": rows,
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

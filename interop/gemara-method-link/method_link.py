"""Check declared Gemara plan, method and executor relationships.

This draft profile consumes already validated documents using the shape proposed
in Gemara #506. It checks cross-document references, not signatures, actual
execution, method reliability (#496), or conflict-resolution outcomes (#482).
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Mapping
import hashlib
import json
import logging
from pathlib import Path
import shlex
import subprocess
from typing import Any

LOGGER = logging.getLogger(__name__)
Document = Mapping[str, Any]


class CorpusError(ValueError):
    """The pinned fixture corpus cannot be read or reproduced."""


def assessments(log: Document) -> list[tuple[int, int, Document]]:
    """Return assessment positions without changing the source log.

    Parameters
    ----------
    log
        A Gemara EvaluationLog using the proposed #506 shape.

    Returns
    -------
    list
        Control index, assessment index, and the original assessment mapping.
        Indices keep equal names in separate control evaluations distinct.
    """
    return [
        (control_index, assessment_index, assessment)
        for control_index, control in enumerate(log["evaluations"])
        for assessment_index, assessment in enumerate(control["assessment-logs"])
    ]


def _identity(control_index: int, assessment: Document) -> tuple[Any, ...]:
    plan = assessment.get("plan", {})
    requirement = assessment["requirement"]
    return (
        control_index,
        requirement.get("reference-id"),
        requirement["entry-id"],
        plan.get("reference-id"),
        plan.get("entry-id"),
        assessment.get("plan-inputs", {}).get("method-id"),
    )


def shape_errors(log: Document) -> list[str]:
    """Check the three shape rules exercised by this corpus.

    This is a bounded precheck, not a replacement for Gemara's CUE schema.
    Plan and plan-inputs occur together; method-id is required with a plan;
    an exact assessment identity cannot occur twice. The identity uses full
    mapping references so distinct bound policies are not collapsed.
    """
    errors: list[str] = []
    seen: set[tuple[Any, ...]] = set()
    for control_index, assessment_index, assessment in assessments(log):
        location = f"e{control_index}.a{assessment_index}"
        errors.extend(_input_errors(assessment, location))
        key = _identity(control_index, assessment)
        if key in seen:
            errors.append(f"duplicate_assessment:{location}")
        seen.add(key)
    return errors


def _input_errors(assessment: Document, location: str) -> list[str]:
    has_plan = "plan" in assessment
    has_inputs = "plan-inputs" in assessment
    if has_inputs and not has_plan:
        return [f"plan_inputs_without_plan:{location}"]
    if has_plan and "method-id" not in assessment.get("plan-inputs", {}):
        return [f"method_input_missing:{location}"]
    return []


def _find(entries: list[Document], identifier: str) -> list[Document]:
    return [entry for entry in entries if entry["id"] == identifier]


def _resolve(
    assessment: Document, policies: Document
) -> tuple[str, Document | None]:
    plan_ref = assessment.get("plan")
    if plan_ref is None:
        return "unplanned", None
    policy = policies.get(plan_ref["reference-id"])
    if policy is None:
        return "unknown_policy", None
    plans = _find(
        policy["adherence"].get("assessment-plans", []), plan_ref["entry-id"]
    )
    if len(plans) != 1:
        return ("unknown_plan" if not plans else "ambiguous_plan"), None
    return _resolve_method(assessment, plans[0])


def _resolve_method(
    assessment: Document, plan: Document
) -> tuple[str, Document | None]:
    if assessment["requirement"]["entry-id"] != plan["requirement-id"]:
        return "wrong_requirement", None
    method_id = assessment["plan-inputs"]["method-id"]
    methods = _find(plan["evaluation-methods"], method_id)
    if len(methods) != 1:
        return ("unknown_method" if not methods else "ambiguous_method"), None
    return "matched", methods[0]


def _executor_state(
    assessment: Document, method: Document | None, author: Document
) -> tuple[str, str]:
    source = "explicit" if "executor" in assessment else "log_author"
    declared_executor = assessment.get("executor", author)
    if method is None:
        return "unresolved", source
    accepted_executor = method.get("executor")
    if accepted_executor is None:
        return "unconstrained", source
    state = "match" if declared_executor["id"] == accepted_executor["id"] else "mismatch"
    return state, source


def _linked_rows(log: Document, policies: Document) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for control_index, assessment_index, assessment in assessments(log):
        state, method = _resolve(assessment, policies)
        executor, source = _executor_state(assessment, method, log["metadata"]["author"])
        rows.append(
            {
                "position": f"e{control_index}.a{assessment_index}",
                "method": state,
                "executor": executor,
                "executor_source": source,
                "reported_result": assessment["result"],
            }
        )
    return rows


def _conflicts(log: Document, rows: list[dict[str, Any]]) -> list[list[str]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for (control_index, _, assessment), row in zip(assessments(log), rows, strict=True):
        if row["method"] == "matched":
            groups[_identity(control_index, assessment)[:-1]].append(row)
    return [
        [row["position"] for row in group]
        for group in groups.values()
        if {"Passed", "Failed"} <= {row["reported_result"] for row in group}
    ]


def check_links(bundle: Document) -> dict[str, Any]:
    """Return relationship findings while retaining mismatched reported events.

    Parameters
    ----------
    bundle
        A mapping with log and policies. The policies mapping explicitly binds
        mapping-reference IDs to policy documents. This function neither
        fetches documents nor chooses their versions. Documents must first
        pass their native schema; :func:`shape_errors` checks only corpus
        preconditions. Repeated plan or method IDs are reported as ambiguous.

    Returns
    -------
    dict
        Shape errors, per-assessment method and declared-executor findings,
        and groups containing both Passed and Failed reports. A mismatch
        remains a row. Conflict detection does not choose a winning method.

    Notes
    -----
    Executor comparison uses declared IDs, not display names. It authenticates
    no actor and establishes no independent evidence of execution. The draft
    uses #506's convention that an omitted executor denotes metadata.author.
    """
    log = bundle["log"]
    errors = shape_errors(log)
    if errors:
        return {"shape_errors": errors, "rows": [], "conflicts": []}
    rows = _linked_rows(log, bundle["policies"])
    return {"shape_errors": [], "rows": rows, "conflicts": _conflicts(log, rows)}


def _fail(message: str) -> None:
    LOGGER.error(message)
    raise CorpusError(message)


def _read_pinned(root: Path, path: str, digest: str) -> bytes:
    target = (root / path).resolve()
    if not target.is_relative_to(root.resolve()):
        _fail(f"fixture path escapes corpus: {path}")
    data = target.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        _fail(f"fixture digest mismatch: {path}")
    return data


def load_cases(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read fixtures only after checking every byte against MANIFEST.json.

    Parameters
    ----------
    root
        Corpus directory containing the checked-in manifest and case files.

    Returns
    -------
    tuple
        The manifest and complete case data. Hashes detect drift against the
        manifest; the manifest digest printed by :func:`run` is the pin.

    Raises
    ------
    CorpusError
        A fixture path escapes the corpus or its digest does not match.
    """
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="ascii"))
    for source in manifest["sources"]:
        _read_pinned(root, source["path"], source["sha256"])
    cases = [
        json.loads(_read_pinned(root, entry["path"], entry["sha256"]))
        for entry in manifest["cases"]
    ]
    return manifest, cases


def _adapter(command: str, bundle: Document) -> dict[str, Any]:
    result = subprocess.run(
        shlex.split(command),
        input=json.dumps(bundle, ensure_ascii=True),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        _fail(f"adapter exited {result.returncode}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def run(root: Path, command: str | None = None) -> dict[str, Any]:
    """Score a reader while sending it input documents only.

    The optional command reads a bundle as JSON on stdin and writes one result
    object to stdout. Expected answers never enter the reader's stdin. This
    contract permits another implementation; it does not establish that an
    implementation was developed independently or without reading the corpus.
    """
    manifest, cases = load_cases(root)
    rows = []
    for case in cases:
        actual = _adapter(command, case["input"]) if command else check_links(case["input"])
        rows.append(
            {"id": case["id"], "matches": actual == case["expected"], "actual": actual}
        )
    return {
        "corpus": manifest["corpus"],
        "manifest_sha256": hashlib.sha256((root / "MANIFEST.json").read_bytes()).hexdigest(),
        "matched": sum(row["matches"] for row in rows),
        "total": len(rows),
        "rows": rows,
    }


def main() -> int:
    """Run the corpus, or answer one reader request from stdin."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", help="reader command; no shell is used")
    parser.add_argument("--stdin", action="store_true", help="answer one input bundle")
    parser.add_argument("--corpus", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    if args.stdin:
        import sys

        print(json.dumps(check_links(json.load(sys.stdin)), sort_keys=True))
        return 0
    report = run(args.corpus, args.adapter)
    print(json.dumps(report, sort_keys=True, indent=2))
    return int(report["matched"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())

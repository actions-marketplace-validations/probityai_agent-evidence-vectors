"""Apply a selected dual-name policy without rewriting received card fields.

The frozen descriptor projection covers the 21 message types reachable from
AgentCard in SDK 1.2.1. Unknown objects and protobuf Struct values stay opaque.
Signature verification reuses the retained-field ES256 implementation; this
module supplies the additional, separately selected admission condition.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "a2a-s3-retain-2026-10-01"))
from retain_gate import AdmissionResult, admit, refuse  # noqa: E402

SCHEMA = json.loads((ROOT / "schema-aliases.json").read_text())
POLICIES = ("dual-name-tolerate", "dual-name-refuse")


def child_objects(value: Any, kind: str) -> list[Any]:
    """Select schema-owned message children while preserving original values.

    Parameters
    ----------
    value : Any
        A field value whose descriptor declares a message, repeated message,
        or map of messages. Null values carry no message children.
    kind : str
        Frozen descriptor edge kind from ``schema-aliases.json``.

    Returns
    -------
    list[Any]
        References to the supplied children, never normalized or copied.

    Raises
    ------
    retain_gate.PolicyError
        If a repeated-message or message-map container has the wrong shape.
    """
    if value is None:
        return []
    if kind == "repeated":
        if not isinstance(value, list):
            refuse("schema message array must be an array")
        return value
    if kind == "map":
        if not isinstance(value, dict):
            refuse("schema message map must be an object")
        return list(value.values())
    return [value]


def check_field(obj: dict[str, Any], field: dict[str, str], path: str) -> None:
    """Refuse both names of one schema field, then visit its message children.

    The check depends on message context. Similar-looking keys in an unknown
    member, Struct, scalar map, or another message do not become aliases.
    Even equal or null values under both names are ambiguous and refuse.
    """
    names = tuple(dict.fromkeys((field["json_name"], field["proto_name"])))
    present = [name for name in names if name in obj]
    if len(present) > 1:
        refuse(f"dual schema names at {path}: {names[0]} and {names[1]}")
    if not present or not field["message"]:
        return
    key = present[0]
    for index, child in enumerate(child_objects(obj[key], field["kind"])):
        check_names(child, field["message"], f"{path}/{key}/{index}")


def check_names(obj: Any, message: str = SCHEMA["root"], path: str = "$") -> None:
    """Check aliases throughout the frozen AgentCard message graph.

    Parameters
    ----------
    obj : Any
        Received message object. No parser conversion or canonicalization has
        occurred; :func:`check_field` handles aliases in this exact object.
    message : str
        Descriptor message name selected by the parent schema edge.
    path : str
        Diagnostic location, including positions of traversed children.

    Raises
    ------
    retain_gate.PolicyError
        If a message is not an object or any field has both schema names.

    Notes
    -----
    This is an alias gate, not full schema validation. Unknown fields retain
    their values and remain covered by retained-field signature verification.
    """
    if not isinstance(obj, dict):
        refuse(f"schema message must be an object at {path}")
    for field in SCHEMA["messages"][message]:
        check_field(obj, field, path)


def admit_with_policy(card: dict[str, Any], jwk: dict[str, Any], policy: str) -> AdmissionResult:
    """Evaluate a caller-selected alias policy and the retained JSON signature.

    ``dual-name-refuse`` adds :func:`check_names` before the unchanged ES256
    gate. ``dual-name-tolerate`` verifies both members as received. Neither
    policy tries a normalized fallback payload. The policy label in the result
    identifies this candidate selection, not an adopted A2A requirement.
    """
    if policy not in POLICIES:
        refuse("unsupported dual-name policy")
    if policy == "dual-name-refuse":
        check_names(card)
    result = admit(card, jwk)
    return AdmissionResult(result.admitted, result.signature_results, policy)

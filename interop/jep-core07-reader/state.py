"""Synthetic atomic acceptance and a read-only view of committed local effects."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

from validator import unsigned


def initialize(root: Path) -> None:
    """Create isolated test state before the preregistered assertion starts."""
    root.mkdir(parents=True, exist_ok=False)
    with sqlite3.connect(root / "acceptance.sqlite") as connection:
        connection.execute(
            "CREATE TABLE accepted (domain TEXT, actor TEXT, id TEXT, digest TEXT, "
            "PRIMARY KEY (domain, actor, id))"
        )
        connection.execute(
            "CREATE TABLE effects (domain TEXT, actor TEXT, id TEXT, "
            "PRIMARY KEY (domain, actor, id))"
        )


def accept(root: Path, domain: str, event: dict[str, Any]) -> dict[str, Any]:
    """Commit acceptance identity and its synthetic effect in one transaction.

    No external side effect is performed. SQLite serializes concurrent writers,
    and each adapter process opens existing state. A missing/unavailable store
    refuses a fresh acceptance rather than claiming an unapplied effect.
    """
    if (root / "unavailable").exists():
        return {"outcome": "indeterminate", "effect_applied": False}
    try:
        database = (root / "acceptance.sqlite").resolve().as_uri() + "?mode=rw"
        with sqlite3.connect(database, uri=True, timeout=10) as connection:
            connection.execute("BEGIN IMMEDIATE")
            return _transaction(connection, domain, event)
    except sqlite3.Error:
        return {"outcome": "indeterminate", "effect_applied": False}


def _transaction(
    connection: sqlite3.Connection, domain: str, event: dict[str, Any]
) -> dict[str, Any]:
    """Compare unsigned content before either identity or effect is written."""
    identity = (domain, event["who"], event["id"])
    digest = hashlib.sha256(unsigned(event)).hexdigest()
    previous = connection.execute(
        "SELECT digest FROM accepted WHERE domain=? AND actor=? AND id=?", identity
    ).fetchone()
    if previous:
        return {
            "outcome": "already_accepted" if previous[0] == digest else "rejected",
            "effect_applied": False,
        }
    connection.execute("INSERT INTO accepted VALUES (?,?,?,?)", (*identity, digest))
    connection.execute("INSERT INTO effects VALUES (?,?,?)", identity)
    return {"outcome": "accepted", "effect_applied": True}


def observe(root: Path, domain: str) -> int:
    """Count actual committed effect rows through SQLite's read-only connection.

    Missing or unreadable state raises an error. The probe never manufactures a
    zero result from a missing database and never counts adapter flags.
    """
    uri = (root / "acceptance.sqlite").resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=10) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM effects WHERE domain=?", (domain,)
        ).fetchone()
        if row is None:
            raise ValueError("read-only effect probe returned no count")
        return int(row[0])

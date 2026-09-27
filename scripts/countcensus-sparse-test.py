#!/usr/bin/env python3
"""Tests for the tracked-file reader in scripts/countcensus.py.

THE DEFECT (2026-09-27). `read_tracked` listed the tracked files and then opened
each one on disk. A sparse checkout holds only the paths somebody asked for, so a
tracked file outside the cone is in the index and absent from disk, and the read
died with FileNotFoundError. A consumer gate in another repository reads its whole
outbound corpus through this function, and every send from a sparse lane stopped.

The repair that would have looked cheapest is the one these cases exist to refuse:
skipping the absent file. The census would then count fewer integers and pass, and
nothing in its output would say a file went unread. So the property asserted here
is equality, not absence of a crash: a SPARSE checkout of a commit reads exactly the
text a FULL checkout of the same commit reads, and a census over each examines the
same integers and refuses the same ones.

THE MUTATION CHECK. A test that cannot go red proves nothing, so the same cases are
then run against copies of countcensus.py each broken in one way that the repair
is meant to exclude -- the skip, an empty read, a lost uncommitted edit, a missing
object read as empty -- and every mutant must fail at least one case. A mutant
that survives is a guarantee this file does not actually hold, and it fails the
run by name.

Usage: python3 scripts/countcensus-sparse-test.py
Exit 0 when every case holds and every mutant is killed; 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

ENGINE = Path(__file__).resolve().parent / "countcensus.py"

#: The fixture's numbers, built rather than written. This file is itself prose the
#: repository's own count gate reads, and a literal figure beside a count noun here
#: would be a count-shaped integer that gate has to account for.
CURRENT = 6 * 7
SMALL = (2 + 1, 3 + 4, 3 * 3, 6 + 7)

#: The fixture's files. Paths with a space and a non-ASCII byte are here because a
#: listing split on whitespace, or one git quotes, names a file that does not exist.
FILES = {
    "keep/intro.md": f"The corpus carries {CURRENT} widgets across {SMALL[1]} kinds.\n",
    "keep/notes.txt": "Nothing to count here.\n",
    "away/report.md": f"We measured {CURRENT} widgets and {SMALL[3]} of {CURRENT} failed.\n",
    "away/deep/table.toml": f'summary = "{CURRENT} widgets, {SMALL[0]} of {SMALL[1]} kinds"\n',
    "away/with space.md": f"A body naming {CURRENT} widgets.\n",
    "away/caf\u00e9.md": f"Another {CURRENT} widgets, {SMALL[2]} kinds.\n",
    "away/tool.py": f'# {CURRENT} widgets checked here\nprint("{SMALL[3]} of {CURRENT}")\n',
    "away/binary.bin": "not read: suffix not wanted\n",
}
EDITED = f"An unsent draft says {CURRENT + 1} widgets.\n"
SUFFIXES = {".md", ".txt", ".toml", ".py"}


def git(root: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    ).stdout


def fixture(tmp: Path) -> tuple[Path, Path]:
    """A committed origin, a full clone of it, and a sparse clone holding `keep/` only."""
    origin = tmp / "origin"
    origin.mkdir(parents=True)
    git(origin, "init", "-q", "-b", "main")
    for rel, text in FILES.items():
        path = origin / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    os.symlink("intro.md", origin / "keep" / "link.md")
    git(origin, "add", "-A")
    git(origin, "commit", "-q", "-m", "fixture")
    full = tmp / "full"
    sparse = tmp / "sparse"
    subprocess.run(["git", "clone", "-q", str(origin), str(full)], check=True, capture_output=True)
    subprocess.run(
        ["git", "clone", "-q", "--no-checkout", str(origin), str(sparse)],
        check=True,
        capture_output=True,
    )
    git(sparse, "sparse-checkout", "set", "--cone", "keep")
    git(sparse, "checkout", "-q", "main")
    if (sparse / "away").exists():
        raise SystemExit("FIXTURE: the sparse clone materialised away/, so it tests nothing")
    return full, sparse


def load(source: str, name: str) -> ModuleType:
    """Import an engine from source text, so a mutant never touches the real file."""
    holder = Path(tempfile.mkdtemp(prefix="census-mutant-"))
    path = holder / "countcensus.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def census_of(engine: ModuleType, texts: dict[str, str]) -> tuple[list[str], int]:
    """A minimal consumer: CURRENT is a current value and `widgets`/`kinds` are nouns."""
    census = engine.Census(
        masks=(),
        nouns=(
            (re.compile(r"\b(\d+)\s+widgets\b"), "a widget count"),
            (re.compile(r"\b(\d+)\s+kinds\b"), "a kind count"),
        ),
        small_value_nouns=re.compile(r"widgets|kinds"),
    )
    quantities = engine.Quantities(current={CURRENT: "the widget count"})
    result: tuple[list[str], int] = engine.run_census(census, quantities, texts, {})
    return result


Case = Callable[[ModuleType, Path, Path], str | None]


def case_whole_tree_equal(engine: ModuleType, full: Path, sparse: Path) -> str | None:
    a = engine.read_tracked(full, SUFFIXES)
    b = engine.read_tracked(sparse, SUFFIXES)
    if a != b:
        return f"whole-tree read differs: full has {sorted(a)}, sparse has {sorted(b)}"
    if "away/report.md" not in b or "away/café.md" not in b:
        return f"the sparse read is missing a file outside the cone: {sorted(b)}"
    return None


def case_named_paths_equal(engine: ModuleType, full: Path, sparse: Path) -> str | None:
    named = ["keep/intro.md", "away/report.md", "away/with space.md", "away/deep/table.toml"]
    for ref in (None, "HEAD"):
        a = engine.read_tracked(full, SUFFIXES, paths=named, ref=ref)
        b = engine.read_tracked(sparse, SUFFIXES, paths=named, ref=ref)
        if a != b or sorted(b) != sorted(named):
            return f"named read at {ref or 'the index'} differs: {sorted(a)} vs {sorted(b)}"
    return None


def case_same_census(engine: ModuleType, full: Path, sparse: Path) -> str | None:
    a = census_of(engine, engine.read_tracked(full, SUFFIXES))
    b = census_of(engine, engine.read_tracked(sparse, SUFFIXES))
    if a != b:
        return f"census differs: full examined {a[1]}, sparse examined {b[1]}"
    if a[1] < len(FILES):
        return f"the census examined only {a[1]} integers, so equality proves little"
    return None


def case_uncommitted_edit_wins(engine: ModuleType, full: Path, sparse: Path) -> str | None:
    del full
    body = sparse / "keep" / "intro.md"
    original = body.read_text(encoding="utf-8")
    body.write_text(EDITED, encoding="utf-8")
    try:
        got = engine.read_tracked(sparse, SUFFIXES, paths=["keep/intro.md"])
    finally:
        body.write_text(original, encoding="utf-8")
    if got.get("keep/intro.md") != EDITED:
        return f"an uncommitted edit on disk was not what was read: {got!r}"
    return None


def case_deleted_file_reads_as_tracked(engine: ModuleType, full: Path, sparse: Path) -> str | None:
    del sparse
    gone = full / "away" / "report.md"
    gone.unlink()
    try:
        got = engine.read_tracked(full, SUFFIXES)
    finally:
        git(full, "checkout", "--", "away/report.md")
    if got.get("away/report.md") != FILES["away/report.md"]:
        return "a tracked file deleted from disk was not read from its blob"
    return None


def case_unknown_path_is_absent(engine: ModuleType, full: Path, sparse: Path) -> str | None:
    del full
    got = engine.read_tracked(sparse, SUFFIXES, paths=["keep/intro.md", "nowhere/at-all.md"])
    if sorted(got) != ["keep/intro.md"]:
        return f"a path neither on disk nor tracked was not left out: {sorted(got)}"
    return None


def case_missing_object_refuses(engine: ModuleType, full: Path, sparse: Path) -> str | None:
    del full
    try:
        engine.read_blobs(sparse, {"away/lost.md": "0" * 40})
    except engine.TrackedUnreadable as exc:
        return None if "away/lost.md" in str(exc) else f"refusal does not name the path: {exc}"
    except Exception as exc:  # noqa: BLE001 - any other failure is the finding
        return f"a missing object raised {type(exc).__name__}, not TrackedUnreadable"
    return "a blob the object store does not hold was read as a file"


def case_absent_symlink_refuses(engine: ModuleType, full: Path, sparse: Path) -> str | None:
    del full
    link = sparse / "keep" / "link.md"
    link.unlink()
    try:
        engine.read_tracked(sparse, SUFFIXES)
    except engine.TrackedUnreadable:
        return None
    except Exception as exc:  # noqa: BLE001 - any other failure is the finding
        return f"an absent tracked symlink raised {type(exc).__name__}"
    finally:
        git(sparse, "checkout", "--", "keep/link.md")
    return "an absent tracked symlink was read or dropped instead of refused"


CASES: list[tuple[str, Case]] = [
    ("a sparse checkout reads the whole tree a full one reads", case_whole_tree_equal),
    ("named paths read the same, at the index and at HEAD", case_named_paths_equal),
    ("the census examines and refuses the same integers", case_same_census),
    ("an uncommitted edit on disk is what is read", case_uncommitted_edit_wins),
    ("a tracked file deleted from disk reads as its blob", case_deleted_file_reads_as_tracked),
    ("a path neither on disk nor tracked is left out", case_unknown_path_is_absent),
    ("a missing object refuses by path", case_missing_object_refuses),
    ("an absent tracked symlink refuses", case_absent_symlink_refuses),
]

#: Each mutant removes one guarantee the repair makes. (name, old, new).
MUTANTS: list[tuple[str, str, str]] = [
    (
        "skip a tracked file that is absent from disk",
        "and (rel in tree.modes or tree.on_disk(rel))",
        "and tree.on_disk(rel)",
    ),
    (
        "read an absent file as empty",
        "        return self._blobs[rel]\n",
        '        return b""\n',
    ),
    (
        "read the blob even when the file is on disk",
        "    def read_bytes(self, rel: str) -> bytes:\n        if self.on_disk(rel):",
        "    def read_bytes(self, rel: str) -> bytes:\n        if False:",
    ),
    (
        "accept whatever cat-file answers for a blob",
        'if len(header) != 3 or header[1] != "blob" or header[0] != blob:',
        "if False:",
    ),
    (
        "read a symlink's blob as the file",
        "        if entry[0] not in _FILE_MODES:\n            raise TrackedUnreadable(",
        "        if False:\n            raise TrackedUnreadable(",
    ),
]


def run_cases(engine: ModuleType, tmp: Path) -> list[str]:
    full, sparse = fixture(tmp)
    failures: list[str] = []
    for name, case in CASES:
        try:
            problem = case(engine, full, sparse)
        except Exception as exc:  # noqa: BLE001 - a crash is a failed case
            problem = f"raised {type(exc).__name__}: {exc}"
        if problem:
            failures.append(f"{name}: {problem}")
    return failures


def main() -> int:
    source = ENGINE.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="census-sparse-") as tmp:
        failures = run_cases(load(source, "countcensus_under_test"), Path(tmp) / "real")
        for name in failures:
            print(f"FAIL  {name}")
        for index, (name, old, new) in enumerate(MUTANTS):
            if source.count(old) != 1:
                failures.append(f"mutant '{name}' matched {source.count(old)} sites, not 1")
                print(f"FAIL  mutant '{name}' no longer matches the engine; update it")
                continue
            mutant = load(source.replace(old, new), f"countcensus_mutant_{index}")
            killed = run_cases(mutant, Path(tmp) / f"mutant-{index}")
            if killed:
                print(f"ok    mutant '{name}' killed ({len(killed)} case(s) red)")
            else:
                failures.append(f"mutant '{name}' survived every case")
                print(f"FAIL  mutant '{name}' survived every case")
    if failures:
        print(f"\n{len(failures)} failure(s)")
        return 1
    print(f"\nall {len(CASES)} cases hold and all {len(MUTANTS)} mutants are killed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

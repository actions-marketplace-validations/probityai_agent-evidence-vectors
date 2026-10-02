"""Retain a fresh bounded AgentID report; no network or producer scripts are used."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

from reader import MAX_BYTES, InputError, evaluate, refuse


def read_bounded(path: Path) -> bytes:
    """Read at most the profile budget plus one byte, refusing oversized files.

    A bounded read, instead of an initial stat followed by read_bytes, also limits
    memory if the file changes after inspection. Normal file-access failures
    propagate to main and prevent a report from being written.
    """
    with path.open("rb") as stream:
        payload = stream.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        refuse("JSON byte budget exceeded")
    return payload


def main(argv: list[str] | None = None) -> int:
    """Read three inputs and atomically write a report inside a new directory.

    Parameters
    ----------
    argv : list[str] or None
        Command-line arguments; None uses sys.argv. All four paths are required.

    Returns
    -------
    int
        0 means all eight bounded comparisons matched and a fresh report exists;
        1 means a fresh report records a contradiction; 2 means input or output
        handling failed and no successful report was produced by this invocation.
        An existing output directory is always refused, even when empty.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--jwks", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        args.output_dir.mkdir(parents=False, exist_ok=False)
        inputs = tuple(map(read_bounded, (args.attestation, args.request, args.jwks)))
        report = evaluate(*inputs)
        report["reader_sha256"] = hashlib.sha256(
            Path(__file__).with_name("reader.py").read_bytes()
        ).hexdigest()
        temporary = args.output_dir / "report.json.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        temporary.replace(args.output_dir / "report.json")
    except (InputError, OSError) as exc:
        logging.getLogger(__name__).error("run failed: %s", exc)
        return 2
    print(
        json.dumps(
            {
                "report": str(args.output_dir / "report.json"),
                "all_comparisons_match": report["all_comparisons_match"],
            }
        )
    )
    return 0 if report["all_comparisons_match"] else 1


if __name__ == "__main__":
    sys.exit(main())

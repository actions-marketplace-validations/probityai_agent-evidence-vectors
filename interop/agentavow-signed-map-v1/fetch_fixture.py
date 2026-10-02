"""Fetch the one selected native packet for evaluation, outside the source tree."""

from __future__ import annotations

import argparse
import hashlib
import urllib.request
from pathlib import Path

from map_reader import ROOT, load_json, refuse


def fetch(output: Path) -> None:
    """Retain a single bounded response only if its selected digest matches.

    Parameters
    ----------
    output : pathlib.Path
        Fresh destination whose parent exists. Existing files are never reused
        or overwritten, so a previous report cannot disguise a failed fetch.

    Raises
    ------
    map_reader.InputError
        If the response exceeds 256 KiB or differs from the immutable source
        selection. Network and filesystem errors propagate as failures.
    """
    selected = load_json((ROOT / "source-lock.json").read_bytes())["fixture"]
    with urllib.request.urlopen(selected["url"], timeout=30) as response:
        raw = response.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        refuse("native fixture exceeds the selected size guard")
    if hashlib.sha256(raw).hexdigest() != selected["sha256"]:
        refuse("native fixture digest differs from the selected source")
    with output.open("xb") as destination:
        destination.write(raw)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    fetch(parser.parse_args().output)

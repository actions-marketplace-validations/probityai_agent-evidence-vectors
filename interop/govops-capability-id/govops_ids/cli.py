"""Installed stdin contract for descriptor and signed-record comparison."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .reader import Admitter, evaluate


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare raw descriptor identity and explicit signed decision bindings")
    parser.add_argument("--admitter", type=Path, required=True)
    parser.add_argument("--profile", choices=("rfc8785", "ijson", "ijson-integers"), default="ijson-integers")
    parser.add_argument("--max-depth", type=int, default=32)
    parser.add_argument("--max-bytes", type=int, default=1048576)
    parser.add_argument("--trusted-key", action="append", default=[], metavar="AUTHORITY=HEX")
    parser.add_argument("--expected-authority")
    options = parser.parse_args()
    if options.max_depth < 0 or options.max_depth > 128 or options.max_bytes < 0 or options.max_bytes > 20971520:
        parser.error("caps may only lower jcs-admit defaults")
    keys = {}
    try:
        for pair in options.trusted_key:
            authority, key = pair.rsplit("=", 1)
            public = bytes.fromhex(key)
            if not authority or len(public) != 32 or authority in keys:
                raise ValueError("invalid or duplicate authority key")
            keys[authority] = public
    except ValueError:
        parser.error("trusted keys need unique nonempty authorities and Ed25519 public key hex")
    admitter = Admitter(options.admitter.resolve(), options.profile, options.max_depth, options.max_bytes)
    result = evaluate(sys.stdin.buffer.read(options.max_bytes + 1), admitter, keys, options.expected_authority)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["verdict"] in ("bound", "correlated") else 1


if __name__ == "__main__":
    raise SystemExit(main())

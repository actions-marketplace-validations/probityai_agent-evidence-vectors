# Local run

Base: `probityai/agent-evidence-vectors` main `a430a9cf7a4b137d6cb899506119a1b320d1cf16`. Python 3.12.14, using the repository checkout's `packaging` source. The repository metadata requires Python 3.13 for release; CI on this unpublished patch has not run.

| Command | Result |
| --- | --- |
| `PYTHONPATH=packaging python interop/ws4-prior-witness-candidate/gen_fixture.py --check` | Five fixture files reproduced exactly. |
| `PYTHONPATH=packaging python interop/ws4-prior-witness-candidate/run.py` | Three candidate results matched `EXPECTED.json`. |
| `PYTHONPATH=packaging python -m unittest discover -s interop/ws4-prior-witness-candidate -p 'test_profile.py' -q` | Five tests passed, including path and malformed witness controls. |
| `uv sync --extra dev --extra generators`, `uv pip install --no-deps .`, `PYTHONPATH=packaging uv run --extra dev --extra generators python scripts/typecheck-gate.py` | 170 tracked Python files type-checked clean from an exact-index export with the installed checkout wheel in Python 3.14.7. |
| `ruff check interop/ws4-prior-witness-candidate` and `ruff format --check interop/ws4-prior-witness-candidate` | Clean on the exact-index export. |

This run was local and author-operated. The test key is public, and no external witness held the head before an actual invocation.

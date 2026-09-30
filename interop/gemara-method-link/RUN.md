# Local draft run

Run date: 2026-09-30. Python 3.12.14, pytest 9.1.1, Hypothesis 6.168.3.
This is an author-produced run. It is not signed, independently witnessed,
or externally preregistered.

- Current reader/control report manifest SHA-256: `5448e5684565ea3c4211aa41ffe9a9998ad24c35b6ae6e42e125695e1accb70c`.
- Original 32-test suite manifest SHA-256 (before license packaging): `b0cda7d30ce37f6fb48ee6778b992ffcdd8f365469c3c77f5229b02f9fb1a4c9`.
- Reader SHA-256: `603c01061bf73563acdce846db8fd25d0330ef8a3307eca55c971825f43b7c7a`.
- Tests SHA-256: `893ddcc8dd7ff7840eb4e9620821567d36782f6e45ff8d60f6fc46372af3aa64`.
- Bundled reader: 20/20 matching answers. Raw output: `result.json`.
- Bundled reader through stdin adapter: 20/20. This uses the same code.
- Accept-all control: 3/20 matching answers, exit 1. Raw output: `negative-control.json`.
- pytest: 32 passed. Raw output: `pytest-result.txt`.

The CI proposal is inactive. If this directory is placed at
`interop/gemara-method-link` in agent-evidence-vectors, install
`ci-proposal.yml` as `.github/workflows/gemara-method-link.yml`. It exercises
the reader and pytest suite, including the negative control. Its action SHAs
were checked against the official actions repositories.

Native Gemara CUE validation and a separately written reader remain pending.
The proposal scores declared relationships only. It does not prove method
reliability, actual execution, actor authenticity, or observed effects.

License packaging update, September 30: the exact upstream Apache-2.0 LICENSE is included and hashed by the current manifest. The bundled author reader and accept-all control were rerun once against that manifest; all case answers/counts were unchanged and only their report provenance pins changed. The 20 case files, four upstream source files, reader and tests are unchanged. Integrity-manifest validation was repeated; the 32 pytest tests were not repeated.

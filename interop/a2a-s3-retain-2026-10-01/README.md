# Provisional A2A S3 retained-field consumer gate

This optional Probity profile recomputes ES256 signatures over the served JSON,
retaining every member except the top-level `signatures` array. It matches all
13 `unknown-retain` expectations in the frozen proposed upstream S3 corpus.
It does not change the released vectors, the reference rail, or A2A rules.

## Reproduce

From this directory, with Python 3.12 or later:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=. .venv/bin/python -m pytest -q
.venv/bin/python run_regression.py > run-report.json
```

The runner checks all source SHA-256 digests before evaluating cases and exits
nonzero on a mismatched outcome. It derives signing bytes from `served_card`;
the fixture's expected verdict and supplied canonical hex are not inputs to
admission. The cryptographic primitives come from `cryptography`, canonicalization
from `rfc8785`; no A2A SDK verifier or corpus-generator code is imported.
The public fixture key is supplied from the pinned JWKS. `jku` is never fetched.

## What the cases establish

| Case | This gate | Meaning |
| --- | --- | --- |
| S3-D-012 | accept; signatures `[false, true]` | Signer-side dual signing works when a retained-form signature verifies. |
| S3-T-011 | reject | A signature over an excluded legacy URL cannot authenticate its served value. |
| S3-D-013 | reject; signatures `[false, false]` | A second excluded-form signature does not provide verifier-side fallback. |
| S3-D-013 diagnostic exclusion control | excluded signatures `[true, false]` | Reconstructing the excluded form would accept the altered card. This control is never an admission path. |

The other ten cases cover retained/excluded signature pairs for legacy top-level
fields, a nested provider field, an unknown object, a field in a repeated skill,
and an unknown empty array. Tests also mutate signed values, reorder signatures,
exercise duplicate JSON keys and malformed JOSE inputs, and check source tampering.

## Boundaries

- **Provisional consumer policy**, not normative A2A conformance. PR
  [a2a-tck#246](https://github.com/a2aproject/a2a-tck/pull/246) was open at inspected
  head `1a6d1882d70c9f760fb38f67c314b5c447101db2`.
- Only the S3 unknown-field axis is evaluated. The S0–S2 default-value and absent
  required-field questions are excluded. Retaining all fields happens to match
  the S3 retained reading; this is not an implementation of every rule-1 case.
- This is a Probity-authored and operated reproduction using independent checker
  code and upstream-produced native signatures. It is not a new SDK run, producer
  acceptance, host adoption, independently operated Probity result, or independent
  custody. No network action, redirect, or production key control was exercised.
- A malformed signature fails the whole local gate. This conservative choice is
  not presented as a normative interpretation of multiple-signature handling.
- The fixture's test key is publicly reproducible and has no identity assurance.

## Sources and attribution

The unchanged upstream JSON and Apache-2.0 license are under `upstream/`.
`source-lock.json` records exact blob identities, SHA-256 digests, and immutable
source URLs. All JSON came from ogasurfproject-jpg's A2A TCK proposal at the exact
head above. The original [unknown-field report](https://github.com/a2aproject/A2A/issues/2122#issuecomment-5940286366),
[separate reproduction](https://github.com/a2aproject/A2A/issues/2122#issuecomment-5940903881),
and [dual-signing transition report](https://github.com/a2aproject/A2A/issues/2122#issuecomment-5941187936)
remain separate evidence records. The latest group contains 13 cases, superseding
the earlier 11-case count. The upstream README labels one observation October 2;
this package's date identifies preparation, not a correction to producer dates.

Publication can precede the canonical ruling only with this provisional label.
After a ruling, compare the adopted exact text before proposing a normative
profile; retain this historical result unchanged.

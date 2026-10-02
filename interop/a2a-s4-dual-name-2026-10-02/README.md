# A2A received-card dual-name admission candidate

This additive regression consumes the five S4 fixtures published in
[TCK #246 at 248b22f](https://github.com/ogasurfproject-jpg/a2a-tck/tree/248b22fb748f8e8ede6e4e54e632341c9cc8b03d/conformance-vectors/a2a-card-sign-v01).
The original S3 reader and its 13-case frozen corpus are unchanged.

The reader preserves received JSON, verifies ES256 with the pinned public test
key, and applies either `dual-name-tolerate` or `dual-name-refuse`, selected by
the caller. The latter refuses a schema field supplied under both its JSON and
protobuf names, even when the values agree or are null. It checks all 21 message
types reachable from AgentCard in the frozen SDK 1.2.1 descriptor projection,
including repeated messages and message-map values. Unknown members, protobuf
Struct values and scalar-map keys stay opaque and covered by the signature.
It does not convert field spellings or try a fallback canonical form.

| Case | Retained signature | Tolerate | Refuse |
| --- | --- | --- | --- |
| S4-001 top-level aliases | valid | accept | refuse |
| S4-002 repeated skill aliases | valid | accept | refuse |
| S4-003 security-scheme map aliases | valid | accept | refuse |
| S4-004 single-spelling control | valid | accept | accept |
| S4-REJECT-005 added after signing | invalid | refuse | refuse |

The proposal is [the sentence in A2A #2122](https://github.com/a2aproject/A2A/issues/2122#issuecomment-5946904114).
Its refusal reading is not an adopted specification requirement. A tolerate
result on the first three cases is a divergence from that proposal. The reader
is a Probity-operated candidate regression; it establishes neither host adoption
nor production signer authority. It does not implement rule-1 default pruning,
full card schema validation, transport, key discovery or issuer authorization.

Run from this directory with Python 3.13:

```sh
python -m pip install -r ../a2a-s3-retain-2026-10-01/requirements.txt
PYTHONPATH=. python -m pytest -q tests
python run_dual_name.py > fresh-report.json
```

The source lock selects raw corpus bytes, native protocol text at
`173695755607e884aa9acf8ce4feed90e32727a1`, the shared verifier, and the schema
projection. The projection is original data extracted from the `AgentCard`
reachable fields of `a2a-sdk==1.2.1`'s serialized protobuf descriptor; its source
digest and derivation are retained in the projection. It contains aliases and
message edges only. Native fixtures and protocol text carry their Apache-2.0
license in `upstream/LICENSE`; HORIZON SHIELD authored the fixture corpus. Exact
membership and source hashes are checked before every recorded regression.

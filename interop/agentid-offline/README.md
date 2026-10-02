# AgentID offline reader

This optional consumer profile recomputes an AgentID attestation from three retained files: the signed envelope, the original request and a saved JWKS. It checks eight separate byte, signature and request relationships without a network call or an import of AgentID's verifier. It is separate from the released vector corpus and does not change its scoring or reference rail.

The fixture comes from [preaction-governance-conformance PR #9](https://github.com/babyblueviper1/preaction-governance-conformance/pull/9), pinned at `47e80f3ed65e7295ffac4383e659de268ff0c170`. The PR was open when captured. Exact file hashes, source paths and attribution are in [INPUTS.json](INPUTS.json). The copied files retain their upstream [MIT license](fixtures/LICENSE.upstream); the reader and tests use this repository's Apache-2.0 license.

The retained [positive result](RESULTS.json) establishes all eight bounded comparisons. [Five controls](CONTROLS.json) retain exact per-claim outcomes for a changed envelope, a substituted request, a wrong key, a changed action scope and the native concatenation ambiguity. These were produced by Probity on October 1, 2026; the source digest and runtime versions are retained. The 77-test pytest/Hypothesis run, lint and type checks passed locally. Remote CI is a separate result.

## Run

From the repository root, install the locked development environment and choose an output directory that does not exist:

```bash
uv sync --locked --extra dev
uv run python -m pytest interop/agentid-offline/test_reader.py -q
uv run python interop/agentid-offline/run.py \
  --attestation interop/agentid-offline/fixtures/positive.raw.json \
  --request interop/agentid-offline/fixtures/request.json \
  --jwks interop/agentid-offline/fixtures/jwks.json \
  --output-dir /tmp/agentid-first-attempt
uv run python interop/agentid-offline/check_result.py /tmp/agentid-first-attempt/report.json
```

Use a new output directory for each attempt. The reader refuses even an empty existing directory; it never reuses an old report. The CLI emits a report pointer on stdout and retains the full per-claim result in `report.json`. Exit 0 means all eight comparisons matched and a fresh report was written; exit 1 retains a report with at least one contradiction; exit 2 means malformed or unsupported input, or an output failure. Failed parsing produces no new report. An existing report left by an earlier invocation is never changed or counted as success.

`check_result.py` requires the exact pinned input files, eight established comparisons, the source digest of this checkout's reader and the bounded run classification. The CI job runs dependency installation, tests, the reader and report checking as separate failure-propagating steps. Missing reports make artifact retention fail as well. No live issuer endpoint is contacted.

## What is measured

| Claim | Recomputed relationship |
|---|---|
| `core_digest` | `SHA-256(JCS(envelope without digest and jws))` equals the carried digest. |
| `signed_payload_equals_core` | The decoded compact JWS payload equals those exact JCS bytes. |
| `signature_under_retained_key` | Ed25519 verifies the original protected-header/payload signing input under the unique matching retained key. |
| `header_kid_matches_signed_verifier` | Protected-header `kid` equals the signed verifier's `kid`. |
| `binding_digest` | The signed amount, charge reference, nonce and subject DID reproduce the carried binding digest. |
| `request_binding_matches` | Those four values equal the separately supplied request's values. |
| `action_ref` | The signed agent ID, supplied request action type/scope and issued-at milliseconds reproduce the native raw-concatenation hash. |
| `attestation_ref` | The signed key ID, verifier ID and subject DID reproduce the carried attestation reference. |

These are separate comparisons. A changed envelope can leave its original compact signature valid while breaking signed-payload equality. A changed request can preserve the signed binding digest while contradicting the request comparison. Neither the `admission.verdict` nor the `fast_gates` fields are accepted as recomputed policy or identity decisions.

The native `action_ref` construction is `SHA-256(UTF8(agent_id) || UTF8(action_type) || UTF8(scope) || int64_be(milliseconds(issued_at)))`. It has no separator between its string components. The retained limitation test changes `read` / `conformance-fixture` to `rea` / `dconformance-fixture` and gets the same hash. The reader preserves that native construction and reports `action_tuple_uniqueness` as not established. This is a digest-consistency result, not proof that the signature uniquely authorizes an exact action tuple. Request fields `action` and `action_class` are outside the named comparisons.

## Refusal boundary

Every JSON input is at most 64 KiB, an object at the root, and strict UTF-8 with unique member names. The profile supports safe integers, Unicode strings, booleans, nulls, arrays and objects; floating-point values, non-finite values, invalid Unicode, excessive depth and excessive node counts are refused. Canonical bytes come from the pinned `rfc8785` dependency, including UTF-16 key ordering. This is a bounded input domain, not a general JSON acceptance policy.

The JWS must have three canonical unpadded base64url segments and a protected header containing exactly `alg`, `typ` and `kid`, with `EdDSA` and `VerifierAttestation`. Critical extensions, detached payloads, header-supplied keys and alternate encodings are unsupported and fail closed. JWKS selection refuses duplicate IDs, absent IDs, nonpublic material, incompatible algorithm/purpose declarations and incorrect key widths. Its key count is bounded at 32. Unknown payload fields remain covered by core canonicalization and payload equality.

The tests include duplicate/nested JSON keys, malformed encodings, algorithm confusion, key substitution and ambiguity, request substitutions, altered signed fields, resource limits, Unicode properties, fresh output requirements and stale/missing report refusal. The positive fixture is evaluated at its historical bytes; no present-time freshness check is asserted.

## Provenance and remaining claims

This is a Probity-authored and operated consumer implementation. The producer's `verify_fixture.py` and published expected results were read before writing it; it is not a blind or clean-room exercise. It imports no producer verifier code and uses separately declared RFC 8785 and Ed25519 dependencies. Both source exposure and dependency reuse remain part of the record.

The saved JWKS makes signature checking reproducible. It does not authenticate production identity, prove who controlled the key, or establish revocation state at issuance. Freshness, policy sufficiency, execution, independent custody and unique action-tuple binding remain explicitly unestablished. The frozen composed/v2 slot discussed for Pack #3 is structural; this separately signed fixture does not turn it into a signed slot. Nothing here is a formal Pack #3 result, independent operation, AgentID adoption or host acceptance.

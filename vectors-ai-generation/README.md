# AI generation predicate v0.1 conformance suite

Conformance vectors for the generation predicate
`https://open-fab.ai/attestation/generation/v0.1`, an in-toto predicate that
records how an artifact was produced by an AI pipeline: per-range AI-or-human
attribution, the model, a prompt fingerprint, the embedded acceptance contract
and human sign-offs. The predicate is under discussion for adoption at
`ossf/tac#628`.

The suite tests a verifier in the predicate's default **attest-only** mode:
recompute the artifact digests, verify the ed25519 signatures over the
canonical statement, and read attribution from the predicate without executing
anything.

## What it certifies against

Specification revision 0.1.4, vendored unchanged from `Open-fab-ai/openfab` at
commit `17b964ee24b2cb7b751aebf9ed51524a5a9e1bd8`, with the JSON Schema and the
licence from the same commit, under `spec-vendored/`. `MANIFEST.json` pins each
file by sha256 and `aee-verify` refuses a copy whose bytes moved.

Revision 0.1.4 adopted the six findings in
`../docs/proposals/ai-generation-v01-findings.md`: member names ordered by
UTF-16 code units, integers admitted inside the I-JSON safe range, duplicate
member names refused, and the bytes each signature covers once sign-offs exist,
with every sign-off record bound to the key that signed it. The members that
showed those gaps as `proposed` are now required accepts and rejects.

The golden member is the upstream repository's own golden conformance vector,
the statement its test `canonical_encoding_golden_vector` pins by length and
sha256. The generator transcribes it and refuses to write anything unless the
transcription reproduces the pinned hash. The base attestation is that golden
statement with real artifact digests, signed with a fixed test key; every member
the generator builds is one change to it, and a refused member names the member
it was changed from in its `parent` field.

Four accept members were built by someone else: the signed attestations the
upstream repository publishes under `docs/vectors/`, one from its Rust
implementation and one from its browser implementation, each with and without
two sign-offs. They are copied byte for byte into `upstream-vectors/17b964ee/`,
their manifest rows carry the upstream path and sha256 under `source`, and the
generator refuses a copy whose bytes moved. Their subject is the digest of the
four bytes `test` and their one generated range is the line `hello`, both under
`artifacts/`.

## Three kinds of member

- **accept** and **reject** are required by revision 0.1.4 as written. A reject
  member cites the clause it breaks and names the code a verifier refuses it
  with. An accept member is valid under the revision and under the proposal
  below.
- **proposed** members depend on text the revision does not yet carry. Each
  declares two outcomes: what revision 0.1.4 as written says of it, and what
  the proposal in `../docs/proposals/ai-generation-v01-findings.md` says. A
  verifier is never failed on a proposed member; the pair of outcomes is what
  the member shows. Two rules remain proposed: attribution ranges for one path
  do not overlap, and a supplied `Assisted-by:` trailer matches `agent.id` and
  `agent.tools`.

Counts are in `INDEX.md` and `MANIFEST.json`, both written by the generator.

## Readings this suite has to state

The revision leaves one thing open that a digest cannot be computed without,
and this suite states its reading rather than leaving it implicit:

- A generated range's `sha256` is the digest of exactly the lines the range
  names, each with its LF terminator. The subject's digest is over the whole
  artifact file. The artifacts are under `artifacts/`.

One case this suite does not build: a prompt fingerprint checked against the
recorded model, because the predicate deliberately omits the prompt text and no
rule relates `prompt_sha256` to the model, so no verifier can check it from the
attestation.

## Keys

Every signature the generator makes is by a published test key derived from a
fixed seed, listed in `MANIFEST.json` under `keys` with the derivation in
`keyNote`. The four upstream members are signed by the upstream repository's own
published test keys, listed in its `docs/vectors/TEST-KEYS.json`. None of these
keys signs anything that should be trusted.

## Regenerate and check

```bash
uv run --extra generators python vectors-ai-generation/gen_vectors.py
uv run --extra generators python vectors-ai-generation/gen_vectors.py --check
go run ./cmd/aee-verify vectors-ai-generation
```

The corpus digest routine is `digest.py`, which imports only the standard
library, so a reader who installed nothing can recompute it.

## Licence of the vendored text

The files under `spec-vendored/` and `upstream-vectors/` are the upstream
project's, under the Apache License 2.0 carried as
`spec-vendored/LICENSE-17b964ee`.

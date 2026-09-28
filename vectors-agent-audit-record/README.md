# Agent audit record conformance vectors

The conformance corpus of the Internet-Draft
[`draft-gilda-wimse-agent-audit-record-01`](https://datatracker.ietf.org/doc/draft-gilda-wimse-agent-audit-record/01/),
Appendix B, published member for member. Every row of that table is one member
here, and each [`MANIFEST.json`](MANIFEST.json) entry carries the row's
identifier in `draftId` (`A1`, `F3b`, `TI4`, ...) and its `from` column in
`parentDraftId`. [`INDEX.md`](INDEX.md) lists the rows beside their files.

Each member is a DSSE envelope whose payload is an in-toto Statement carrying one
agent audit record. The bytes are in `statements/`; the verdict a conforming
verifier must reach is in the manifest under `expected.verdict`, never in the
file, so a member cannot be scored without being read.

## Running it

```sh
# The reference reader, from the published package. Prints one line per
# failing member and exits 0 when every member behaves as the manifest says.
uvx agent-evidence-vectors --corpus vectors-agent-audit-record

# From a checkout: rebuild every member (byte-identical on every machine),
# then judge the committed bytes, verify every signature with a second
# Ed25519 library, and sweep every rule for load-bearing effect.
uv run --extra generators python vectors-agent-audit-record/gen_vectors.py
uv run --extra generators python vectors-agent-audit-record/check_vectors.py
```

To score your own verifier, run it over each `statements/<id>.json` with the
observer public key from `keys.observer.publicKey` and compare its verdict with
`expected.verdict`. The draft defines three verdicts: `valid`, `malformed`, and,
for `N1` and `N2`, `indeterminate`, where the manifest lists under `readings`
every verdict a conforming verifier may reach.

`expected.codes` are the reference reader's names for its first refusal. The
draft does not define codes, so a verifier is scored on the verdict alone; the
codes are published so two implementations can compare where they stopped.

## What the members are built from

Every reject member is its `from` member with the one mutation its row names.
Where the mutation moves a value another member is a function of, the dependent
value moves with it (the rows that say "roots and chain moved to match"). The
keys are published test keys derived from fixed seeds in
[`gen_vectors.py`](gen_vectors.py): the observer key signs every envelope, and
the agent key signs nothing and is the key `agent.signers` names.

Three readings the draft leaves to the corpus, stated so they can be checked:

- `T2` is signed over its declaration-order bytes. A verifier that checks the
  signature over the carried bytes accepts it; one that derives the RFC 8785
  bytes itself, as the draft requires, refuses it.
- `F5` reaches "beacon-anchored with externalAnchor removed" by changing
  `timeBasis` on `A1`, which carries `asserted` and no anchor. `N1` is `A1`
  with an anchor carried under `beacon-anchored`, so `A1` itself raises no
  anchor question.
- `priorCommitment.sig` is carried and not checked: revision 01 names the
  member and defines no preimage for it.

## What the rule sweep reports

`check_vectors.py` disables one rule of the reader at a time. Four Appendix B
rows are still refused when their own rule is off, by a later check: `S1` and
`I1r` (the subject-interval rule), `F1` (membership), `E3` (the empty-tree
constant, whose mutation also breaks the commitment digest), and `V2` (the glob
rule, whose scope also puts the write out of scope). The verdict holds in each
case. The sweep prints these as notes, and they are candidates for isolating
members in a later revision of the draft.

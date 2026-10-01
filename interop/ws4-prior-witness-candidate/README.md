# Prior witness case for WS4 §7.4

This optional candidate profile exercises one question left open in [CoSAI WS4 PR #219](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/pull/219): where the expected prior commitment came from. The PR merged into the `feat/containment` integration branch at `84604125869469926968acdf433501f87d1d1665`. Section 7.4 is unchanged from its proposal head, but the whole whitepaper has a new hash, pinned in [MANIFEST.json](MANIFEST.json). The [18 candidate cases](https://github.com/astrogilda/ws4-secure-design-agentic-systems/pull/1) are pinned at `642a3ee74534f3a38699a93741af646aedc2fc23`. The integration draft and these cases are not adopted conformance text.

The profile uses our published, signed Observed Effect read-only record, SHA-256 `162352770f2f6c1cd861685e8e84c85603948b324cfa58752e7ad9dd76747da8`. It calls this repository's `observedeffect.verify` to admit the record. It does not import the WS4 checker or copy its cases or text. The input and exact source hashes are in [MANIFEST.json](MANIFEST.json); expectations are kept in [EXPECTED.json](EXPECTED.json), outside the reader input.

| Case | Property result | Action outcome | Distinguishing input |
| --- | --- | --- | --- |
| Claimed digest | `not_established / invocation_binding` | `pending` | The record's digest is copied into context, but no separately pinned witness is supplied. |
| Signed prior | `pass` | `pending` | A distinct witness key signs the prior commitment and a subsequent invocation-open record; the consumer policy pins its key, nonce and log head. |
| After reporting window | `pass` | `pending` | The same bound observation is evaluated one second after the window closes without a terminal action observation. |

The property checked here is narrowly `no_write_in_scope` for `/srv/app/` during the pinned interval. `pass` depends on this consumer's declared write visibility for the same claim, the admitted record's complete coverage and below-observed vantage, and the separately verified commitment. The source of write visibility is still stipulated by the consumer policy. This run does not establish general field visibility or the physical independence of the observer. A malformed witness log or wrong configured key is a processing failure, not a property verdict. The action outcome stays a separate axis. Each result binds the property, claim, observed interval, scope, record hash and the witness head it relied on, if any.

The witness seed is published in `gen_fixture.py` so anyone can regenerate these test bytes. The same author made both records and selected the consumer pins. Signed sequence proves the order of those authored records under the configured key; it does not prove they were retained before a real invocation, that the author lacked the key, or that an outside operator held the head. A deployment needs a separately operated witness and a consumer-held pre-invocation pin before it can claim that provenance. The fixtures test the reader's use of that premise.

From the repository root:

```sh
PYTHONPATH=packaging python interop/ws4-prior-witness-candidate/gen_fixture.py --check
PYTHONPATH=packaging python interop/ws4-prior-witness-candidate/run.py
PYTHONPATH=packaging python -m unittest discover -s interop/ws4-prior-witness-candidate -p 'test_profile.py'
```

`--check` rebuilds the five fixture files in memory and compares their bytes. `run.py` hashes each input and the separate expected file, keeps expected results out of the reader call, and exits nonzero on disagreement. The tests change the witness key, head, nonce, claim, commitment and signed bytes, omit and add log entries, duplicate a JSON field, reject unknown policy fields and noncanonical paths, check capability binding and visibility scope, and probe a false terminal result. The local [run receipt](RUN.md) names what actually ran.

This directory sits under `interop` so the normative Observed Effect corpus and release wheel do not acquire a new rule from the WS4 integration draft. The code here is original and covered by this repository's Apache-2.0 license. The upstream WS4 repository's CC BY 4.0 material is referenced by URL and hash, not distributed here.

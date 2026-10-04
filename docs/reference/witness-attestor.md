# go-witness attestor

[witnessattestor/](../../witnessattestor/) validates an existing evidence statement before go-witness signs it. The upstream integration is staged; this page describes the local package.

The attestor follows go-witness's SARIF pattern. After step products exist, it locates `aee-evidence.json` by default, checks its digest against the recorded product, and applies GATE 0, GATE 1 and result recomputation. A failed check returns an error. The signed predicate contains the exact validated bytes.

| Mechanism | What it covers |
| --- | --- |
| Witness envelope key | Producer assembly, gate validity and recomputation at pipeline step time |
| Signed `observationRecords` | Substrate evidence, checked later against the consumer's pinned keys |
| Consumer GATE 2 | Evidence tier under that consumer's policy |
| Producer `expect-substrate-key` QA option | Local record-signature checks; no tier derivation |

The attestor signs a producer statement. Its envelope key does not witness execution, and go-witness `commandrun` tracing is not `basis: substrate`.

[cmd/aee-witness-demo](../../witnessattestor/cmd/aee-witness-demo/) runs the attestor through the real witness library lifecycle and prints the signed standalone statement. Read it with [cmd/aee-verify](../../cmd/aee-verify/). A `VerifyRunType` attestor that signs a verification summary remains planned work; the witness verify CLI is coupled to its policy attestor.

# JEP Core 0.7 preregistered Probity pilot

This protocol is published before implementation execution. The accepted scope is [the maintainer's confirmation](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-5954500341) of [Probity's offer](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-5931607272). It establishes neither a completed run nor JEP CI adoption.

## Frozen question and sources

Evaluate the Core 0.7 BYOI manifest at `a87a395b54b5685fd22d6cc86d120058f1c8850d`: 25 validation assertions, four producer assertions, and eight stateful acceptance assertions. These populations are reported separately. The manifest is SHA-256 pinned in `source-lock.json`, along with every one of its 36 covered files and the Core specification. The source manifest is not a claim of complete Core coverage.

Implement the validator, producer and acceptance processor in Probity without importing JEP's validator, adapter, BYOI harness, or acceptance fixture. Python's standard library, cryptography and Trail of Bits' RFC 8785 canonicalizer are allowed dependencies. The public fixture expectations and specification have been read before implementation; this is an exposed-answer conformance study, not a blind study.

## Adapter and exact planned commands

From a checkout of the published reader revision:

```sh
python -m venv .jep-reader-env
.jep-reader-env/bin/python -m pip install -r interop/jep-core07-reader/requirements.txt
.jep-reader-env/bin/python interop/jep-core07-reader/run.py \
  --upstream interop/jep-core07-reader/upstream \
  --output jep-core07-result \
  --reader-revision "$(git rev-parse HEAD)"
```

The reader revision is the exact published implementation commit, selected and recorded before execution. The adapter command is `python interop/jep-core07-reader/adapter.py`, with `validate`, `produce` and `probe` subcommands. It reads fixture bytes from files and emits a single JSON result. A validation result keeps syntax, cryptography, event identity, extension processing and acceptance distinct; unchecked authority, external identity, target truth and external execution stay unestablished.

The test trust store is the pinned suite's `keys.json`, SHA-256 `514a7aee94d3287cdc3b8b757b4c7fab596a84fdd0585df9fa1f5081d6fea697`. No network resolution or candidate-selected trust store is used. The public fixture keys are test keys and establish no real-world identity.

## Scoring and stateful controls

First save the complete actual result for each assertion; then compare its declared fields against the published expected answer. Preserve failures rather than change the protocol or silently omit assertions. Report 25/4/8 denominators even when an assertion fails or is unavailable. Producer cases sign each of the four pinned templates using a disclosed test-only seed, then the independently implemented verifier checks the produced bytes.

Each acceptance assertion gets a fresh SQLite database. Every validation delivery runs in a new process. Acceptance identity is `(domain, who, id)`; compare canonical unsigned content rather than full signed-event hashes, so re-signing does not apply another effect. Record acceptance and the synthetic effect in one SQLite transaction. The effect is a local row, not an external service or an assertion that a JEP-described act occurred.

A separately invoked read-only probe counts committed effect rows. Exercise archival reads, restarts, conflicting content, re-signing, actor and domain separation, rejection without consuming identity, eight concurrent deliveries, and unavailable state. A missing or failed probe fails the affected assertion. No power-loss, distributed failover, complete host observation or independently held database is claimed.

Hostile controls include changed input pins, duplicate members, invalid signatures, a substituted trust store, critical extensions, unavailable state, competing identities and accept-all comparison. Controls and conformance populations remain separate.

## Retention and correction

The output directory must not exist. Retain source-lock, protocol digest, reader file digests, environment and exact commands, raw per-invocation stdout/stderr/exit status, produced events, read-only probe results, assertion results and final comparison. Do not overwrite an old run. Publish the protocol and reader in agent-evidence-vectors, and retain the result through the [Open Evidence Lab](https://probityai.github.io/agent-evidence-atlas/lab.html) as a submitted record. Protocol deviations and producer objections are retained next to the result.

Implementation diversity is a separate fact from operator independence. Probity operates this fixture study outside JEP, while its own adapter and probe share Probity control. The run proves no independent effect custody. Ask JEP to run the pinned reader in its own CI only after concrete adapter, instructions and retained outputs exist; host adoption requires the host-owned workflow and completed run.

# Report a verifier run

Use the [independent-run form](https://github.com/probityai/agent-evidence-vectors/issues/new?template=independent-run.yml) to submit a result. Include the corpus pin and digest, the verifier source pin, the command and the retained report. A disagreement is useful too.

| Record | What belongs there |
| --- | --- |
| [RUNS.md](../../RUNS.md) | Posted runs, the reporter's account, and blind or directed status |
| [DISTRIBUTION.md](../../DISTRIBUTION.md) | Release identifiers, the module path and requirements for adding a corpus |
| [Citing a run](../reference/citing.md) | Release, suite revision and corpus digest to retain with the result |
| [Release verification](../reference/release-verification.md) | Check the corpus bytes, signature and timestamp evidence |

`scripts/distribution-gate.py` checks the release recipe against DISTRIBUTION.md, reconciles its tag with CITATION.cff, and checks that the distribution table and run form list the tracked corpora.

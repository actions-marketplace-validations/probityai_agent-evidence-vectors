# Source-coverage vectors

Six synthetic cases for `source_text_coverage/v1`. Each case has a separate
consumer policy, a source capture binding, and a report binding. The expected
decision and reason are in `MANIFEST.json`.

| Case | Expected decision | Distinction |
| --- | --- | --- |
| complete | supported | The selected passage appears in both bound artifacts. |
| self-hashed-truncation | contradicted | A valid report hash covers truncated bytes. |
| middle-omission | contradicted | A middle passage is absent from an otherwise intact report. |
| returned-after-requested-window | not_established | A June capture cannot establish an April source state. |
| capture-absent | not_established | The named source bytes were never supplied. |
| hidden-script-only | not_established | Script text is outside the selected article. |

Run a verifier that accepts `case.json --policy policy.json --json`:

```sh
python3 vectors-source-coverage/check_vectors.py --verifier './verifier'
```

The wheel supports the same corpus:
`agent-evidence-vectors --corpus vectors-source-coverage --verifier './verifier'`.
The checker verifies fixture bytes and compares each decision and reason.
Regenerate the cases with `python3 vectors-source-coverage/gen_vectors.py`.

Passing these synthetic cases does not establish source authority, passage
materiality, or report completeness.

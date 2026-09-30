# Disagreements between this run and the producers' stated results

None. Every claim this checker evaluated reached the result its producer states:

- APS cases (`case.json` `expected`, the APS README table): permit, narrow and expired verify, deny does not
  admit dispatch, expired fails at the reference time, deny has no validity window.
- PriorSeal pair (the fixtures' own `compliance`, the example README, `PAYMENT-LIMIT-REPORT.json`): within
  limit matches the signed call and sits under the APS cap; over limit differs from the signed call and exceeds
  the cap; both correlate to the one APS `decision_ref`.
- The report: all 22 values we could recompute agree, and the 3 it quotes from the signed fixtures match them.

Two things that are not disagreements, recorded so nobody reads them as one:

1. Our entry 4 row compares six fields (chain, target, calldata hash, value, sender against executor, nonce)
   and reports each difference. PriorSeal's own result is one reason code, `TRANSACTION_VALUE_MISMATCH`. Both
   find exactly one difference on the over-limit fixture, the value.
2. Where our composition rows go `void` in the negatives, PriorSeal's adapter tests would fail the case
   outright. Same direction; ours keeps the reason (which integrity check the claim rested on) in the record.

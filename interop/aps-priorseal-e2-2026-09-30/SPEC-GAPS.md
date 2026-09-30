# Where the published text was not enough to implement E2 independently

Each row: the passage, why the text did not settle it, and what we did. No APS or PriorSeal source code was
read for this run. Where a rule was recovered by trying a construction against the bytes, it says so.

1. **PriorSeal signing inputs are defined only in SDK source.** The example README and the claim-boundary
   document say the principal signs "with EIP-712 for the exact intent", and imokokok (thread comment 34)
   says `priorseal-sdk@0.4.0` "and its pinned verification source define the exact hashes, canonical JSON and
   signature checks". No specification text gives the EIP-712 domain and types, the `authorizationHash`
   construction, the acceptance `entryHash` construction, or the receipt signing input. We tried the obvious
   constructions for `authorizationHash` and `entryHash` (SHA-256 and Keccak-256 of JCS, with and without the
   domain strings and the signature members) and none matched. Result: lab entry 2 is not exercised here, cause
   `out_of_scope`. Consequence for the pilot: an independent implementation of PriorSeal's signatures needs a
   written profile, not a reading of `sdk/src/verifier-core.ts`, or it is a port.
2. **Two PriorSeal hashes recovered by trial.** `intentHash = SHA-256(JCS(intent without intentHash))` and
   `executionHash = SHA-256(JCS(execution))` both match the carried values on both fixtures. No text we read
   states either; we use them and label them in every row that relies on them.
3. **No rule maps the APS spend unit to the PriorSeal asset.** APS writes `eip155:31337:native:wei`; PriorSeal
   writes `eip155:31337/native` with a separate `chainId`. The cap comparison (entry 5) needs one. We read
   both as the native asset of chain 31337 in wei and say so in the row; a verifier that refuses the mapping
   would report entry 5 as inconclusive, cause `unsupported_input`, which our checker does when the strings
   do not have these exact shapes.
4. **The APS action payload is not named.** Draft-03 Section 4.1 defines `payload_ref` over "the exact JSON
   value presented for authorization and dispatch", and the fixture README does not say which object that
   is. `SHA-256("APS-ACTION-PAYLOAD-V1" || 0x00 || JCS(policy_input.requested_call))` matches `payload_ref`
   in all four cases, so we check it that way and say so.
5. **Temporal validity is the consumer's, and the fixtures say so.** The APS README states that the 6.0.1
   composite verifier checks `valid_until` against `issued_at`, not the reference time. Draft-03 Section 5.3.2
   puts expiry at dispatch. We report the reference-time check as its own claim, as the thread agreed.
6. **Draft-03, not -04.** aeoess (comment 31): "The fixtures predate -04." We implemented -03. A later lab
   record against -04 fixtures needs its own run.

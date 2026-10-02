# Action tuple framed v1 candidate

Identifier: `probity.action-tuple-framed.v1`.

This is a proposed Probity digest profile for a tuple of `agent_id`, `action_type`, `scope` and `issued_at_ms`. It is a new unsigned candidate, separate from the native AgentID `argentum-core action-ref-v1` and the retained AgentID offline reader. Selecting it does not reinterpret an existing AgentID `action_ref` or endorse a signature over another construction.

The byte preimage, in order, is:

| Component | Exact encoding |
| --- | --- |
| Domain | ASCII `PROBITY`, byte `00`, ASCII `action-tuple`, byte `00`, ASCII `v1`, byte `00` |
| Agent ID | Unsigned 32-bit big-endian UTF-8 byte count, followed by those bytes |
| Action type | Unsigned 32-bit big-endian UTF-8 byte count, followed by those bytes |
| Scope | Unsigned 32-bit big-endian UTF-8 byte count, followed by those bytes |
| Issued time | Signed 64-bit two's-complement big-endian integer, milliseconds since Unix epoch |

The domain's hexadecimal bytes are `50524f4249545900616374696f6e2d7475706c6500763100`. The digest is lowercase hexadecimal SHA-256 over the whole preimage. The domain is fixed, including its trailing zero; it is not a caller-selected label. Fields have fixed positions. There is no sorting, delimiter splitting, Unicode normalization, URL encoding, case folding, timestamp parsing or floating-point conversion. Each string must contain only Unicode scalar values and encode to at most 65,536 UTF-8 bytes. Empty strings and embedded zero bytes are valid. The timestamp must be a JSON integer in the signed 64-bit range; Booleans, floats and numeric strings are refused. Negative and extreme timestamps test representation, not historical plausibility or freshness.

The transport packet is a JSON object with exactly four members: `profile`, `tuple`, `frame_hex` and `digest`. The tuple contains exactly the four named fields above. Duplicate JSON member names are refused at every nesting level. Input JSON must be strict UTF-8, at most eight times the maximum preimage size plus 1,024 bytes, with depth at most 32 and at most 4,096 value nodes; frame hex is lowercase with exactly two digits per byte, with no spaces. This transport budget accommodates a compact JSON representation of every bounded tuple, including maximum-length strings whose every byte requires a six-byte JSON escape, together with the frame hex and fixed envelope. Arbitrary extra whitespace still consumes the input budget. The reader parses each declared frame length, decodes strict UTF-8, requires exactly eight remaining timestamp bytes, recomputes the frame from the separately carried tuple, and compares its SHA-256 digest. A consistent frame for a different tuple is refused. Surplus bytes, unknown packet or tuple members and alternate domains are refused.

Length framing makes the preimage uniquely decodable on this bounded domain: after the fixed prefix each string has one fixed-width size and exactly that many bytes, followed by one fixed-width timestamp. The original `read` + `conformance-fixture` and `rea` + `dconformance-fixture` pair therefore have different frames. This is an encoding property, not a claim that SHA-256 cannot collide, that a key authenticated a tuple, or that an authorization policy admitted it.

Any producer migration must explicitly select this new method identifier and authenticate the new digest and its tuple context under a declared signing contract. Existing native signatures are not carried over. A relying party must select the expected tuple and profile independently; acceptance of a self-consistent unsigned packet alone does not authenticate that selection, establish issuer identity, enforce an action, prove key custody or demonstrate AgentID adoption.

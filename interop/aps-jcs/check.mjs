#!/usr/bin/env node
// Compare original raw bytes before interpreting receipt and serializer results.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  assert.match(process.argv[index], /^--(aps|jcs|output|rust-bin|aps-only)$/);
  args.set(process.argv[index].slice(2), process.argv[index + 1]);
}
const aps = resolve(args.get('aps') ?? 'aps');
const jcs = resolve(args.get('jcs') ?? 'jcs-admit');
const source = JSON.parse(readFileSync(resolve(here, 'source-lock.json'), 'utf8'));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const git = (root, ...arguments_) => {
  const result = spawnSync('git', ['-C', root, ...arguments_], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
};
for (const [root, pin] of [[aps, source.aps], [jcs, source.jcs_admit]]) {
  assert.equal(git(root, 'rev-parse', 'HEAD'), pin.commit, 'source revision drift');
  for (const entry of pin.files) {
    const bytes = readFileSync(resolve(root, entry.path));
    assert.equal(bytes.length, entry.bytes, entry.path);
    assert.equal(sha256(bytes), entry.sha256, entry.path);
    assert.equal(git(root, 'rev-parse', `HEAD:${entry.path}`), entry.git_blob_sha, entry.path);
  }
}
const { canonicalizeJCS } = await import(pathToFileURL(resolve(aps, 'src/core/canonical-jcs.ts')));
const { parseStrictIJson } = await import(pathToFileURL(resolve(aps, 'src/v2/receipt-core/jcs.ts')));
const { createReceiptV1, verifyReceiptV1, verifyReceiptV1Serialized } = await import(
  pathToFileURL(resolve(aps, 'src/v2/receipt-core/receipt.ts')));
const { publicKeyFromPrivate } = await import(pathToFileURL(resolve(aps, 'src/crypto/keys.ts')));
const rawText = bytes => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
const outcome = (bytes, raw) => {
  try {
    const text = rawText(bytes);
    const value = raw ? parseStrictIJson(text) : JSON.parse(text);
    const canonical = Buffer.from(canonicalizeJCS(value));
    return { status: 'accepted', canonical_hex: canonical.toString('hex'),
      canonical_sha256: sha256(canonical), canonical_bytes: canonical.length };
  } catch (error) {
    return { status: 'refused', error_class: error.constructor.name, error: error.message };
  }
};
const cases = [];
const add = (name, raw, profile, expected) => cases.push({ name, raw, profile, expected });
for (const [family, output, profile] of [
  ['rfc8785', 'output', 'rfc8785'], ['cross-rail', 'canonical', 'ijson-integers']]) {
  const base = resolve(jcs, 'tests/vectors', family);
  for (const file of readdirSync(resolve(base, output)).filter(file => file.endsWith('.json')).sort()) {
    add(`${family}/${file}`, readFileSync(resolve(base, 'input', file)), profile,
      { status: 'accepted', canonical_hex: readFileSync(resolve(base, output, file)).toString('hex') });
  }
}
const lines = path => readFileSync(resolve(jcs, path), 'utf8').split('\n')
  .filter(line => line && !line.startsWith('#'));
for (const line of lines('tests/vectors/cross-rail/refused.tsv')) {
  const [name, error_class] = line.split('\t');
  add(`cross-rail/${name}.json`, readFileSync(resolve(jcs, 'tests/vectors/cross-rail/input', `${name}.json`)),
    'ijson-integers', { status: 'refused', error_class });
}
for (const line of lines('tests/vectors/attack/strings-keys-members.tsv')) {
  const [name, input, expected] = line.split('\t');
  add(`attack/${name}`, Buffer.from(input, 'hex'), 'ijson-integers', expected === 'REFUSE'
    ? { status: 'refused' } : { status: 'accepted', canonical_hex: expected.slice('ACCEPT '.length) });
}
for (const [index, line] of lines('tests/vectors/es-number-ties.tsv').entries()) {
  const [input, expected] = line.split('\t');
  add(`number-ties/${index}`, Buffer.from(input), 'rfc8785',
    { status: 'accepted', canonical_hex: Buffer.from(expected).toString('hex') });
}
const controls = JSON.parse(readFileSync(resolve(jcs, 'interop/rfc8785-py/controls.json'), 'utf8'));
for (const control of controls.cases) {
  add(`raw-control/${control.name}`, Buffer.from(control.raw), control.profile, control.rust_error
    ? { status: 'refused', error_class: control.rust_error }
    : { status: 'accepted', canonical_hex: control.rust_canonical_hex });
}
assert.equal(cases.filter(item => item.name.startsWith('rfc8785/')).length, 6);
assert.equal(cases.filter(item => item.name.startsWith('cross-rail/')).length, 39);
assert.equal(cases.filter(item => item.name.startsWith('attack/')).length, 317);
assert.equal(cases.filter(item => item.name.startsWith('number-ties/')).length, 850);
assert.equal(cases.filter(item => item.name.startsWith('raw-control/')).length, 11);

let rust = [];
if (!args.has('aps-only')) {
  assert.ok(args.has('rust-bin'), 'an executed raw-byte Rust probe is required');
  const run = spawnSync(resolve(args.get('rust-bin')), [], {
    input: cases.map(item => JSON.stringify({ raw_hex: item.raw.toString('hex'), profile: item.profile })).join('\n') + '\n',
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
  if (args.has('output')) {
    writeFileSync(`${args.get('output')}.native.ndjson`, run.stdout ?? '');
    writeFileSync(`${args.get('output')}.native.stderr`, run.stderr ?? '');
  }
  assert.equal(run.status, 0, run.stderr);
  rust = run.stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(rust.length, cases.length, 'every raw case must have a native admission result');
}
const rows = cases.map((item, index) => {
  const parsed = outcome(item.raw, false);
  const raw = outcome(item.raw, true);
  const native = rust[index];
  const expected = item.expected;
  if (native) {
    for (const [key, value] of Object.entries(expected)) {
      assert.equal(native[key], value, `native ${item.name}: ${key}`);
    }
  }
  if (expected.status === 'accepted') {
    assert.equal(parsed.status, 'accepted', `APS serializer ${item.name}`);
    assert.equal(parsed.canonical_hex, expected.canonical_hex, `APS bytes ${item.name}`);
  }
  if (raw.status === 'accepted' && parsed.status === 'accepted') {
    assert.equal(raw.canonical_hex, parsed.canonical_hex, `APS raw/object bytes ${item.name}`);
  }
  if (native?.status === 'accepted' && raw.status === 'accepted') {
    assert.equal(raw.canonical_hex, native.canonical_hex, `native/APS shared bytes ${item.name}`);
  }
  return { name: item.name, input_sha256: sha256(item.raw), input_bytes: item.raw.length,
    profile: item.profile, expected, ...(native ? { native_admission: native } : {}),
    aps_parsed_serializer: parsed, aps_raw_parser: raw };
});

const private_key = '00'.repeat(32);
const publicKey = publicKeyFromPrivate(private_key);
const resolveKey = () => publicKey;
const receipt = createReceiptV1({
  profile: 'aps-receipt-v1', receipt_type: 'aps:action-intent:v1',
  issuer: 'did:example:agent', subject_agent: 'did:example:agent', action_ref: 'a'.repeat(64),
  delegation_ref: `sha256:${'b'.repeat(64)}`, issued_at: '2026-04-08T12:00:00.000Z',
  evidence_refs: [], result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
}, [{ signer: 'did:example:agent', key_id: 'k1', private_key }]);
const clean = JSON.stringify(receipt);
const issuer = '"issuer":"did:example:agent"';
const duplicate = clean.replace(issuer, `${issuer},${issuer}`);
const escaped = clean.replace(issuer, `${issuer},"\\u0069ssuer":"did:example:agent"`);
assert.notEqual(duplicate, clean);
assert.notEqual(escaped, clean);
assert.equal(verifyReceiptV1Serialized(clean, resolveKey).valid, true);
const receipts = [
  ['clean', clean, 'valid'], ['duplicate-issuer', duplicate, 'invalid'],
  ['escaped-duplicate-issuer', escaped, 'invalid'],
  ['wrong-key', clean, 'invalid'], ['resource-depth', '{"a":'.repeat(200) + '1' + '}'.repeat(200), 'indeterminate'],
].map(([name, raw, status]) => {
  const key = name === 'wrong-key' ? () => publicKeyFromPrivate('11'.repeat(32)) : resolveKey;
  const result = verifyReceiptV1Serialized(raw, key);
  assert.equal(result.status, status, name);
  const parsed = name.includes('duplicate') ? verifyReceiptV1(JSON.parse(raw), resolveKey) : undefined;
  if (parsed) {
    assert.equal(parsed.valid, true, 'parse-first bypass canary must really verify');
    assert.equal(result.errors[0], 'parse_error');
    assert.equal(result.receipt_id_valid, 'not_checked');
    assert.equal(result.signature_results.length, 0);
  }
  return { name, input_sha256: sha256(raw), input_bytes: Buffer.byteLength(raw),
    serialized_verifier: result, ...(parsed ? { parse_first_verifier: parsed } : {}) };
});
const report = {
  schema: 'probity.aps-jcs.comparison.v1', controller: 'astrogilda', execution: 'author-operated',
  executor: process.env.GITHUB_ACTIONS ? 'GitHub Actions hosted runner' : 'authorized cloud workspace',
  ...(process.env.GITHUB_RUN_ID ? { workflow_run_id: process.env.GITHUB_RUN_ID,
    workflow_run_attempt: process.env.GITHUB_RUN_ATTEMPT, executed_head: process.env.GITHUB_SHA } : {}),
  scope: 'pinned raw JSON admission, serializer bytes and finite signed receipt controls',
  aps_commit: source.aps.commit, corpus_commit: source.jcs_admit.commit,
  source_lock_sha256: sha256(readFileSync(resolve(here, 'source-lock.json'))),
  node_version: process.version, native_admission_executed: !args.has('aps-only'),
  admission_dependency: { repository: 'probityai/jcs-admit', commit: source.jcs_admit.commit },
  summary: {
    corpus_cases: rows.length,
    expected_accepted: rows.filter(row => row.expected.status === 'accepted').length,
    aps_raw_accepted: rows.filter(row => row.aps_raw_parser.status === 'accepted').length,
    parsed_refusal_bypasses: rows.filter(row => row.expected.status === 'refused'
      && row.aps_parsed_serializer.status === 'accepted').length,
    raw_policy_differences: args.has('aps-only') ? null : rows.filter(row => row.native_admission
      && row.native_admission.status !== row.aps_raw_parser.status).length,
    signed_receipt_controls: receipts.length,
  }, rows, receipts,
};
if (args.has('output')) writeFileSync(args.get('output'), JSON.stringify(report, null, 2) + '\n');
process.stdout.write(JSON.stringify({ node_version: report.node_version,
  native_admission_executed: report.native_admission_executed, summary: report.summary }) + '\n');

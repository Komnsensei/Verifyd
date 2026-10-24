// D1 CLI: a supplied policy body is transport for the commitment, not a trust
// input. With the sidecar lost, the chain verbs can still work when handed the
// body, and a body that does not hash to genesis is refused with a different
// code than an absent one.
//
// The policy file is only ever accepted through `resolvePolicy`, which compares
// `policyHash(body)` with the `policy_hash` inside the signed genesis line.

'use strict';

const test = require('node:test');
const assert = require('node:assert');

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(ROOT, 'bin', 'verifyd.cjs');

function run(args, env) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: Object.assign({}, process.env, env),
  });
}

function checkpointLines(ledger) {
  return fs.readFileSync(ledger + '.checkpoints.jsonl', 'utf8').split('\n').filter(Boolean);
}

test('chain verbs accept the committed policy when the sidecar is lost', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-policy-cli-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const keyring = path.join(dir, 'keys');
  const ledger = path.join(dir, 'audit.ledger');
  const env = { VERIFYD_KEYRING: keyring };

  assert.equal(run(['keys', 'init'], env).status, 0);
  assert.equal(run(['chain', 'init', '--ledger', ledger], env).status, 0);

  const doc = path.join(dir, 'doc.txt');
  fs.writeFileSync(doc, 'A document for the policy transport check.\n');
  assert.equal(run(['audit', doc, '--ledger', ledger], env).status, 0);

  // The committed body is copied out, then the sidecar is lost.
  const saved = path.join(dir, 'saved-policy.json');
  fs.copyFileSync(ledger + '.policy.json', saved);
  fs.rmSync(ledger + '.policy.json');

  // No body anywhere: absent, and named as absent.
  const absent = run(['chain', 'verify', '--ledger', ledger], env);
  assert.equal(absent.status, 1);
  assert.match(absent.stdout, /Ledger: {7}POLICY_MISSING/);

  // The saved body restores verification, because its hash is the commitment.
  const restored = run(['chain', 'verify', '--ledger', ledger, '--policy', saved], env);
  assert.equal(restored.status, 0, restored.stdout + restored.stderr);
  assert.match(restored.stdout, /ok {3}writer_authorization/);
  assert.match(restored.stdout, /Ledger: {7}VALID/);

  // A different body is not a policy change: it hashes differently and fails
  // as a mismatch, which is distinguishable from the absent case above.
  const wrong = path.join(dir, 'wrong-policy.json');
  fs.writeFileSync(wrong, JSON.stringify({
    writer_keys: ['ed25519:' + 'a'.repeat(64)],
    admin_keys: [],
    witness_policy: null,
  }) + '\n');
  const mismatched = run(['chain', 'verify', '--ledger', ledger, '--policy', wrong], env);
  assert.equal(mismatched.status, 1);
  assert.match(mismatched.stdout, /Ledger: {7}POLICY_MISMATCH/);
  assert.doesNotMatch(mismatched.stdout, /POLICY_MISSING/);

  // An explicit file that cannot be read is a caller error, not a missing
  // sidecar, and does not silently fall back to one.
  const unreadable = run(['chain', 'verify', '--ledger', ledger, '--policy', path.join(dir, 'absent.json')], env);
  assert.equal(unreadable.status, 1);
  assert.match(unreadable.stderr, /policy file not found/);

  // Append accepts the supplied body and attaches the block as usual.
  const doc2 = path.join(dir, 'doc2.txt');
  fs.writeFileSync(doc2, 'A second document, appended under the saved policy.\n');
  assert.equal(run(['audit', doc2], env).status, 0);
  const receipt2 = path.join(dir, 'doc2.verifyd-receipt.json');
  const appended = run(['chain', 'append', receipt2, '--ledger', ledger, '--policy', saved], env);
  assert.equal(appended.status, 0, appended.stdout + appended.stderr);
  assert.match(appended.stdout, /Ledger: {7}IN CHAIN \(seq 2, tree 2\)/);

  // The same append with a mismatched body is refused, and nothing is recorded.
  const doc3 = path.join(dir, 'doc3.txt');
  fs.writeFileSync(doc3, 'A third document, refused under a wrong policy.\n');
  assert.equal(run(['audit', doc3], env).status, 0);
  const receipt3 = path.join(dir, 'doc3.verifyd-receipt.json');
  const refusedAppend = run(['chain', 'append', receipt3, '--ledger', ledger, '--policy', wrong], env);
  assert.equal(refusedAppend.status, 1);
  assert.match(refusedAppend.stderr, /LEDGER_POLICY_MISMATCH/);
  assert.equal(JSON.parse(fs.readFileSync(receipt3, 'utf8')).ledger, undefined);

  // A reseal authorizes from the supplied body too: leave the entry log ahead
  // of the checkpoint log, then repair it with only the saved policy.
  const lines = checkpointLines(ledger);
  fs.writeFileSync(ledger + '.checkpoints.jsonl', lines[0] + '\n');
  const repaired = run(['chain', 'fsck', '--ledger', ledger, '--policy', saved], env);
  assert.equal(repaired.status, 0, repaired.stdout + repaired.stderr);
  assert.match(repaired.stdout, /CHECKPOINT_RESEALED/);
  assert.match(repaired.stdout, /Ledger: {7}VALID/);
});

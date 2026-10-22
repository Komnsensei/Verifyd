'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const Signing = require('../signing.cjs');
const Canonical = require('../canonicalize.cjs');
const Witness = require('../witness.cjs');
const lattice = require('../lattice.cjs');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-witness-'));
const trusted = path.join(root, 'trusted');
fs.mkdirSync(trusted, { recursive: true });

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function auditorKeyring(name) {
  const dir = path.join(root, name || 'auditor');
  Signing.createKey({ dir });
  return dir;
}

const auditorDir = auditorKeyring();
const auditorKeyId = Signing.activeKeyId({ dir: auditorDir });

function makeEnvelope(overrides) {
  const receipt = Object.assign({
    valf_version: '1.0',
    receipt_id: crypto.randomUUID(),
    lattice: { status: 'DEPOSITED' },
  }, overrides && overrides.receipt);
  receipt.this_hash = sha256(Canonical.canonicalJSON(receipt, { omitKeys: ['this_hash'] }));
  const envelope = {
    valf_version: '1.0',
    receipt_type: 'document',
    signed_at: (overrides && overrides.signed_at) || new Date().toISOString(),
    document: { file: 'doc.txt', sha256: sha256('doc') },
    receipt,
  };
  return Signing.seal(envelope, { dir: auditorDir });
}

function newWitness(name) {
  const dir = path.join(root, name);
  Signing.createKey({ dir });
  return { dir, key_id: Signing.activeKeyId({ dir }) };
}

function trust(witness, opts) {
  const keys = Signing.listKeys({ dir: witness.dir });
  const record = {
    key_id: keys[0].key_id,
    algorithm: 'ed25519',
    public_key_pem: keys[0].public_key_pem,
    created_at: keys[0].created_at,
    status: (opts && opts.status) || 'active',
    expires_at: (opts && opts.expires_at) || null,
  };
  fs.writeFileSync(path.join(trusted, keys[0].key_id.replace(':', '-') + '.pub.json'), JSON.stringify(record, null, 2));
  return keys[0].key_id;
}

function proofFor(witness, identity, name) {
  const file = path.join(root, (name || identity.replace(/[^a-z0-9]/gi, '_')) + '.proof.txt');
  fs.writeFileSync(file, Witness.bindingLine(witness.key_id, identity) + '\n');
  return file;
}

function attestOn(envelope, witness, identity, opts) {
  const proofPath = proofFor(witness, identity, opts && opts.proofName);
  const att = Witness.attest(envelope, Object.assign({
    dir: witness.dir,
    identity,
    proofPath,
  }, opts || {}));
  Witness.attach(envelope, att);
  return att;
}

const alice = newWitness('w-alice');
const bob = newWitness('w-bob');
const carol = newWitness('w-carol');
const dave = newWitness('w-dave');
const erin = newWitness('w-erin');
const voucher = newWitness('w-voucher');

for (const w of [alice, bob, carol, dave, erin, voucher]) trust(w);

test('four verified witnesses meet quorum with traceable identities and tiers', async () => {
  const envelope = makeEnvelope();
  attestOn(envelope, alice, 'alice@example.org');
  attestOn(envelope, bob, 'bob@example.org');
  attestOn(envelope, carol, 'carol@example.org');
  attestOn(envelope, dave, 'dave@example.org');

  const result = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(result.assessed, true);
  assert.strictEqual(result.quorum.counted, 4);
  assert.strictEqual(result.quorum.met, true);
  assert.deepStrictEqual(
    result.counted.map(w => w.identity).sort(),
    ['alice@example.org', 'bob@example.org', 'carol@example.org', 'dave@example.org']
  );
  assert.ok(result.counted.every(w => w.tier === 'key'));
  assert.ok(result.counted.every(w => /^ed25519:[0-9a-f]{64}$/.test(w.key_id)));
  assert.strictEqual(result.rejected.length, 0);
  assert.strictEqual(result.subject_digest, Witness.receiptDigest(envelope));
});

test('attaching attestations does not change what the receipt signature covers', async () => {
  const envelope = makeEnvelope();
  const before = Witness.receiptDigest(envelope);
  attestOn(envelope, alice, 'signed-later@example.org');
  const after = Witness.receiptDigest(envelope);

  assert.strictEqual(after, before);
  assert.strictEqual(Signing.open(envelope, { dir: auditorDir }).ok, true);
});

test('a signed attestation with no proof material is label-only and counts for nothing', async () => {
  const envelope = makeEnvelope();
  attestOn(envelope, alice, 'alice@example.org');
  const bare = {
    scheme: Witness.SCHEME,
    attestation_id: crypto.randomUUID(),
    identity: 'bare@example.org',
    witness_key_id: bob.key_id,
    receipt_digest: Witness.receiptDigest(envelope),
    attested_at: new Date().toISOString(),
    statement: 'I agree',
  };
  bare.signature = Signing.seal(Witness.attestationSubject(bare), {
    dir: bob.dir,
    keyId: bob.key_id,
    domain: Witness.ATTESTATION_DOMAIN,
  }).signature;
  Witness.attach(envelope, bare);

  const result = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 1);
  assert.strictEqual(result.quorum.met, false);
  assert.strictEqual(result.rejected.length, 1);
  assert.strictEqual(result.rejected[0].reason, 'label_only');
  assert.strictEqual(result.rejected[0].identity, 'bare@example.org');
});

test('an unsigned attestation is reported, not counted and not dropped', async () => {
  const envelope = makeEnvelope();
  attestOn(envelope, alice, 'alice@example.org');
  Witness.attach(envelope, {
    scheme: Witness.SCHEME,
    attestation_id: crypto.randomUUID(),
    identity: 'forged@example.org',
    witness_key_id: bob.key_id,
    receipt_digest: Witness.receiptDigest(envelope),
    attested_at: new Date().toISOString(),
  });

  const result = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 1);
  assert.strictEqual(result.rejected[0].reason, 'unsigned');
  assert.strictEqual(result.rejected.length, 1);
});

test('the same key under two labels counts once', async () => {
  const envelope = makeEnvelope();
  attestOn(envelope, alice, 'alice@example.org');
  attestOn(envelope, alice, 'alice-alt@example.org', { proofName: 'alice-alt' });

  const result = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 1);
  assert.strictEqual(result.quorum.met, false);
  assert.strictEqual(result.counted.length, 1);
  assert.strictEqual(result.counted[0].identity, 'alice@example.org');
  assert.deepStrictEqual(result.counted[0].aliases, ['alice-alt@example.org']);
  assert.ok(result.notes.some(n => n.code === 'same_key_multiple_labels'));
});

test('two keys claiming one identity are a conflict, counted once', async () => {
  const envelope = makeEnvelope();
  attestOn(envelope, alice, 'shared@example.org', { proofName: 'shared-alice' });
  attestOn(envelope, bob, 'shared@example.org', { proofName: 'shared-bob' });

  const result = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 1);
  assert.strictEqual(result.conflicts.length, 1);
  assert.strictEqual(result.conflicts[0].identity, 'shared@example.org');
  assert.deepStrictEqual(result.conflicts[0].key_ids.sort(), [alice.key_id, bob.key_id].sort());
  assert.ok(result.notes.some(n => n.code === 'label_conflict'));
});

test('the audited party cannot witness its own receipt', async () => {
  const envelope = makeEnvelope();
  const auditor = { dir: auditorDir, key_id: auditorKeyId };
  attestOn(envelope, auditor, 'self@example.org');

  const result = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 0);
  assert.strictEqual(result.rejected[0].reason, 'self_witness');
});

test('an attestation replayed from another receipt is rejected', async () => {
  const first = makeEnvelope();
  const second = makeEnvelope();
  const stolen = attestOn(first, alice, 'alice@example.org');
  Witness.attach(second, stolen);
  attestOn(second, bob, 'bob@example.org');

  const result = await Witness.assess(second, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 1);
  assert.ok(result.rejected.some(r => r.reason === 'wrong_receipt'));
});

test('a revoked witness key stops contributing', async () => {
  const revoked = newWitness('w-revoked');
  trust(revoked, { status: 'revoked' });
  const envelope = makeEnvelope();
  attestOn(envelope, alice, 'alice@example.org');
  attestOn(envelope, revoked, 'revoked@example.org');

  const result = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 1);
  assert.strictEqual(result.rejected[0].reason, 'key_revoked');
});

test('an expired witness key stops contributing until the receipt predates it', async () => {
  const expiring = newWitness('w-expiring');
  trust(expiring, { expires_at: '2020-01-01T00:00:00.000Z' });
  const now = makeEnvelope();
  attestOn(now, expiring, 'expired@example.org');
  const result = await Witness.assess(now, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 0);
  assert.strictEqual(result.rejected[0].reason, 'key_expired');

  const old = makeEnvelope({ signed_at: '2019-06-01T00:00:00.000Z' });
  attestOn(old, expiring, 'expired@example.org');
  const oldResult = await Witness.assess(old, { keyring: trusted });
  assert.strictEqual(oldResult.quorum.counted, 1, 'receipt signed before expiry still counts');
});

test('a witness key missing from the verifier keyring is rejected, not assumed', async () => {
  const stranger = newWitness('w-stranger');
  const envelope = makeEnvelope();
  attestOn(envelope, stranger, 'stranger@example.org');

  const result = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 0);
  assert.strictEqual(result.rejected[0].reason, 'unknown_witness_key');
});

test('editing an attestation after signing makes it invalid', async () => {
  const envelope = makeEnvelope();
  const att = attestOn(envelope, alice, 'alice@example.org');
  att.identity = 'someone-else@example.org';

  const result = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(result.quorum.counted, 0);
  assert.strictEqual(result.rejected[0].reason, 'signature_invalid');
});

test('proof bytes must match the attested hash and publish the binding line', async () => {
  const envelope = makeEnvelope();
  const proofPath = proofFor(alice, 'alice@example.org', 'alice-proof');
  const att = Witness.attest(envelope, { dir: alice.dir, identity: 'alice@example.org', proofPath });
  Witness.attach(envelope, att);

  fs.writeFileSync(proofPath, Witness.bindingLine(alice.key_id, 'someone-else@example.org') + '\n');
  const changed = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(changed.rejected[0].reason, 'proof_mismatch');

  // A resource that hashes correctly but never publishes the binding line.
  const blank = 'nothing useful here\n';
  fs.writeFileSync(proofPath, blank);
  const unbound = {
    scheme: Witness.SCHEME,
    attestation_id: crypto.randomUUID(),
    identity: 'alice@example.org',
    witness_key_id: alice.key_id,
    receipt_digest: Witness.receiptDigest(envelope),
    attested_at: new Date().toISOString(),
    statement: '',
    proof: { kind: 'resource', uri: att.proof.uri, content_sha256: sha256(Buffer.from(blank)) },
  };
  unbound.signature = Signing.seal(Witness.attestationSubject(unbound), {
    dir: alice.dir,
    keyId: alice.key_id,
    domain: Witness.ATTESTATION_DOMAIN,
  }).signature;
  envelope.attestations[0] = unbound;
  const rebound = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(rebound.rejected[0].reason, 'proof_no_binding');

  fs.rmSync(proofPath);
  const missing = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(missing.rejected[0].reason, 'proof_unavailable');
});

test('vouching upgrades the tier; a voucher from the audited party or the key itself does not', async () => {
  const envelope = makeEnvelope();
  const att = attestOn(envelope, alice, 'alice@example.org');
  Witness.vouch(envelope, att, { dir: voucher.dir, method: 'organizational' });

  const vouched = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(vouched.counted[0].tier, 'vouched');
  assert.strictEqual(vouched.counted[0].vouch.key_id, voucher.key_id);
  assert.strictEqual(vouched.quorum.met, false, 'one witness is still below 4');

  const second = makeEnvelope();
  const selfVouch = attestOn(second, alice, 'alice@example.org');
  Witness.vouch(second, selfVouch, { dir: auditorDir });
  const selfResult = await Witness.assess(second, { keyring: trusted });
  assert.strictEqual(selfResult.counted[0].tier, 'key');
  assert.strictEqual(selfResult.counted[0].vouch.reason, 'voucher_is_audited_party');

  const third = makeEnvelope();
  const unknownVouch = attestOn(third, alice, 'alice@example.org');
  Witness.vouch(third, unknownVouch, { dir: newWitness('w-unknown-voucher').dir });
  const unknownResult = await Witness.assess(third, { keyring: trusted });
  assert.strictEqual(unknownResult.counted[0].tier, 'key');
  assert.strictEqual(unknownResult.counted[0].vouch.reason, 'voucher_key_unknown');

  // A voucher forged by the witness key itself, bypassing the CLI guard.
  const fourth = makeEnvelope();
  const selfSigned = attestOn(fourth, alice, 'alice@example.org');
  const vouchSubject = Witness.voucherSubject({
    witness_key_id: alice.key_id,
    identity: selfSigned.identity,
    receipt_digest: Witness.receiptDigest(fourth),
    method: 'manual',
    issued_at: new Date().toISOString(),
    statement: '',
  });
  selfSigned.vouch = Object.assign({}, vouchSubject, {
    signature: Signing.seal(vouchSubject, { dir: alice.dir, keyId: alice.key_id, domain: Witness.VOUCH_DOMAIN }).signature,
  });
  const forged = await Witness.assess(fourth, { keyring: trusted });
  assert.strictEqual(forged.counted[0].tier, 'key');
  assert.strictEqual(forged.counted[0].vouch.reason, 'voucher_is_witness');
});

test('without a witness keyring the assessment says so instead of assuming quorum', async () => {
  const envelope = makeEnvelope();
  attestOn(envelope, alice, 'alice@example.org');

  const result = await Witness.assess(envelope, { keyring: null });
  assert.strictEqual(result.assessed, false);
  assert.strictEqual(result.reason, 'witness_keyring_missing');
  assert.strictEqual(result.quorum.counted, 0);
  assert.strictEqual(result.quorum.met, false);
});

test('lattice refuses label-only witnesses and trusts only a met assessment', async () => {
  const element = lattice.createElement({ title: 'Ratification subject', content: 'body' });
  lattice.promote(element, 'PROVISIONAL', { sponsor: 'sponsor' });
  lattice.promote(element, 'DEPOSITED', { sponsor: 'sponsor', anchor_uri: 'doi:10.5281/zenodo.1' });

  const labels = lattice.promote(element, 'RATIFIED', {
    attestations: ['W1', 'W2', 'W3', 'W4'].map(witness_id => ({ witness_id })),
  });
  assert.strictEqual(labels.ok, false);
  assert.match(labels.error, /labels are not witnesses/);

  const envelope = makeEnvelope();
  attestOn(envelope, alice, 'alice@example.org');
  attestOn(envelope, bob, 'bob@example.org');
  attestOn(envelope, carol, 'carol@example.org');
  const three = await Witness.assess(envelope, { keyring: trusted });
  const short = lattice.promote(element, 'RATIFIED', {
    witness_assessment: three,
    receipt_digest: three.subject_digest,
  });
  assert.strictEqual(short.ok, false);
  assert.match(short.error, /verified witnesses; got 3 \(0 rejected\)/);

  attestOn(envelope, dave, 'dave@example.org');
  const four = await Witness.assess(envelope, { keyring: trusted });
  assert.strictEqual(four.quorum.met, true);

  const stale = lattice.promote(element, 'RATIFIED', {
    witness_assessment: four,
    receipt_digest: 'f'.repeat(64),
  });
  assert.strictEqual(stale.ok, false);
  assert.match(stale.error, /different receipt/);

  const ratified = lattice.promote(element, 'RATIFIED', {
    witness_assessment: four,
    receipt_digest: four.subject_digest,
  });
  assert.strictEqual(ratified.ok, true, ratified.error);
  assert.strictEqual(element.status, 'RATIFIED');
  assert.strictEqual(element.attestations.length, 4);
  assert.ok(element.attestations.every(a => /^ed25519:/.test(a.key_id) && a.tier === 'key'));
  assert.strictEqual(element.witness_assessment.counted, 4);

  const oversight = lattice.checkOversight(four, false);
  assert.strictEqual(oversight.ok, true);
  assert.strictEqual(oversight.counted_witnesses, 4);
});

test.after(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

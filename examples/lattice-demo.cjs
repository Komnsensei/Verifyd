// Verifyd Lattice end-to-end demo
// 1. Show Lattice structure
// 2. Walk a document through the promotion ladder
// 3. Demonstrate forbidden transitions and label-only witnesses
// 4. Audit an external governance spec for compliance

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const lattice = require('../engine/lattice.cjs');
const Signing = require('../engine/signing.cjs');
const Witness = require('../engine/witness.cjs');
const Canonical = require('../engine/canonicalize.cjs');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// Real witness keys for the quorum demo. Each witness keeps its own keyring and
// publishes a proof resource that binds its key id to its identity. Quorum is
// counted over verified keys, never over the labels typed below.
const demoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-lattice-demo-'));
const auditorDir = path.join(demoDir, 'auditor');
const trustedDir = path.join(demoDir, 'trusted');
fs.mkdirSync(trustedDir, { recursive: true });
Signing.createKey({ dir: auditorDir });

const subjectReceipt = { valf_version: '1.0', receipt_id: crypto.randomUUID(), lattice: { status: 'DEPOSITED' } };
subjectReceipt.this_hash = sha256(Canonical.canonicalJSON(subjectReceipt, { omitKeys: ['this_hash'] }));
const subject = Signing.seal({
  valf_version: '1.0',
  receipt_type: 'document',
  signed_at: new Date().toISOString(),
  document: { file: 'lattice-demo.txt', sha256: sha256('demo body') },
  receipt: subjectReceipt,
}, { dir: auditorDir });

const identities = [
  'peer-review@oversight.example',
  'replication@oversight.example',
  'theory-check@oversight.example',
  'archive@oversight.example',
];
const witnesses = identities.map((identity, i) => {
  const dir = path.join(demoDir, 'w' + i);
  Signing.createKey({ dir });
  const keyId = Signing.activeKeyId({ dir });
  const record = Signing.listKeys({ dir })[0];
  const proofFile = path.join(demoDir, 'proof-' + i + '.txt');
  fs.writeFileSync(proofFile, Witness.bindingLine(keyId, identity) + '\n');
  fs.writeFileSync(path.join(trustedDir, keyId.replace(':', '-') + '.pub.json'), JSON.stringify({
    key_id: keyId,
    algorithm: 'ed25519',
    public_key_pem: record.public_key_pem,
    created_at: record.created_at,
    status: 'active',
    expires_at: null,
  }, null, 2));
  return { dir, identity, proofFile };
});

function attestedEnvelope(count) {
  const envelope = JSON.parse(JSON.stringify(subject));
  for (let i = 0; i < count; i++) {
    const w = witnesses[i];
    Witness.attach(envelope, Witness.attest(envelope, {
      dir: w.dir,
      identity: w.identity,
      proofContent: fs.readFileSync(w.proofFile),
      proofUri: url.pathToFileURL(w.proofFile).href,
    }));
  }
  return envelope;
}

async function main() {
  console.log('=== Verifyd Lattice Demo ===\n');

  console.log('[1] Lattice Core');
  console.log('    formula: ' + lattice.LATTICE.core_formula);
  Object.entries(lattice.LATTICE.components).forEach(([k, v]) => {
    console.log('    ' + k + ' = ' + v);
  });
  console.log('');

  console.log('[2] Promotion Ladder (10 levels)');
  lattice.LATTICE.promotion_ladder.forEach(s => {
    console.log('    ' + s.id.padEnd(20) + 'weight=' + String(s.weight).padEnd(12) + s.description.slice(0, 60));
  });
  console.log('');

  console.log('[3] Oversight Board');
  const ob = lattice.LATTICE.oversight_board;
  console.log('    seats:                    ' + ob.seats);
  console.log('    quorum:                   ' + ob.quorum_required);
  console.log('    self_ratification:        FORBIDDEN');
  console.log('    tier_0_sovereign:         FORBIDDEN');
  console.log('');

  console.log('[4] Walking element through promotion ladder');
  const el = lattice.createElement({
    kind: 'recommendation',
    title: 'Loan approval recommendation L-9821',
    content: 'Approve loan L-9821 per credit and DTI policy.',
    domain_id: 'D.compliance.lending',
    sponsor: 'sponsor-007',
  });
  console.log('    [a] created                   status=' + el.status);

  let r = lattice.promote(el, 'PROVISIONAL', { sponsor: 'sponsor-007' });
  console.log('    [b] DRAFT->PROVISIONAL        ok=' + r.ok + (r.error ? ' err=' + r.error : ''));

  r = lattice.promote(el, 'DEPOSITED', { sponsor: 'sponsor-007', anchor_uri: 'doi:10.5281/zenodo.99999999' });
  console.log('    [c] PROVISIONAL->DEPOSITED    ok=' + r.ok + (r.error ? ' err=' + r.error : ''));

  r = lattice.promote(el, 'RATIFIED', { sole_sovereign: 'MANUS' });
  console.log('    [d] DEPOSITED->RATIFIED (sole)  ok=' + r.ok + ' err=' + r.error);

  // Four typed labels are not four witnesses.
  r = lattice.promote(el, 'RATIFIED', {
    attestations: ['W1', 'W2', 'W3', 'W4'].map(witness_id => ({ witness_id, attested_at: new Date().toISOString() })),
  });
  console.log('    [e] 4 labels, no keys           ok=' + r.ok + ' err=' + r.error);

  const three = await Witness.assess(attestedEnvelope(3), { keyring: trustedDir, required: 4 });
  r = lattice.promote(el, 'RATIFIED', { witness_assessment: three, receipt_digest: three.subject_digest });
  console.log('    [f] 3 verified witnesses        ok=' + r.ok + ' err=' + r.error);

  const four = await Witness.assess(attestedEnvelope(4), { keyring: trustedDir, required: 4 });
  r = lattice.promote(el, 'RATIFIED', { witness_assessment: four, receipt_digest: four.subject_digest });
  console.log('    [g] 4 verified witnesses        ok=' + r.ok + (r.error ? ' err=' + r.error : ' status=' + el.status));

  const duplicateEnvelope = JSON.parse(JSON.stringify(subject));
  const w0 = witnesses[0];
  const secondLabel = 'archive-again@oversight.example';
  const secondProof = path.join(demoDir, 'proof-duplicate-label.txt');
  fs.writeFileSync(secondProof, Witness.bindingLine(Signing.activeKeyId({ dir: w0.dir }), secondLabel) + '\n');
  for (const [identity, proofFile] of [[w0.identity, w0.proofFile], [secondLabel, secondProof]]) {
    Witness.attach(duplicateEnvelope, Witness.attest(duplicateEnvelope, {
      dir: w0.dir,
      identity,
      proofContent: fs.readFileSync(proofFile),
      proofUri: url.pathToFileURL(proofFile).href,
    }));
  }
  const duplicate = await Witness.assess(duplicateEnvelope, { keyring: trustedDir, required: 4 });
  console.log('    [h] one key, two labels         counted=' + duplicate.quorum.counted +
    ' rejected=' + duplicate.rejected.length + ' (labels are not witnesses)');
  console.log('');

  console.log('[5] Forbidden transition tests');
  const skip = lattice.canTransition('DRAFT', 'DEPOSITED');
  console.log('    DRAFT->DEPOSITED              allowed=' + skip.allowed + ' reason=' + (skip.reason || 'n/a'));
  const pat = lattice.canTransition('PATTERN', 'RATIFIED');
  console.log('    PATTERN->RATIFIED             allowed=' + pat.allowed + ' reason=' + (pat.reason || 'n/a'));
  const res = lattice.canTransition('RESONANT', 'RATIFIED');
  console.log('    RESONANT->RATIFIED            allowed=' + res.allowed + ' reason=' + (res.reason || 'n/a'));
  console.log('');

  console.log('[6] External governance audit');
  const externalSpec = {
    name: 'External governance system X',
    sole_sovereign: 'TIER_0_OWNER',
    witness_seats: 7,
    quorum: 4,
    status_algebra: ['DRAFT', 'QUEUED', 'PROVISIONAL', 'DEPOSITED', 'RATIFIED'],
    external_anchor_required: true,
  };
  const audit = lattice.auditExternalGovernance(externalSpec);
  console.log('    audited:  ' + audit.audited_system);
  console.log('    verdict:  ' + audit.verdict);
  audit.findings.forEach(f => console.log('    ' + f.severity.padEnd(6) + f.principle.padEnd(28) + f.detail));
  console.log('');

  console.log('=== Lattice demo complete ===');
  console.log('Final element state: ' + el.status + ' with ' + el.attestations.length + ' attestations');
  console.log('Witness tiers: ' + el.attestations.map(a => a.identity + '=' + a.tier).join(', '));
  console.log('Persistence weight: ' + lattice.persistence(el).toFixed(4));
}

main()
  .catch(e => {
    console.error('Lattice demo failed: ' + (e && e.message ? e.message : e));
    process.exitCode = 1;
  })
  .finally(() => {
    fs.rmSync(demoDir, { recursive: true, force: true });
  });

'use strict';

// One end-to-end pass over the artifact lifecycle: audit a document, verify it,
// reject an untrusted signer, witness it to quorum, determine it, tamper with
// each artifact, then audit a PDF, commit it to a Merkle root and run the folder
// batch. Every path lives in a fresh temporary directory and every command gets
// an explicit keyring, so the user's ~/.verifyd keyring and the shipped example
// receipts are never read or written.
//
// The same lifecycle runs twice from two different clean workspaces. A step that
// only passes because an earlier run left a key, receipt, proof or root behind
// fails on the second run.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(ROOT, 'bin', 'verifyd.cjs');
const BATCH_AUDIT = path.join(ROOT, 'bin', 'batch-audit.cjs');
const EXAMPLE_PDF = path.join(ROOT, 'examples', 'Quantum Information Holography and the Born Rule.pdf');

const Signing = require('../signing.cjs');
const Merkle = require('../merkle.cjs');

const ISOLATED_ENV = [
  'VERIFYD_KEYRING',
  'VERIFYD_WITNESS_KEYS',
  'VERIFYD_TSA_URL',
  'VERIFYD_TSA_CA',
  'VERIFYD_TSA_TIMEOUT_MS',
];

function childEnv(extra) {
  const out = Object.assign({}, process.env);
  for (const key of ISOLATED_ENV) delete out[key];
  return Object.assign(out, extra || {});
}

function run(script, args, opts) {
  const options = opts || {};
  const res = spawnSync(process.execPath, [script].concat(args), {
    cwd: options.cwd,
    encoding: 'utf8',
    env: childEnv(options.env),
    maxBuffer: 8 * 1024 * 1024,
  });
  return { status: res.status, out: (res.stdout || '') + (res.stderr || '') };
}

function cli(args, opts) {
  return run(CLI, args, opts);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
}

function receiptPathFor(file) {
  return file.replace(/\.[^.]+$/, '') + '.verifyd-receipt.json';
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function assurance(out) {
  const match = out.match(/Assurance:\s+([0-9.]+) \(probability; model [^)]*\)(?:; absent: ([^\n]*))?/);
  assert.ok(match, 'no assurance line in output:\n' + out);
  return {
    probability: Number(match[1]),
    absent: (match[2] || '').split(', ').filter(Boolean),
  };
}

function audit(cwd, file, keys) {
  const res = cli(['audit', file, '--keyring', keys], { cwd });
  assert.strictEqual(res.status, 0, res.out);
  const receipt = receiptPathFor(path.isAbsolute(file) ? file : path.join(cwd, file));
  assert.ok(fs.existsSync(receipt), 'audit did not write ' + receipt);
  return receipt;
}

function attest(cwd, receiptFile, witness, identity, proof) {
  return cli(['witness', 'attest', path.basename(receiptFile),
    '--identity', identity, '--proof', proof, '--keyring', witness.dir], { cwd });
}

function hasPdftotext() {
  const probe = spawnSync('pdftotext', ['-v'], { encoding: 'utf8' });
  return !probe.error;
}

const PDF_SKIP = hasPdftotext()
  ? false
  : 'pdftotext (Poppler) is not installed; the PDF extraction path cannot run here';

// ---------------------------------------------------------------------------
// Core lifecycle: identities, audit, verification, witnesses, determination.
// ---------------------------------------------------------------------------

function coreLifecycle() {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-e2e-core-'));
  try {
    const keys = path.join(ws, 'keys');
    const unrelated = path.join(ws, 'unrelated-keys');
    const trust = path.join(ws, 'trusted-witnesses');

    // A. Identities. The signing keyring is created inside the workspace.
    let res = cli(['keys', 'init', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    const signer = (res.out.match(/ed25519:[0-9a-f]{64}/) || [])[0];
    assert.ok(signer, 'keys init did not report a key id:\n' + res.out);
    assert.strictEqual(fs.readFileSync(path.join(keys, 'active'), 'utf8').trim(), signer,
      'the active pointer does not name the key that was just created');
    assert.ok(!fs.existsSync(unrelated), 'the unrelated keyring must not exist yet');

    res = cli(['keys', 'path', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.strictEqual(path.resolve(res.out.trim()), path.resolve(keys));

    // B. Audit and sign a real document.
    const text = 'Loan decision L-9821: approve per credit history and DTI thresholds.\n';
    fs.writeFileSync(path.join(ws, 'decision.txt'), text);
    const receipt = audit(ws, 'decision.txt', keys);

    const sealed = readJson(receipt);
    assert.strictEqual(sealed.receipt_type, 'document');
    assert.strictEqual(sealed.document.file, 'decision.txt');
    assert.strictEqual(sealed.document.sha256, sha256Hex(text),
      'the receipt does not bind the exact document bytes');
    assert.strictEqual(sealed.signature.algorithm, 'ed25519');
    assert.strictEqual(sealed.signature.key_id, signer);

    // Independent cryptographic check, not a check of the CLI's own report.
    const opened = Signing.open(sealed, { dir: keys });
    assert.strictEqual(opened.ok, true, opened.message);
    assert.deepStrictEqual(opened.checks, {
      signature_present: true,
      key_known: true,
      public_key_matches_keyring: true,
      signature_valid: true,
      receipt_hash_valid: true,
    });

    res = cli(['verify', 'decision.verifyd-receipt.json', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Signature:\s+VALID/);
    assert.match(res.out, /Receipt hash:\s+VALID/);
    assert.match(res.out, /Status:\s+VALID/);

    // The same bytes under a keyring that never held the signer stay rejected.
    res = cli(['verify', 'decision.verifyd-receipt.json', '--keyring', unrelated], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /UNTRUSTED_KEY/);
    assert.match(res.out, /Status:\s+REJECTED/);
    assert.match(res.out, /signer key is not in the keyring/);

    // Tampering is detected at the signature, with no partial credit.
    const tampered = Object.assign({}, sealed);
    tampered.document = Object.assign({}, sealed.document, { words: sealed.document.words + 1 });
    writeJson(path.join(ws, 'tampered.json'), tampered);
    res = cli(['verify', 'tampered.json', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /SIGNATURE_INVALID/);
    assert.match(res.out, /Status:\s+REJECTED/);

    // C. Witnesses: one keyring per identity, trusted by the verifier separately.
    const identities = ['alice@example.org', 'bob@example.org', 'carol@example.org', 'dave@example.org'];
    const witnesses = identities.map((identity, i) => ({
      identity,
      dir: path.join(ws, 'w' + i),
      proof: path.join(ws, 'proof-' + i + '.txt'),
    }));

    for (const witness of witnesses) {
      res = cli(['witness', 'init', '--keyring', witness.dir], { cwd: ws });
      assert.strictEqual(res.status, 0, res.out);
      res = cli(['witness', 'prove', witness.identity, '--proof-out', witness.proof,
        '--keyring', witness.dir], { cwd: ws });
      assert.strictEqual(res.status, 0, res.out);
      const binding = fs.readFileSync(witness.proof, 'utf8');
      assert.match(binding, /^verifyd-witness: ed25519:[0-9a-f]{64} /);
      assert.ok(binding.includes(witness.identity), 'the proof does not bind the identity');
      res = cli(['witness', 'register', witness.dir, '--into', trust], { cwd: ws });
      assert.strictEqual(res.status, 0, res.out);
    }
    for (const witness of witnesses) {
      res = attest(ws, receipt, witness, witness.identity, witness.proof);
      assert.strictEqual(res.status, 0, res.out);
    }

    // Each attestation names the digest of the receipt bytes it signed, so a
    // proof lifted from another receipt cannot count here.
    const attested = readJson(receipt);
    const attestedDigest = sha256Hex(Signing.signingPayload(attested));
    assert.strictEqual(attested.attestations.length, identities.length);
    for (const att of attested.attestations) {
      assert.strictEqual(att.receipt_digest, attestedDigest,
        'attestation is not bound to this receipt');
    }

    res = cli(['verify', 'decision.verifyd-receipt.json', '--keyring', keys,
      '--witness-keys', trust], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Signature:\s+VALID/);
    assert.match(res.out, /Receipt hash:\s+VALID/, 'attestations must not disturb the signed payload');
    assert.match(res.out, /Witnesses:\s+4 counted of 4 required \(QUORUM MET\)/);
    for (const identity of identities) {
      assert.match(res.out, new RegExp('counted\\s+' + identity.replace(/[.]/g, '\\.')));
    }
    assert.match(res.out, /tier=key/);
    assert.doesNotMatch(res.out, /rejected/);

    // Three verified witnesses are not a quorum, and the score withholds credit.
    fs.writeFileSync(path.join(ws, 'three-witness.txt'), 'Three witness subject.\n');
    const threeWitness = audit(ws, 'three-witness.txt', keys);
    for (const witness of witnesses.slice(0, 3)) {
      res = attest(ws, threeWitness, witness, witness.identity, witness.proof);
      assert.strictEqual(res.status, 0, res.out);
    }
    res = cli(['verify', 'three-witness.verifyd-receipt.json', '--keyring', keys,
      '--witness-keys', trust], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Witnesses:\s+3 counted of 4 required \(QUORUM NOT MET\)/);
    assert.ok(assurance(res.out).absent.includes('witness_quorum'),
      'an unmet quorum must be named as absent evidence');
    assert.doesNotMatch(res.out, /QUORUM MET/);
    assert.match(res.out, /Status:\s+VALID/,
      'a receipt that does not claim RATIFIED stays valid without a quorum');

    // The audited party's own key never counts as a witness.
    fs.writeFileSync(path.join(ws, 'self-witness.txt'), 'Self witness subject.\n');
    const selfWitness = audit(ws, 'self-witness.txt', keys);
    res = cli(['witness', 'register', keys, '--into', trust], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    const ownProof = path.join(ws, 'auditor.proof.txt');
    res = cli(['witness', 'prove', 'auditor@example.org', '--proof-out', ownProof,
      '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    res = attest(ws, selfWitness, { dir: keys }, 'auditor@example.org', ownProof);
    assert.strictEqual(res.status, 0, res.out);
    res = cli(['verify', 'self-witness.verifyd-receipt.json', '--keyring', keys,
      '--witness-keys', trust], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Witnesses:\s+0 counted of 4 required \(QUORUM NOT MET\)/);
    assert.match(res.out, /rejected\s+auditor@example\.org\s+ed25519:[0-9a-f]{12}\.\.\.\s+self_witness/);
    assert.match(res.out, /the audited party signed this receipt and cannot witness it/);

    // One key under two labels counts once.
    fs.writeFileSync(path.join(ws, 'duplicate-key.txt'), 'Duplicate key subject.\n');
    const duplicate = audit(ws, 'duplicate-key.txt', keys);
    const w0 = witnesses[0];
    const dupProofA = path.join(ws, 'dup-a.proof.txt');
    const dupProofB = path.join(ws, 'dup-b.proof.txt');
    assert.strictEqual(cli(['witness', 'prove', 'dup-a@example.org', '--proof-out', dupProofA,
      '--keyring', w0.dir], { cwd: ws }).status, 0);
    assert.strictEqual(cli(['witness', 'prove', 'dup-b@example.org', '--proof-out', dupProofB,
      '--keyring', w0.dir], { cwd: ws }).status, 0);
    assert.strictEqual(attest(ws, duplicate, w0, 'dup-a@example.org', dupProofA).status, 0);
    assert.strictEqual(attest(ws, duplicate, w0, 'dup-b@example.org', dupProofB).status, 0);
    res = cli(['verify', 'duplicate-key.verifyd-receipt.json', '--keyring', keys,
      '--witness-keys', trust], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Witnesses:\s+1 counted of 4 required/);
    assert.match(res.out, /same_key_multiple_labels/);
    assert.doesNotMatch(res.out, /QUORUM MET/);

    // Two keys claiming one identity are a conflict and the identity counts once.
    fs.writeFileSync(path.join(ws, 'conflict.txt'), 'Conflict subject.\n');
    const conflict = audit(ws, 'conflict.txt', keys);
    const sharedA = path.join(ws, 'shared-a.proof.txt');
    const sharedB = path.join(ws, 'shared-b.proof.txt');
    assert.strictEqual(cli(['witness', 'prove', 'shared@example.org', '--proof-out', sharedA,
      '--keyring', witnesses[0].dir], { cwd: ws }).status, 0);
    assert.strictEqual(cli(['witness', 'prove', 'shared@example.org', '--proof-out', sharedB,
      '--keyring', witnesses[1].dir], { cwd: ws }).status, 0);
    assert.strictEqual(attest(ws, conflict, witnesses[0], 'shared@example.org', sharedA).status, 0);
    assert.strictEqual(attest(ws, conflict, witnesses[1], 'shared@example.org', sharedB).status, 0);
    res = cli(['verify', 'conflict.verifyd-receipt.json', '--keyring', keys,
      '--witness-keys', trust], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Witnesses:\s+1 counted of 4 required/);
    assert.match(res.out, /conflict\s+shared@example\.org\s+2 keys claim this identity \(counted once\)/);
    assert.match(res.out, /label_conflict/);

    // D. Determination, bound to the receipt that carries the full quorum.
    res = cli(['determination', 'create', 'decision.verifyd-receipt.json',
      '--keyring', keys,
      '--jurisdiction', 'EU', '--regime', 'EU_AI_ACT_2024',
      '--reviewer', 'Jane Doe', '--role', 'Head of Compliance',
      '--conclusion', 'compliant',
      '--fact', 'actor_role=provider', '--fact', 'high_risk=no',
      '--out', 'decision.determination.json'], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Status:\s+COMPLIANT/);
    assert.match(res.out, /NOT LEGAL ADVICE/);

    const determination = readJson(path.join(ws, 'decision.determination.json'));
    const witnessed = readJson(receipt);
    assert.strictEqual(determination.status.value, 'compliant');
    assert.strictEqual(determination.receipt_id, witnessed.receipt.receipt_id);
    assert.strictEqual(determination.receipt_digest,
      sha256Hex(Signing.signingPayload(witnessed)),
      'the determination does not bind the signed receipt bytes');

    res = cli(['determination', 'verify', 'decision.determination.json',
      '--receipt', 'decision.verifyd-receipt.json', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Status:\s+COMPLIANT/);
    assert.match(res.out, /Signature:\s+VALID/);
    assert.match(res.out, /Binding:\s+VALID/);
    assert.match(res.out, /Expired:\s+NO/);

    res = cli(['verify', 'decision.verifyd-receipt.json', '--keyring', keys,
      '--witness-keys', trust, '--determination', 'decision.determination.json'], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Status:\s+VALID/);
    assert.match(res.out, /Status:\s+compliant/);
    const complete = assurance(res.out);
    assert.ok(!complete.absent.includes('witness_quorum'), 'a met quorum must be credited');
    assert.ok(!complete.absent.includes('compliant_determination'), 'a compliant determination must be credited');

    // A changed conclusion is tampering, not a new determination.
    const changed = JSON.parse(JSON.stringify(determination));
    changed.review.conclusion = 'non_compliant';
    writeJson(path.join(ws, 'det-tampered.json'), changed);
    res = cli(['determination', 'verify', 'det-tampered.json',
      '--receipt', 'decision.verifyd-receipt.json', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /Status:\s+TAMPERED/);
    assert.match(res.out, /SIGNATURE_INVALID/);

    // The same determination against a different receipt is a wrong binding.
    res = cli(['determination', 'verify', 'decision.determination.json',
      '--receipt', 'three-witness.verifyd-receipt.json', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /Status:\s+WRONG_RECEIPT/);
    assert.match(res.out, /Binding:\s+MISMATCH/);

    res = cli(['verify', 'decision.verifyd-receipt.json', '--determination', 'no-such-det.json',
      '--keyring', keys, '--witness-keys', trust], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /Determination:\s+NOT FOUND/);
    assert.match(res.out, /Status:\s+REJECTED/);

    // Missing prerequisites fail at the stage that needs them, naming the file.
    res = cli(['verify', 'no-such-receipt.json', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /receipt not found/);

    res = cli(['determination', 'create', 'no-such-receipt.json',
      '--jurisdiction', 'EU', '--regime', 'EU_AI_ACT_2024',
      '--reviewer', 'Jane Doe', '--role', 'Head of Compliance',
      '--conclusion', 'compliant'], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /receipt not found/);

    res = cli(['determination', 'verify', 'decision.determination.json',
      '--receipt', 'no-such-receipt.json', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /receipt not found/);

    res = cli(['witness', 'attest', 'no-such-receipt.json',
      '--identity', identities[0], '--proof', witnesses[0].proof,
      '--keyring', witnesses[0].dir], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /receipt not found/);

    res = cli(['witness', 'prove', 'nobody@example.org',
      '--keyring', path.join(ws, 'no-such-keyring')], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /no key in witness keyring; run witness init/);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// PDF lifecycle: audit, Merkle batch, anchored verification, folder batch.
// ---------------------------------------------------------------------------

function pdfLifecycle() {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-e2e-pdf-'));
  try {
    const keys = path.join(ws, 'keys');
    let res = cli(['keys', 'init', '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);

    const deck = path.join(ws, 'deck');
    fs.mkdirSync(deck);
    const pdf = path.join(deck, 'paper.pdf');
    fs.copyFileSync(EXAMPLE_PDF, pdf);

    const receipt = audit(ws, pdf, keys);
    const sealed = readJson(receipt);
    assert.strictEqual(sealed.document.file, 'paper.pdf');
    assert.ok(sealed.document.words > 1000, 'the PDF text was not extracted: ' + sealed.document.words);
    const opened = Signing.open(sealed, { dir: keys });
    assert.strictEqual(opened.ok, true, opened.message);

    // Merkle batch: the root is signed with the same keyring as the receipts.
    res = cli(['batch', deck, '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Receipts:\s+1/);

    const rootFile = path.join(deck, 'verifyd-batch.json');
    assert.ok(fs.existsSync(rootFile), 'batch did not write the root');
    const root = readJson(rootFile);
    assert.strictEqual(root.root_hash,
      Merkle.buildTree([Buffer.from(sha256Hex(Signing.signingPayload(sealed)), 'hex')]).root.toString('hex'),
      'the root does not commit to the receipt signed payload');

    const batched = readJson(receipt);
    assert.ok(batched.inclusion, 'batch did not attach an inclusion proof');
    assert.strictEqual(batched.inclusion.root_hash, root.root_hash);
    assert.strictEqual(batched.inclusion.tree_size, 1);

    res = cli(['verify', receipt, '--keyring', keys, '--batch', rootFile], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Inclusion:\s+VALID \(leaf 0 of 1/);
    assert.match(res.out, /Root:\s+VALID/);
    assert.match(res.out, /Batch check:\s+VALID/);
    assert.match(res.out, /Status:\s+VALID/);

    // An altered root does not authenticate the proof.
    const altered = Object.assign({}, root, { root_hash: '0'.repeat(64) });
    writeJson(path.join(ws, 'root-tampered.json'), altered);
    res = cli(['verify', receipt, '--keyring', keys, '--batch', 'root-tampered.json'], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /Root:\s+REJECTED/);
    assert.match(res.out, /Batch check:\s+INVALID/);
    assert.match(res.out, /Status:\s+REJECTED/);

    // A receipt signed by another keyring cannot be batched into this root.
    const otherKeys = path.join(ws, 'other-keys');
    const otherDeck = path.join(ws, 'other-deck');
    fs.mkdirSync(otherDeck);
    fs.writeFileSync(path.join(otherDeck, 'other.txt'), 'Other signer subject.\n');
    audit(ws, path.join(otherDeck, 'other.txt'), otherKeys);
    res = cli(['batch', otherDeck, '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /UNTRUSTED_KEY/);
    assert.match(res.out, /no root over unverified receipts/);

    // The folder batch seals and then verifies every receipt it wrote.
    const folder = path.join(ws, 'auditdeck');
    fs.mkdirSync(folder);
    fs.copyFileSync(EXAMPLE_PDF, path.join(folder, 'paper.pdf'));
    res = run(BATCH_AUDIT, [folder], { cwd: ws, env: { VERIFYD_KEYRING: keys } });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Sealed:\s+1\/1/);
    assert.match(res.out, /Verified:\s+1\/1/);

    const folderReceipt = path.join(folder, 'paper.verifyd-receipt.json');
    assert.ok(fs.existsSync(folderReceipt), 'the folder batch wrote no receipt');
    assert.ok(fs.existsSync(folderReceipt.replace(/\.json$/i, '') + '.verifyd-certificate.txt'),
      'the folder batch wrote no certificate');

    const summary = readJson(path.join(folder, 'BATCH_SUMMARY.json'));
    assert.strictEqual(summary.results.length, 1);
    assert.strictEqual(summary.results[0].file, 'paper.pdf');
    assert.strictEqual(summary.results[0].signed, true);
    assert.strictEqual(summary.results[0].verified, true,
      'the summary must state verification, not only that a signature exists');

    res = cli(['verify', folderReceipt, '--keyring', keys], { cwd: ws });
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Signature:\s+VALID/);
    assert.match(res.out, /Status:\s+VALID/);

    // A missing folder is a usage error, not a stack trace.
    res = run(BATCH_AUDIT, [path.join(ws, 'no-such-folder')], { cwd: ws });
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /folder not found/);
    assert.doesNotMatch(res.out, /ENOENT/);
    assert.doesNotMatch(res.out, /at Object\.readdirSync/);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------

test('end-to-end: audit, verify, witness and determine (clean workspace 1)', () => {
  coreLifecycle();
});

test('end-to-end: audit, verify, witness and determine (clean workspace 2)', () => {
  coreLifecycle();
});

test('end-to-end: PDF audit, Merkle batch and folder batch (clean workspace 1)',
  { skip: PDF_SKIP }, () => {
    pdfLifecycle();
  });

test('end-to-end: PDF audit, Merkle batch and folder batch (clean workspace 2)',
  { skip: PDF_SKIP }, () => {
    pdfLifecycle();
  });

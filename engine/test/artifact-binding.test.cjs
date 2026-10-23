'use strict';

// A receipt is only evidence of the document it names if verification rehashes
// that document. These tests seal a receipt, modify the artifact normally (no
// editing of the receipt), and require a non-zero exit with an explicit
// integrity failure. They also pin the fail-closed cases: a moved, missing or
// unreadable artifact must not report VALID, and --artifact is the only way to
// point at a document that no longer sits beside its receipt.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(ROOT, 'bin', 'verifyd.cjs');
const EXAMPLE_PDF = path.join(ROOT, 'examples', 'Quantum Information Holography and the Born Rule.pdf');

const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-artifact-'));
const keys = path.join(workspace, 'keys');
const doc = path.join(workspace, 'decision.txt');
const receipt = path.join(workspace, 'decision.verifyd-receipt.json');

const ORIGINAL = 'Decision L-1: approved.\n';
const MODIFIED = 'Decision L-1: approved.\nThe amount was changed to 9,000,000.\n';

function run(args, opts) {
  const res = spawnSync(process.execPath, [CLI].concat(args), {
    cwd: (opts && opts.cwd) || workspace,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
    env: Object.assign({}, process.env, { VERIFYD_KEYRING: keys }),
  });
  return { status: res.status, out: (res.stdout || '') + (res.stderr || '') };
}

function readReceipt() {
  return JSON.parse(fs.readFileSync(receipt, 'utf8'));
}

function pdftotextAvailable() {
  return !spawnSync('pdftotext', ['-v'], { encoding: 'utf8' }).error;
}

test.before(() => {
  fs.writeFileSync(doc, ORIGINAL);
  const audit = run(['audit', 'decision.txt', '--keyring', keys]);
  assert.strictEqual(audit.status, 0, audit.out);
});

test.after(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

test('G1: a document modified after sealing is rejected, with an integrity reason', () => {
  fs.writeFileSync(doc, MODIFIED);
  try {
    const res = run(['verify', 'decision.verifyd-receipt.json', '--keyring', keys]);
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /Signature:\s+VALID/, 'the receipt itself is still signed');
    assert.match(res.out, /Receipt hash:\s+VALID/, 'the receipt is internally consistent');
    assert.match(res.out, /Artifact:\s+CHANGED/);
    assert.match(res.out, /Status:\s+REJECTED/);
    assert.match(res.out, /Reason:\s+document changed after sealing/);
  } finally {
    fs.writeFileSync(doc, ORIGINAL);
  }
});

test('restoring the exact document restores VALID', () => {
  const res = run(['verify', 'decision.verifyd-receipt.json', '--keyring', keys]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Artifact:\s+VALID \(decision\.txt\)/);
  assert.match(res.out, /Status:\s+VALID/);
});

test('a missing document fails closed instead of reporting VALID', () => {
  fs.rmSync(doc);
  try {
    const res = run(['verify', 'decision.verifyd-receipt.json', '--keyring', keys]);
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /Artifact:\s+NOT FOUND/);
    assert.match(res.out, /Status:\s+REJECTED/);
    assert.match(res.out, /Reason:\s+document not found beside the receipt/);
  } finally {
    fs.writeFileSync(doc, ORIGINAL);
  }
});

test('a relocated receipt needs --artifact, and the check still binds the digest', () => {
  const moved = path.join(workspace, 'moved');
  fs.mkdirSync(moved);
  fs.copyFileSync(receipt, path.join(moved, 'decision.verifyd-receipt.json'));

  const without = run(['verify', path.join('moved', 'decision.verifyd-receipt.json'), '--keyring', keys]);
  assert.strictEqual(without.status, 1, without.out);
  assert.match(without.out, /Artifact:\s+NOT FOUND/);

  const withArtifact = run(['verify', path.join('moved', 'decision.verifyd-receipt.json'),
    '--keyring', keys, '--artifact', doc]);
  assert.strictEqual(withArtifact.status, 0, withArtifact.out);
  assert.match(withArtifact.out, /Artifact:\s+VALID/);
  assert.match(withArtifact.out, /Status:\s+VALID/);

  const other = path.join(workspace, 'other.txt');
  fs.writeFileSync(other, 'A different document entirely.\n');
  const wrong = run(['verify', path.join('moved', 'decision.verifyd-receipt.json'),
    '--keyring', keys, '--artifact', other]);
  assert.strictEqual(wrong.status, 1, wrong.out);
  assert.match(wrong.out, /Artifact:\s+CHANGED/);
  assert.match(wrong.out, /Status:\s+REJECTED/);
});

test('certify reaches the same verdict as verify on a changed document', () => {
  fs.writeFileSync(doc, MODIFIED);
  try {
    const res = run(['certify', 'decision.verifyd-receipt.json', '--keyring', keys,
      '--out', path.join(workspace, 'changed-certificate.txt')]);
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /Artifact:\s+CHANGED/);
    assert.match(res.out, /Seal Status:\s+REJECTED/);
    assert.match(res.out, /Verification:\s+REJECTED/);
    const saved = fs.readFileSync(path.join(workspace, 'changed-certificate.txt'), 'utf8');
    assert.match(saved, /Artifact:\s+CHANGED/);
    assert.match(saved, /SEAL STATUS\s+REJECTED/);
  } finally {
    fs.writeFileSync(doc, ORIGINAL);
  }
});

test('a forged signature stays rejected even when the artifact matches', () => {
  const forged = readReceipt();
  forged.signature.value = '00'.repeat(64);
  fs.writeFileSync(path.join(workspace, 'forged.json'), JSON.stringify(forged, null, 2));
  const res = run(['verify', 'forged.json', '--keyring', keys]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Signature:\s+SIGNATURE_INVALID/);
  assert.match(res.out, /Artifact:\s+(VALID|NOT FOUND|CHANGED)/);
  assert.match(res.out, /Status:\s+REJECTED/);
});

test('a PDF artifact is rehashed from its text, and an unreadable one fails closed',
  { skip: pdftotextAvailable() ? false : 'pdftotext (Poppler) is not installed' }, () => {
    const pdf = path.join(workspace, 'paper.pdf');
    fs.copyFileSync(EXAMPLE_PDF, pdf);
    const audit = run(['audit', 'paper.pdf', '--keyring', keys]);
    assert.strictEqual(audit.status, 0, audit.out);

    const intact = run(['verify', 'paper.verifyd-receipt.json', '--keyring', keys]);
    assert.strictEqual(intact.status, 0, intact.out);
    assert.match(intact.out, /Artifact:\s+VALID \(paper\.pdf\)/);

    // Replace the PDF with bytes pdftotext cannot read: verification must not
    // fall back to "the receipt is signed, therefore VALID".
    const digest = crypto.createHash('sha256').update(fs.readFileSync(pdf)).digest('hex');
    fs.writeFileSync(pdf, 'not a pdf any more\n');
    try {
      const broken = run(['verify', 'paper.verifyd-receipt.json', '--keyring', keys]);
      assert.strictEqual(broken.status, 1, broken.out);
      assert.match(broken.out, /Artifact:\s+(UNCHECKED|CHANGED)/);
      assert.match(broken.out, /Status:\s+REJECTED/);
    } finally {
      fs.copyFileSync(EXAMPLE_PDF, pdf);
      assert.strictEqual(crypto.createHash('sha256').update(fs.readFileSync(pdf)).digest('hex'), digest);
    }

    const restored = run(['verify', 'paper.verifyd-receipt.json', '--keyring', keys]);
    assert.strictEqual(restored.status, 0, restored.out);
    assert.match(restored.out, /Artifact:\s+VALID/);
  });

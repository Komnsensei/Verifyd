'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const CLI = path.join(__dirname, '..', '..', 'bin', 'verifyd.cjs');
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-determination-cli-'));
const keyring = path.join(workspace, 'keys');
const doc = path.join(workspace, 'decision.txt');
const receipt = path.join(workspace, 'decision.verifyd-receipt.json');

async function run(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI].concat(args), { cwd: workspace, encoding: 'utf8' });
    return { status: 0, out: stdout + stderr };
  } catch (e) {
    return { status: typeof e.code === 'number' ? e.code : 1, out: (e.stdout || '') + (e.stderr || '') };
  }
}

function createArgs(outFile, extra) {
  return ['determination', 'create', receipt, '--keyring', keyring,
    '--jurisdiction', 'EU', '--regime', 'EU_AI_ACT_2024',
    '--reviewer', 'Jane Doe', '--role', 'Head of Compliance',
    '--conclusion', 'compliant',
    '--fact', 'actor_role=provider', '--fact', 'high_risk=no',
    '--out', outFile].concat(extra || []);
}

function verifyAssurance(out) {
  const match = out.match(/Assurance:\s+([0-9.]+) \(probability; model [^)]*\)(?:; absent: ([^\n]*))?/);
  if (!match) return null;
  return { p: match[1], absent: (match[2] || '').split(', ').filter(Boolean) };
}

function certifyAssurance(out) {
  const p = out.match(/Assurance:\s+\d+ \/ 100\s+p=([0-9.]+)/);
  const absent = out.match(/Evidence Absent:\s+([^\n]*)/);
  return { p: p ? p[1] : null, absent: absent ? absent[1].split(', ').filter(Boolean) : [] };
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
}

test.before(async () => {
  fs.writeFileSync(doc, 'Loan decision L-9821: approve per credit history and DTI thresholds.\n');
  const audit = await run(['audit', doc, '--keyring', keyring]);
  assert.strictEqual(audit.status, 0, audit.out);
});

test.after(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

test('a compliant determination is created, signed and verified', async () => {
  const out = path.join(workspace, 'compliant.determination.json');
  const created = await run(createArgs(out));
  assert.strictEqual(created.status, 0, created.out);
  assert.match(created.out, /Status:\s+COMPLIANT/);
  assert.match(created.out, /NOT LEGAL ADVICE/);

  const det = readJson(out);
  assert.strictEqual(det.status.value, 'compliant');
  assert.ok(det.signature.value);
  assert.strictEqual(det.receipt_digest.length, 64);

  const verified = await run(['determination', 'verify', out, '--receipt', receipt, '--keyring', keyring]);
  assert.strictEqual(verified.status, 0, verified.out);
  assert.match(verified.out, /Status:\s+COMPLIANT/);
  assert.match(verified.out, /Signature:\s+VALID/);
  assert.match(verified.out, /Binding:\s+VALID/);
  assert.match(verified.out, /Expired:\s+NO/);

  const withReceipt = await run(['verify', receipt, '--keyring', keyring, '--determination', out]);
  assert.strictEqual(withReceipt.status, 0, withReceipt.out);
  assert.match(withReceipt.out, /Determination:\s+/);
  assert.match(withReceipt.out, /Reviewer:\s+Jane Doe \(Head of Compliance\)/);
  assert.match(withReceipt.out, /Status:\s+VALID/);
});

test('an unsigned determination never renders as valid', async () => {
  const out = path.join(workspace, 'unsigned.determination.json');
  await run(createArgs(out));
  const det = readJson(out);
  delete det.signature;
  writeJson(out, det);

  const verified = await run(['determination', 'verify', out, '--receipt', receipt, '--keyring', keyring]);
  assert.strictEqual(verified.status, 1, verified.out);
  assert.match(verified.out, /Status:\s+UNSIGNED/);
  assert.match(verified.out, /Signature:\s+UNSIGNED/);

  const withReceipt = await run(['verify', receipt, '--keyring', keyring, '--determination', out]);
  assert.strictEqual(withReceipt.status, 1, withReceipt.out);
  assert.match(withReceipt.out, /  Status:\s+unsigned/);
  assert.match(withReceipt.out, /Status:\s+REJECTED/);
});

test('an edited determination is reported tampered', async () => {
  const out = path.join(workspace, 'tampered.determination.json');
  await run(createArgs(out));
  const det = readJson(out);
  det.review.conclusion = 'non_compliant';
  writeJson(out, det);

  const verified = await run(['determination', 'verify', out, '--receipt', receipt, '--keyring', keyring]);
  assert.strictEqual(verified.status, 1, verified.out);
  assert.match(verified.out, /Status:\s+TAMPERED/);
  assert.match(verified.out, /Signature:\s+SIGNATURE_INVALID/);
});

test('an expired determination is signed but refused', async () => {
  const out = path.join(workspace, 'expired.determination.json');
  const created = await run(createArgs(out, ['--expires', '2020-01-01T00:00:00Z']));
  assert.strictEqual(created.status, 1, created.out);
  assert.match(created.out, /Status:\s+EXPIRED/);
  assert.ok(fs.existsSync(out));

  const verified = await run(['determination', 'verify', out, '--receipt', receipt, '--keyring', keyring]);
  assert.strictEqual(verified.status, 1, verified.out);
  assert.match(verified.out, /Status:\s+EXPIRED/);
  assert.match(verified.out, /Signature:\s+VALID/);
  assert.match(verified.out, /Expired:\s+YES/);

  const withReceipt = await run(['verify', receipt, '--keyring', keyring, '--determination', out]);
  assert.strictEqual(withReceipt.status, 1, withReceipt.out);
  assert.match(withReceipt.out, /Status:\s+REJECTED/);
  assert.match(withReceipt.out, /Reason:\s+determination expired/);
});

test('a determination verified against another receipt is refused', async () => {
  const out = path.join(workspace, 'bound.determination.json');
  await run(createArgs(out));

  const otherDoc = path.join(workspace, 'other.txt');
  fs.writeFileSync(otherDoc, 'A different decision on different bytes.\n');
  const audit = await run(['audit', otherDoc, '--keyring', keyring]);
  assert.strictEqual(audit.status, 0, audit.out);
  const otherReceipt = path.join(workspace, 'other.verifyd-receipt.json');

  const verified = await run(['determination', 'verify', out, '--receipt', otherReceipt, '--keyring', keyring]);
  assert.strictEqual(verified.status, 1, verified.out);
  assert.match(verified.out, /Status:\s+WRONG_RECEIPT/);
  assert.match(verified.out, /Binding:\s+MISMATCH/);
});

test('a missing applicability fact yields an incomplete record', async () => {
  const out = path.join(workspace, 'incomplete.determination.json');
  const created = await run(['determination', 'create', receipt, '--keyring', keyring,
    '--jurisdiction', 'EU', '--regime', 'EU_AI_ACT_2024',
    '--reviewer', 'Jane Doe', '--role', 'Head of Compliance',
    '--conclusion', 'compliant', '--fact', 'actor_role=provider', '--out', out]);
  assert.strictEqual(created.status, 1, created.out);
  assert.match(created.out, /Status:\s+INCOMPLETE/);
  assert.match(created.out, /applicability_fact_missing: high_risk/);

  const verified = await run(['determination', 'verify', out, '--receipt', receipt, '--keyring', keyring]);
  assert.strictEqual(verified.status, 1, verified.out);
  assert.match(verified.out, /Status:\s+INCOMPLETE/);
});

test('an unknown jurisdiction is undetermined and refused', async () => {
  const out = path.join(workspace, 'undetermined.determination.json');
  const created = await run(['determination', 'create', receipt, '--keyring', keyring,
    '--jurisdiction', 'ZZ', '--regime', 'EU_AI_ACT_2024',
    '--reviewer', 'Jane Doe', '--role', 'Head of Compliance',
    '--conclusion', 'compliant', '--out', out]);
  assert.strictEqual(created.status, 1, created.out);
  assert.match(created.out, /Status:\s+UNDETERMINED/);
  assert.match(created.out, /jurisdiction_unknown: ZZ/);

  const verified = await run(['determination', 'verify', out, '--receipt', receipt, '--keyring', keyring]);
  assert.strictEqual(verified.status, 1, verified.out);
  assert.match(verified.out, /Status:\s+UNDETERMINED/);
});

test('the CLI refuses to determine over an unsigned receipt', async () => {
  const unsignedReceipt = path.join(workspace, 'unsigned-receipt.json');
  const data = readJson(receipt);
  delete data.signature;
  writeJson(unsignedReceipt, data);
  const out = path.join(workspace, 'unsigned-receipt.determination.json');

  const created = await run(['determination', 'create', unsignedReceipt, '--keyring', keyring,
    '--jurisdiction', 'EU', '--regime', 'EU_AI_ACT_2024',
    '--reviewer', 'Jane Doe', '--role', 'Head of Compliance',
    '--conclusion', 'compliant', '--out', out]);
  assert.strictEqual(created.status, 1, created.out);
  assert.match(created.out, /RECEIPT_INVALID/);
  assert.ok(!fs.existsSync(out));
});

test('the CLI refuses to create without a reviewer, role, conclusion or jurisdiction', async () => {
  const missingRole = await run(['determination', 'create', receipt, '--keyring', keyring,
    '--jurisdiction', 'EU', '--regime', 'EU_AI_ACT_2024',
    '--reviewer', 'Jane Doe', '--conclusion', 'compliant', '--out', path.join(workspace, 'missing.json')]);
  assert.strictEqual(missingRole.status, 1, missingRole.out);
  assert.match(missingRole.out, /--role is required/);
  assert.ok(!fs.existsSync(path.join(workspace, 'missing.json')));

  const missingJurisdiction = await run(['determination', 'create', receipt, '--keyring', keyring,
    '--regime', 'EU_AI_ACT_2024', '--reviewer', 'Jane Doe', '--role', 'Head of Compliance',
    '--conclusion', 'compliant', '--out', path.join(workspace, 'missing.json')]);
  assert.strictEqual(missingJurisdiction.status, 1, missingJurisdiction.out);
  assert.match(missingJurisdiction.out, /--jurisdiction is required/);
});

test('determination show and verify reject a directory instead of leaking EISDIR', async () => {
  const dir = path.join(workspace, 'a-determination-folder');
  fs.mkdirSync(dir, { recursive: true });

  const shown = await run(['determination', 'show', dir]);
  assert.strictEqual(shown.status, 1, shown.out);
  assert.match(shown.out, /not a file/);
  assert.doesNotMatch(shown.out, /EISDIR/);

  const verified = await run(['determination', 'verify', dir]);
  assert.strictEqual(verified.status, 1, verified.out);
  assert.match(verified.out, /not a file/);
  assert.doesNotMatch(verified.out, /--receipt/);
});

test('determination verify separates a missing flag from a missing receipt', async () => {
  const out = path.join(workspace, 'binding-check.determination.json');
  await run(createArgs(out));

  const missingFile = await run(['determination', 'verify', out,
    '--receipt', path.join(workspace, 'no-such-receipt.json')]);
  assert.strictEqual(missingFile.status, 1, missingFile.out);
  assert.match(missingFile.out, /receipt not found: /);
  assert.doesNotMatch(missingFile.out, /--receipt <receipt.json> is required/);

  const missingFlag = await run(['determination', 'verify', out]);
  assert.strictEqual(missingFlag.status, 1, missingFlag.out);
  assert.match(missingFlag.out, /--receipt <receipt.json> is required/);
});

test('show and verify refuse JSON that is not a determination object', async () => {
  const nullFile = path.join(workspace, 'null.determination.json');
  fs.writeFileSync(nullFile, 'null\n');
  const shown = await run(['determination', 'show', nullFile]);
  assert.strictEqual(shown.status, 1, shown.out);
  assert.match(shown.out, /not a determination object/);
  assert.doesNotMatch(shown.out, /Cannot read|TypeError/);

  const arrayFile = path.join(workspace, 'array.determination.json');
  fs.writeFileSync(arrayFile, '[]\n');
  const verified = await run(['determination', 'verify', arrayFile, '--receipt', receipt, '--keyring', keyring]);
  assert.strictEqual(verified.status, 1, verified.out);
  assert.match(verified.out, /not a determination object/);
});

test('show labels the stored status as unverified and repeats the notice', async () => {
  const out = path.join(workspace, 'show.determination.json');
  await run(createArgs(out));

  const shown = await run(['determination', 'show', out]);
  assert.strictEqual(shown.status, 0, shown.out);
  assert.match(shown.out, /Stored status:\s+COMPLIANT \(UNVERIFIED/);
  assert.match(shown.out, /Signature:\s+NOT CHECKED/);
  assert.match(shown.out, /NOT LEGAL ADVICE/);
  assert.match(shown.out, /Machine:\s+satisfied/);
  assert.match(shown.out, /Conclusion:\s+compliant \(human judgement\)/);
});

test('regimes lists only repo-indexed entries and states the limits', async () => {
  const res = await run(['determination', 'regimes']);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /EU/);
  assert.match(res.out, /US/);
  assert.match(res.out, /EU_AI_ACT_2024/);
  assert.match(res.out, /NOT LEGAL ADVICE/);
  assert.match(res.out, /undetermined, never compliant/);
});

// Regression: verify used to score a determination against the receipt keyring
// even when --reviewer-keyring said to trust another key. The printed verdict
// said compliant while the assurance line called it untrusted. Both now read
// engine/evidence.cjs, so the report and the score cannot disagree.
test('a separate reviewer keyring is honoured by the report and the score', async () => {
  const reviewerKeys = path.join(workspace, 'reviewer-keys');
  const out = path.join(workspace, 'split.determination.json');
  const created = await run(createArgs(out, ['--reviewer-keyring', reviewerKeys]));
  assert.strictEqual(created.status, 0, created.out);
  assert.match(created.out, /Status:\s+COMPLIANT/);

  const verified = await run(['verify', receipt, '--keyring', keyring,
    '--reviewer-keyring', reviewerKeys, '--determination', out]);
  assert.strictEqual(verified.status, 0, verified.out);
  assert.match(verified.out, /^\s{2}Status:\s+compliant$/m);

  const scored = verifyAssurance(verified.out);
  assert.ok(scored, 'verify prints an assurance probability:\n' + verified.out);
  assert.ok(!scored.absent.includes('compliant_determination'),
    'a compliant determination cannot be listed as absent:\n' + verified.out);
  assert.doesNotMatch(verified.out, /determination_not_compliant/);

  const certFile = path.join(workspace, 'split-certificate.txt');
  const cert = await run(['certify', receipt, '--keyring', keyring,
    '--reviewer-keyring', reviewerKeys, '--determination', out, '--out', certFile]);
  assert.strictEqual(cert.status, 0, cert.out);

  const certScored = certifyAssurance(cert.out);
  assert.strictEqual(certScored.p, scored.p, 'verify and certify score the same evidence identically');
  assert.deepStrictEqual(certScored.absent, scored.absent);
});

test('a reviewer keyring that does not hold the reviewer is untrusted everywhere', async () => {
  const reviewerKeys = path.join(workspace, 'reviewer-keys-untrusted');
  const out = path.join(workspace, 'untrusted-reviewer.determination.json');
  const created = await run(createArgs(out, ['--reviewer-keyring', reviewerKeys]));
  assert.strictEqual(created.status, 0, created.out);

  const strangerKeys = path.join(workspace, 'stranger-keys');
  const init = await run(['keys', 'init', '--keyring', strangerKeys]);
  assert.strictEqual(init.status, 0, init.out);

  const verified = await run(['verify', receipt, '--keyring', keyring,
    '--reviewer-keyring', strangerKeys, '--determination', out]);
  assert.strictEqual(verified.status, 1, verified.out);
  assert.match(verified.out, /^\s{2}Status:\s+untrusted_reviewer_key$/m);

  const scored = verifyAssurance(verified.out);
  assert.ok(scored, verified.out);
  assert.ok(scored.absent.includes('compliant_determination'),
    'an untrusted reviewer key cannot contribute a compliant determination:\n' + verified.out);
  assert.match(verified.out, /determination_not_compliant: untrusted_reviewer_key/);

  const certFile = path.join(workspace, 'untrusted-certificate.txt');
  const cert = await run(['certify', receipt, '--keyring', keyring,
    '--reviewer-keyring', strangerKeys, '--determination', out, '--out', certFile]);
  assert.strictEqual(cert.status, 1, cert.out);
  assert.match(cert.out, /Verification:\s+REJECTED/);
  assert.match(cert.out, /Seal Status:\s+REJECTED/);

  const certScored = certifyAssurance(cert.out);
  assert.strictEqual(certScored.p, scored.p);
  assert.ok(certScored.absent.includes('compliant_determination'));
});

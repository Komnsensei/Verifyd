'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const v = require('../verifyd.cjs');
const Score = v.TrustScoreCalculator;

const ROOT = path.join(__dirname, '..', '..');
const CORPUS = path.join(ROOT, 'engine', 'calibration', 'corpus.jsonl');
const MODEL_FILE = path.join(ROOT, 'engine', 'calibration', 'trust-model.json');
const README = path.join(ROOT, 'README.md');

const dirs = [];

function tempDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

function readCorpus() {
  return fs.readFileSync(CORPUS, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
}

// Match the calibration script: the digest is over the corpus lines, so a
// checkout with CRLF endings names the same dataset as the LF blob.
function sha256File(file) {
  const text = fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

// Recompute the held-out metrics from the corpus and the committed parameters,
// independently of the calibration script's own evaluator.
function heldoutMetrics() {
  const rows = readCorpus().filter(r => r.split === 'heldout');
  const pairs = rows.map(row => ({ p: Score.probability(row.features), y: row.label }));
  const n = pairs.length;

  let brier = 0;
  const bins = Array.from({ length: 10 }, () => ({ n: 0, p: 0, y: 0 }));
  for (const pair of pairs) {
    brier += (pair.p - pair.y) * (pair.p - pair.y);
    const bin = bins[Math.min(9, Math.floor(pair.p * 10))];
    bin.n += 1;
    bin.p += pair.p;
    bin.y += pair.y;
  }

  let ece = 0;
  for (const bin of bins) {
    if (!bin.n) continue;
    ece += (bin.n / n) * Math.abs(bin.p / bin.n - bin.y / bin.n);
  }

  const positives = pairs.filter(p => p.y === 1);
  const negatives = pairs.filter(p => p.y === 0);
  let wins = 0;
  for (const pos of positives) {
    for (const neg of negatives) {
      if (pos.p > neg.p) wins += 1;
      else if (pos.p === neg.p) wins += 0.5;
    }
  }

  return {
    rows: n,
    brier: Math.round((brier / n) * 1e6) / 1e6,
    ece: Math.round(ece * 1e6) / 1e6,
    auc: Math.round((wins / (positives.length * negatives.length)) * 1e6) / 1e6,
  };
}

function makeEnvelope(opts) {
  const dir = (opts && opts.dir) || tempDir('verifyd-assurance-key-');
  const session = v.authenticatedSession({ human_id: 'auditor', agent_id: 'verifyd-test' });
  const output = v.sessionOutput({
    session_id: session.session_id,
    content: 'Audit note with provenance, receipts and hashes for review.',
    source_anchors: (opts && opts.anchors) || [{
      uri: 'file:///tmp/note.txt',
      span_hash: 'a'.repeat(64),
    }],
  });
  const checks = v.PolicyEngine.run(session, output);
  const receipt = v.buildReceipt({
    session,
    outputs: [output],
    policy_checks: checks,
    document_quality: v.TrustScoreCalculator.documentQuality(session, output, checks),
    ratification: v.ratificationEvent({
      session,
      output,
      policy_passed: true,
      document_quality_value: 50,
    }),
    prev_hash: 'GENESIS',
  });
  const envelope = v.buildEnvelope({ receipt });
  return { dir, sealed: v.Signing.seal(envelope, { dir }) };
}

test.after(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
});

test('the committed model is fitted, not hand-set', () => {
  assert.strictEqual(Score.SCHEME, 'verifyd-trust-assurance-v1');
  assert.strictEqual(Score.MODEL.features.length, 10);
  assert.strictEqual(Score.MODEL.parameters.weights.length, 10);
  assert.strictEqual(Score.MODEL.dataset.labels_origin, 'synthetic');
  assert.ok(Number.isFinite(Score.MODEL.parameters.intercept));
  assert.ok(Score.MODEL.parameters.weights.every(w => Number.isFinite(w) && w !== 0));
  assert.strictEqual(Score.MODEL.dataset.sha256, sha256File(CORPUS), 'model names the corpus it was fitted on');
  assert.strictEqual(Score.MODEL.dataset.rows, readCorpus().length);
});

test('a single command refits the committed model and reproduces its metrics', () => {
  const res = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'calibrate-trust.cjs')], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.strictEqual(res.status, 0, (res.stdout || '') + (res.stderr || ''));
  const metrics = Score.metrics();
  assert.match(res.stdout, new RegExp('held-out:\\s+Brier=' + metrics.brier.toFixed(6)));
  assert.match(res.stdout, new RegExp('ECE=' + metrics.ece.toFixed(6)));
  assert.match(res.stdout, new RegExp('AUC=' + metrics.auc.toFixed(6)));
});

test('held-out metrics reproduce from the corpus and the committed parameters', () => {
  const measured = heldoutMetrics();
  const reported = Score.metrics();

  assert.strictEqual(measured.rows, Score.MODEL.dataset.heldout_rows);
  assert.strictEqual(measured.brier, reported.brier);
  assert.strictEqual(measured.ece, reported.ece);
  assert.strictEqual(measured.auc, reported.auc);
  assert.strictEqual(reported.bins.length, 10);
  assert.strictEqual(reported.bins.reduce((n, b) => n + b.n, 0), measured.rows);
});

test('the documented numbers match the committed artifact', () => {
  const readme = fs.readFileSync(README, 'utf8');
  const reported = Score.metrics();
  assert.ok(readme.includes('Brier ' + reported.brier.toFixed(6)), 'README states the Brier score');
  assert.ok(readme.includes('ECE ' + reported.ece.toFixed(6)), 'README states the ECE');
  assert.ok(readme.includes('AUC ' + reported.auc.toFixed(6)), 'README states the AUC');
});

test('scoring is deterministic and fits nothing at inference time', () => {
  const features = readCorpus()[0].features;
  const first = Score.probability(features);
  for (let i = 0; i < 20; i++) assert.strictEqual(Score.probability(features), first);

  const modelBefore = JSON.stringify(JSON.parse(fs.readFileSync(MODEL_FILE, 'utf8')));
  Score.probability(features);
  const modelAfter = JSON.stringify(JSON.parse(fs.readFileSync(MODEL_FILE, 'utf8')));
  assert.strictEqual(modelAfter, modelBefore, 'inference never rewrites the model');

  assert.throws(() => Score.probability([1, 0]), /expected 10 feature values/);
});

test('a verified signature is the only signature state that pays', async () => {
  const { dir, sealed } = makeEnvelope();
  const valid = await Score.assess(sealed, { keyring: dir });
  assert.strictEqual(valid.evidence.signature.status, 'valid');
  assert.strictEqual(valid.features.signature, 1);

  const otherRing = tempDir('verifyd-assurance-other-');
  v.Signing.createKey({ dir: otherRing });
  const untrusted = await Score.assess(sealed, { keyring: otherRing });
  assert.strictEqual(untrusted.evidence.signature.status, 'key_untrusted');
  assert.strictEqual(untrusted.features.signature, 0, 'an untrusted key pays nothing');

  const unsigned = await Score.assess(Object.assign({}, sealed, { signature: undefined }), { keyring: dir });
  assert.strictEqual(unsigned.evidence.signature.status, 'unsigned');
  assert.ok(unsigned.absent.includes('signature'));
  assert.strictEqual(unsigned.features.missing, 1, 'an unsigned receipt is missing all five dimensions');
  assert.ok(untrusted.probability < valid.probability);
  assert.strictEqual(untrusted.probability, unsigned.probability,
    'a failed signature scores no better than no signature at all');
  assert.strictEqual(untrusted.features.missing, unsigned.features.missing,
    'a failed signature counts as missing evidence');
});

test('absent evidence is named and costs probability rather than being skipped', async () => {
  const { dir, sealed } = makeEnvelope();
  const base = await Score.assess(sealed, { keyring: dir });

  assert.ok(base.absent.includes('attested_time'));
  assert.ok(base.absent.includes('witness_quorum'));
  assert.ok(base.absent.includes('compliant_determination'));
  assert.strictEqual(base.features.missing, 0.8, 'four of five dimensions are missing; signature is the fifth');
  assert.strictEqual(base.features.signature, 1, 'the signature itself is verified');
  assert.ok(base.probability < 0.5, 'no timestamp, no witnesses, no determination cannot score high: ' + base.probability);

  // A timestamp that is present but cannot be checked is not treated as absent,
  // and is not treated as attested either.
  const withToken = Object.assign({}, sealed, { timestamp: {
    type: 'rfc3161',
    tsa_url: 'https://tsa.example',
    token: Buffer.from('not a real token').toString('base64'),
  } });
  const unverified = await Score.assess(withToken, { keyring: dir });
  assert.strictEqual(unverified.evidence.time.value, 0);
  assert.ok(unverified.absent.includes('attested_time'));

  // Supplying attested time removes both a missing dimension and a zero
  // feature, so the probability can only rise.
  const richer = Object.assign({}, base.features, { time: 1, missing: 0.6 });
  assert.ok(Score.probability(Score.MODEL.features.map(name => richer[name])) > base.probability);
});

test('only a compliant determination counts as compliance evidence', async () => {
  const { dir, sealed } = makeEnvelope();
  const base = await Score.assess(sealed, { keyring: dir });
  const raw = await v.AssuranceEvidence.collect(sealed, { keyring: dir });

  for (const status of ['non_compliant', 'incomplete', 'undetermined', 'expired', 'evidence_mismatch']) {
    const evidence = Object.assign({}, raw, {
      determination: {
        requested: true,
        file: 'determination.json',
        det: {},
        error: null,
        result: { status, ok: false, reasons: [status], reviewer: null },
      },
    });
    const scored = await Score.assess(sealed, { evidence });
    assert.ok(scored.absent.includes('compliant_determination'),
      status + ' must not fill the compliant_determination dimension');
    assert.ok(scored.probability <= base.probability + 1e-12,
      status + ' must not raise the assurance probability: ' + scored.probability);
  }

  const compliant = Object.assign({}, raw, {
    determination: {
      requested: true,
      file: 'determination.json',
      det: {},
      error: null,
      result: { status: 'compliant', ok: true, reasons: [], reviewer: { name: 'Jane Doe', role: 'Head' } },
    },
  });
  const scored = await Score.assess(sealed, { evidence: compliant });
  assert.ok(!scored.absent.includes('compliant_determination'));
  assert.ok(scored.probability > base.probability, 'a compliant determination must add evidence');
});

// A hostile receipt may carry a signature under the wrong key, a token it
// cannot chain, a bad inclusion proof, a batch root that does not authenticate,
// three witnesses, a warning or uncited policy result, an unresolved anchor, or
// an adverse review. Each is a failed check, and a failed check must score
// exactly what the same receipt scores when that evidence is absent. This walks
// all eight dimensions through both states on an otherwise complete receipt, so
// a partial-credit path cannot hide behind low baseline evidence.
function evidenceFixture() {
  const session = v.authenticatedSession({ human_id: 'auditor', agent_id: 'verifyd-test' });
  const output = v.sessionOutput({
    session_id: session.session_id,
    content: 'Audit note with provenance, receipts and hashes for review.',
    source_anchors: [{
      anchor_id: 'anchor-1',
      uri: 'https://arxiv.org/abs/2410.00001',
      span_hash: 'a'.repeat(64),
      retrieved_at: '2026-10-22T00:00:00.000Z',
      resolved_metadata: {
        title: 'Paper',
        source: 'arxiv',
        resolved_at: '2026-10-22T00:00:00.000Z',
      },
    }],
  });
  const checks = v.PolicyEngine.run(session, output);
  const envelope = {
    receipt: {
      policy_checks: checks,
      lattice: { status: 'RATIFIED' },
      outputs: [output],
    },
    attestations: [{}, {}, {}, {}],
  };

  const raw = {
    envelope,
    quorumRequired: 4,
    signature: {
      ok: true,
      code: 'OK',
      key_id: 'ed25519:' + 'b'.repeat(64),
      checks: { signature_present: true, signature_valid: true, receipt_hash_valid: true },
    },
    time: { status: 'attested', analysis: { gen_time: '2026-10-22T00:00:00.000Z' }, caError: null },
    inclusion: { present: true, proofOk: true, reason: null, record: {} },
    batch: { present: true, authenticated: true, reason: 'root signature and batch identity match' },
    witnesses: {
      assessed: true,
      quorum: { counted: 4, required: 4, met: true },
      counted: [{ tier: 'vouched' }, { tier: 'vouched' }, { tier: 'vouched' }, { tier: 'vouched' }],
      conflicts: [],
      rejected: [],
    },
    determination: {
      requested: true,
      error: null,
      result: { status: 'compliant', ok: true, reasons: [], reviewer: { name: 'Jane Doe', role: 'Head' } },
    },
  };
  return { envelope, raw };
}

test('no failing scored dimension can outscore its absent baseline', async () => {
  const good = evidenceFixture();
  const baseline = await Score.assess(good.envelope, { evidence: good.raw });
  assert.ok(baseline.probability > 0.9, 'the fixture is complete evidence: ' + baseline.probability);

  const cases = [
    {
      dimension: 'signature',
      absent: fix => { fix.raw.signature = { ok: false, code: 'UNSIGNED', checks: { signature_present: false } }; },
      failures: [
        fix => { fix.raw.signature = { ok: false, code: 'UNTRUSTED_KEY', checks: { signature_present: true } }; },
        fix => { fix.raw.signature = { ok: false, code: 'KEYRING_NOT_FOUND', checks: { signature_present: true } }; },
        fix => { fix.raw.signature = { ok: false, code: 'SIGNATURE_INVALID', checks: { signature_present: true } }; },
      ],
    },
    {
      dimension: 'time',
      absent: fix => { fix.raw.time = { status: 'unattested', analysis: null, caError: null }; },
      failures: [
        fix => { fix.raw.time = { status: 'unverified', analysis: {}, caError: null }; },
        fix => { fix.raw.time = { status: 'invalid', analysis: null, caError: 'TSA_CHAIN_UNTRUSTED' }; },
        fix => { fix.raw.time = { status: 'invalid', analysis: { reasons: ['bad imprint'] }, caError: null }; },
      ],
    },
    {
      dimension: 'inclusion proof',
      absent: fix => { fix.raw.inclusion = { present: false, proofOk: false, reason: null, record: null }; },
      failures: [
        fix => { fix.raw.inclusion = { present: true, proofOk: false, reason: 'path mismatch', record: {} }; },
        fix => { fix.raw.inclusion = { present: true, proofOk: false, reason: 'tree size mismatch', record: {} }; },
      ],
    },
    {
      dimension: 'batch root',
      absent: fix => { fix.raw.batch = { present: false, authenticated: false, error: null, reason: 'no batch root supplied' }; },
      failures: [
        fix => { fix.raw.batch = { present: true, authenticated: false, error: null, reason: 'batch_id mismatch: proof is from another batch' }; },
        fix => { fix.raw.batch = { present: true, authenticated: false, error: 'batch root is not valid JSON', reason: 'batch root is not valid JSON' }; },
        fix => { fix.raw.batch = { present: true, authenticated: false, error: null, opened: { ok: false, code: 'UNTRUSTED_KEY' }, reason: 'root signature UNTRUSTED_KEY' }; },
      ],
    },
    {
      dimension: 'witness quorum',
      absent: fix => {
        fix.envelope.attestations = [];
        fix.raw.witnesses = { assessed: false, quorum: { counted: 0, required: 4, met: false }, counted: [], conflicts: [], rejected: [], detail: 'no witness keyring' };
      },
      failures: [
        fix => { fix.raw.witnesses = { assessed: false, quorum: { counted: 0, required: 4, met: false }, counted: [], conflicts: [], rejected: [], detail: 'no witness keyring' }; },
        fix => { fix.raw.witnesses = Object.assign({}, fix.raw.witnesses, { quorum: { counted: 3, required: 4, met: false }, counted: [{ tier: 'vouched' }, { tier: 'vouched' }, { tier: 'vouched' }] }); },
        fix => { fix.raw.witnesses = Object.assign({}, fix.raw.witnesses, { quorum: { counted: 0, required: 4, met: false }, counted: [] }); },
      ],
    },
    {
      dimension: 'determination',
      absent: fix => { fix.raw.determination = { requested: false, error: null, result: null }; },
      failures: [
        fix => { fix.raw.determination = { requested: true, error: null, result: { status: 'non_compliant', ok: false, reasons: ['reviewer rejected'], reviewer: null } }; },
        fix => { fix.raw.determination = { requested: true, error: null, result: { status: 'expired', ok: false, reasons: ['expired'], reviewer: null } }; },
        fix => { fix.raw.determination = { requested: true, error: 'determination is not valid JSON', result: null }; },
      ],
    },
    {
      dimension: 'policy',
      absent: fix => { fix.envelope.receipt.policy_checks = []; },
      failures: [
        fix => { fix.envelope.receipt.policy_checks[0].result = 'warn'; },
        fix => { fix.envelope.receipt.policy_checks[0].result = 'fail'; },
        fix => { fix.envelope.receipt.policy_checks[0].result = 'skipped'; },
        fix => { fix.envelope.receipt.policy_checks[0].citations = []; },
        fix => { fix.envelope.receipt.policy_checks[0].citations = [{ standard: 'EU.AI.Act.2024.1689', locator: 'not a cited ground' }]; },
        fix => { fix.envelope.receipt.policy_checks[0].citations[0].standard = 'NOT.A.STANDARD'; },
        fix => { delete fix.envelope.receipt.policy_checks[0].checked_at; },
        fix => { fix.envelope.receipt.policy_checks.push({ principle: 'invented_check', result: 'pass', checked_at: '2026-10-22T00:00:00.000Z', citations: [{ standard: 'EU.AI.Act.2024.1689', locator: 'x' }] }); },
      ],
    },
    {
      dimension: 'anchors',
      absent: fix => { fix.envelope.receipt.outputs[0].source_anchors = []; },
      failures: [
        fix => { fix.envelope.receipt.outputs[0].source_anchors[0].resolved_metadata = null; },
        fix => { fix.envelope.receipt.outputs[0].source_anchors[0].resolved_metadata = {}; },
        fix => { fix.envelope.receipt.outputs[0].source_anchors[0].resolved_metadata = { title: 'Paper', source: 'arxiv' }; },
        fix => { fix.envelope.receipt.outputs[0].source_anchors[0].resolved_metadata = { title: 'Paper', source: 'unknown', resolved_at: '2026-10-22T00:00:00.000Z' }; },
        fix => { fix.envelope.receipt.outputs[0].source_anchors[0].resolved_metadata = { title: '', source: 'arxiv', resolved_at: '2026-10-22T00:00:00.000Z' }; },
        fix => { fix.envelope.receipt.outputs[0].source_anchors[0].uri = 'https://doi.org/10.1000/example'; },
        fix => { fix.envelope.receipt.outputs[0].source_anchors[0].span_hash = ''; },
      ],
    },
  ];


  for (const item of cases) {
    const absentFix = evidenceFixture();
    item.absent(absentFix);
    const absentScore = await Score.assess(absentFix.envelope, { evidence: absentFix.raw });
    assert.ok(absentScore.probability < baseline.probability,
      item.dimension + ' absent must score below complete evidence');

    for (const breakIt of item.failures) {
      const failedFix = evidenceFixture();
      breakIt(failedFix);
      const failedScore = await Score.assess(failedFix.envelope, { evidence: failedFix.raw });
      assert.ok(failedScore.probability <= absentScore.probability + 1e-12,
        item.dimension + ' failure (' + failedScore.probability + ') must not outscore absence (' +
        absentScore.probability + '): ' + JSON.stringify(failedScore.evidence));
      assert.ok(failedScore.probability < baseline.probability,
        item.dimension + ' failure must score below complete evidence');
    }
  }
});

test('quorum comes from the lattice configuration, not a constant', async () => {
  const lattice = require('../lattice.cjs');
  const { dir, sealed } = makeEnvelope();
  const evidence = await v.AssuranceEvidence.collect(sealed, { keyring: dir });

  assert.strictEqual(evidence.quorumRequired, lattice.LATTICE.oversight_board.quorum_required);
  const scored = await Score.assess(sealed, { evidence });
  assert.strictEqual(scored.evidence.witnesses.required, lattice.LATTICE.oversight_board.quorum_required);
});

test('provenance travels with every probability', async () => {
  const { dir, sealed } = makeEnvelope();
  const result = await Score.assess(sealed, { keyring: dir });

  assert.strictEqual(result.scheme, Score.SCHEME);
  assert.strictEqual(result.model_version, Score.MODEL.model_version);
  assert.strictEqual(result.dataset_sha256, sha256File(CORPUS));
  assert.strictEqual(result.labels_origin, 'synthetic');
  assert.match(result.meaning, /synthetic labels/);
  assert.ok(result.probability > 0 && result.probability < 1);
  assert.strictEqual(result.percent, Math.round(result.probability * 100));
});

test('the legacy heuristic is labelled uncalibrated and is not a probability', () => {
  const session = v.authenticatedSession({ human_id: 'auditor', agent_id: 'verifyd-test' });
  const output = v.sessionOutput({
    session_id: session.session_id,
    content: 'A document about provenance, hashes and audit review.',
    source_anchors: [{ uri: 'file:///tmp/note.txt', span_hash: 'a'.repeat(64) }],
  });
  const quality = v.TrustScoreCalculator.documentQuality(session, output, v.PolicyEngine.run(session, output));

  assert.strictEqual(quality.calibrated, false);
  assert.strictEqual(quality.status, 'UNCALIBRATED');
  assert.strictEqual(quality.scale, '0-100-heuristic');
  assert.ok(quality.value >= 0 && quality.value <= 100);
  assert.strictEqual(v.TrustScoreCalculator.compute, undefined, 'the old calibrated-looking entry point is gone');
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const v = require('../verifyd.cjs');
const Det = require('../determination.cjs');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-determination-'));
const auditorDir = path.join(root, 'auditor');
v.Signing.createKey({ dir: auditorDir });

const EU_FACTS = { actor_role: 'provider', high_risk: 'no' };
const REVIEWER = { name: 'Jane Doe', role: 'Head of Compliance', organization: 'Example Ltd' };

function makeReceipt(opts) {
  opts = opts || {};
  const session = v.authenticatedSession({ human_id: 'auditor-1', agent_id: 'agent@1.0' });
  const output = v.sessionOutput({
    session_id: session.session_id,
    content: 'Approved per credit history and policy thresholds.',
    source_anchors: [{
      anchor_id: 'a1',
      uri: 'doc://policy/dti',
      span_hash: v.sha256('policy'),
      retrieved_at: new Date().toISOString(),
    }],
    confidence: { value: 0.8, decay_function: 'none', decay_half_life_days: 0, scored_at: new Date().toISOString() },
  });
  const ratification = v.ratificationEvent({
    session,
    output,
    human_method: 'sso',
    policy_passed: true,
    document_quality_value: 70,
  });
  let checks = opts.checks || v.PolicyEngine.run(session, output, ratification);
  if (opts.mutateChecks) checks = opts.mutateChecks(checks);
  const receipt = v.buildReceipt({
    session,
    outputs: [output],
    policy_checks: checks,
    document_quality: v.TrustScoreCalculator.documentQuality(session, output, checks),
    ratification: opts.withoutRatification ? null : ratification,
    prev_hash: 'GENESIS',
  });
  const envelope = v.buildEnvelope({
    receipt_type: 'document',
    document: { file: 'decision.txt', sha256: v.sha256('decision') },
    receipt,
  });
  return v.Signing.seal(envelope, { dir: auditorDir });
}

function makeDetermination(envelope, overrides) {
  return Det.create(envelope, Object.assign({
    dir: auditorDir,
    jurisdiction: 'EU',
    regime: 'EU_AI_ACT_2024',
    reviewer: REVIEWER,
    conclusion: 'compliant',
    facts: EU_FACTS,
  }, overrides || {}));
}

function reseal(determination) {
  const payload = Object.assign({}, determination);
  delete payload.signature;
  return v.Signing.seal(payload, { dir: auditorDir, domain: Det.DOMAIN });
}

const good = makeReceipt();

test('a fully evidenced, signed determination is compliant and verifiable', () => {
  const det = makeDetermination(good);
  assert.strictEqual(det.status.value, 'compliant');
  assert.strictEqual(det.machine.result, 'satisfied');
  assert.strictEqual(det.machine.requirements.length, 3);
  assert.ok(det.machine.requirements.every(r => r.status === 'satisfied'));
  assert.strictEqual(det.receipt_digest, Det.receiptDigest(good));
  assert.match(det.notice, /NOT LEGAL ADVICE/);
  assert.strictEqual(det.review.reviewer.name, 'Jane Doe');
  assert.strictEqual(det.review.reviewer.role, 'Head of Compliance');

  const result = Det.verify(det, { receipt: good, dir: auditorDir });
  assert.strictEqual(result.status, 'compliant');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.signature.valid, true);
  assert.strictEqual(result.binding, 'valid');
  assert.strictEqual(result.expired, false);
});

test('the artifact keeps the machine and reviewer judgements separate', () => {
  const det = makeDetermination(good);
  assert.strictEqual(det.machine.checked_by, undefined);
  assert.ok(det.machine.requirements.every(r => r.checked_by === 'machine' && Array.isArray(r.evidence)));
  assert.strictEqual(det.review.conclusion, 'compliant');
  assert.ok(det.review.reviewed_at);
  assert.ok(!Object.prototype.hasOwnProperty.call(det.review, 'machine_result'));
});

test('an undeclared jurisdiction is undetermined, never compliant', () => {
  const det = makeDetermination(good, { jurisdiction: null });
  assert.strictEqual(det.status.value, 'undetermined');
  assert.ok(det.status.reasons.some(r => r.includes('jurisdiction_undeclared')));
  assert.strictEqual(Det.verify(det, { receipt: good, dir: auditorDir }).ok, false);
});

test('an unknown jurisdiction is undetermined and checks no requirements', () => {
  const det = makeDetermination(good, { jurisdiction: 'ZZ' });
  assert.strictEqual(det.status.value, 'undetermined');
  assert.strictEqual(det.jurisdiction.known, false);
  assert.strictEqual(det.machine.requirements.length, 0);
  assert.ok(det.status.reasons.some(r => r.includes('jurisdiction_unknown: ZZ')));
});

test('an unknown regime is undetermined', () => {
  const det = makeDetermination(good, { regime: 'NOT_A_REGIME' });
  assert.strictEqual(det.status.value, 'undetermined');
  assert.ok(det.status.reasons.some(r => r.includes('regime_unknown')));
});

test('a missing applicability fact makes the determination incomplete', () => {
  const det = makeDetermination(good, { facts: { actor_role: 'provider' } });
  assert.strictEqual(det.status.value, 'incomplete');
  assert.deepStrictEqual(det.applicability.missing, ['high_risk']);
  assert.ok(det.status.reasons.includes('applicability_fact_missing: high_risk'));
});

test('an invalid or unresolved applicability fact makes the determination incomplete', () => {
  const invalid = makeDetermination(good, { facts: { actor_role: 'provider', high_risk: 'maybe' } });
  assert.strictEqual(invalid.status.value, 'incomplete');
  assert.ok(invalid.status.reasons.includes('applicability_fact_invalid: high_risk'));

  const unresolved = makeDetermination(good, { facts: { actor_role: 'provider', high_risk: 'unknown' } });
  assert.strictEqual(unresolved.status.value, 'incomplete');
  assert.ok(unresolved.status.reasons.includes('applicability_unresolved: high_risk'));
});

test('a receipt without the required evidence is incomplete, never compliant', () => {
  const bare = makeReceipt({ mutateChecks: () => [] });
  const det = makeDetermination(bare);
  assert.strictEqual(det.machine.result, 'incomplete');
  assert.strictEqual(det.status.value, 'incomplete');
  assert.ok(det.machine.requirements.some(r => r.status === 'no_evidence'));
  assert.ok(det.machine.requirements
    .filter(r => r.predicate.startsWith('policy_check_passed:'))
    .every(r => r.status === 'no_evidence'));
  assert.strictEqual(Det.verify(det, { receipt: bare, dir: auditorDir }).ok, false);
});

test('a failing requirement is non_compliant even if the reviewer says compliant', () => {
  const failing = makeReceipt({
    mutateChecks: checks => checks.map(c => c.principle === 'audit_trail' ? Object.assign({}, c, { result: 'fail' }) : c),
  });
  const det = makeDetermination(failing);
  assert.strictEqual(det.machine.result, 'not_satisfied');
  assert.strictEqual(det.status.value, 'non_compliant');
  assert.ok(det.status.reasons.some(r => r.includes('machine_requirement_not_satisfied')));
});

test('a reviewer conclusion can disagree with a satisfied machine result', () => {
  const det = makeDetermination(good, { conclusion: 'non_compliant' });
  assert.strictEqual(det.machine.result, 'satisfied');
  assert.strictEqual(det.review.conclusion, 'non_compliant');
  assert.strictEqual(det.status.value, 'non_compliant');
});

test('reviewer conclusion alone cannot make an incomplete machine result compliant', () => {
  const bare = makeReceipt({ mutateChecks: () => [] });
  const det = makeDetermination(bare, { conclusion: 'compliant' });
  assert.strictEqual(det.review.conclusion, 'compliant');
  assert.strictEqual(det.machine.result, 'incomplete');
  assert.strictEqual(det.status.value, 'incomplete');
});

test('an unsigned determination verifies as unsigned and is not ok', () => {
  const det = makeDetermination(good);
  const unsigned = JSON.parse(JSON.stringify(det));
  delete unsigned.signature;
  const result = Det.verify(unsigned, { receipt: good, dir: auditorDir });
  assert.strictEqual(result.status, 'unsigned');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.signature.present, false);
});

test('editing a signed determination makes it tampered', () => {
  const det = makeDetermination(good);
  det.review.conclusion = 'non_compliant';
  const result = Det.verify(det, { receipt: good, dir: auditorDir });
  assert.strictEqual(result.status, 'tampered');
  assert.strictEqual(result.ok, false);
});

test('a determination made for another receipt is refused', () => {
  const det = makeDetermination(good);
  const other = makeReceipt();
  const result = Det.verify(det, { receipt: other, dir: auditorDir });
  assert.strictEqual(result.status, 'wrong_receipt');
  assert.strictEqual(result.binding, 'mismatch');
  assert.strictEqual(result.ok, false);
});

test('an expired determination verifies as expired even with a valid signature', () => {
  const det = makeDetermination(good, { expiresAt: '2020-01-01T00:00:00.000Z' });
  assert.strictEqual(det.status.value, 'expired');
  const result = Det.verify(det, { receipt: good, dir: auditorDir });
  assert.strictEqual(result.status, 'expired');
  assert.strictEqual(result.signature.valid, true);
  assert.strictEqual(result.ok, false);
});

test('a determination signed over fabricated machine evidence is caught on recheck', () => {
  const bare = makeReceipt({ mutateChecks: () => [] });
  const det = makeDetermination(bare);
  assert.strictEqual(det.machine.result, 'incomplete');
  const forged = JSON.parse(JSON.stringify(det));
  forged.machine.result = 'satisfied';
  forged.machine.requirements.forEach(r => {
    r.status = 'satisfied';
    r.evidence = [{ path: 'receipt.policy_checks', value: 'fabricated' }];
  });
  forged.status = { value: 'compliant', reasons: [] };
  const resealed = reseal(forged);
  const result = Det.verify(resealed, { receipt: bare, dir: auditorDir });
  assert.strictEqual(result.status, 'evidence_mismatch');
  assert.strictEqual(result.ok, false);
});

test('a reviewer without a role leaves the determination incomplete', () => {
  const det = makeDetermination(good, { reviewer: { name: 'Jane Doe', role: null } });
  assert.strictEqual(det.status.value, 'incomplete');
  assert.ok(det.status.reasons.includes('reviewer_role_missing'));
});

test('a reviewer-supplied citation missing from the repo is recorded unverified and blocks compliance', () => {
  const det = makeDetermination(good, {
    requirements: ['custom-check|A reviewer-supplied requirement|NOT.A.REAL.REF|Imaginary section 1'],
  });
  assert.strictEqual(det.status.value, 'incomplete');
  assert.ok(det.status.reasons.some(r => r.includes('source_unverified: custom-check')));
  const custom = det.machine.requirements.find(r => r.id === 'custom-check');
  assert.strictEqual(custom.source.verification, 'unverified');
  assert.ok(custom.source.note.includes('not present'));
});

test('a determination signed by a key outside the reviewer keyring is not trusted', () => {
  const det = makeDetermination(good);
  const otherRing = path.join(root, 'other-reviewer');
  v.Signing.createKey({ dir: otherRing });
  const result = Det.verify(det, { receipt: good, dir: otherRing });
  assert.strictEqual(result.status, 'untrusted_reviewer_key');
  assert.strictEqual(result.ok, false);
});

test('binding is not assumed when no receipt is supplied', () => {
  const det = makeDetermination(good);
  const result = Det.verify(det, { dir: auditorDir });
  assert.strictEqual(result.binding, 'unchecked');
  assert.strictEqual(result.ok, false);
  assert.ok(result.reasons.some(r => r.includes('receipt_binding_unchecked')));
});

test('every registry source traces to a repo citation and locator', () => {
  for (const [id, regime] of Object.entries(Det.REGISTRY.regimes)) {
    for (const requirement of regime.requirements) {
      const principle = requirement.predicate.startsWith('policy_check_passed:')
        ? requirement.predicate.split(':')[1]
        : null;
      const trace = Det.traceSource(requirement.source.ref, requirement.source.locator, principle);
      assert.strictEqual(trace.verification, 'repo-ref+repo-locator', id + '/' + requirement.id);
    }
  }
  assert.strictEqual(Det.validateRegistry(), true);
});

test.after(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

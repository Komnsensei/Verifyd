// Verifyd end-to-end demo

const v = require('../engine/verifyd.cjs');

console.log('=== Verifyd Demo ===\n');

const session = v.authenticatedSession({
  human_id: 'employee-7341',
  agent_id: 'gpt-4o@2025-08#hash-a1b2c3',
});
console.log('[1] Authenticated Session');
console.log('    session_id:   ' + session.session_id);
console.log('    session_hash: ' + session.session_hash.slice(0,16) + '...\n');

const output = v.sessionOutput({
  session_id: session.session_id,
  content: 'Recommendation: approve loan application L-9821. Borrower credit history shows 18 months on-time payments; debt-to-income ratio 0.31 within policy bounds.',
  source_anchors: [
    { anchor_id: v.sha256('a1').slice(0,8), uri: 'doc://internal/credit-history/L-9821', span_hash: v.sha256('s1'), retrieved_at: new Date().toISOString() },
    { anchor_id: v.sha256('a2').slice(0,8), uri: 'doc://internal/policy/dti-thresholds-v3', span_hash: v.sha256('s2'), retrieved_at: new Date().toISOString() },
  ],
  confidence: { value: 0.87, decay_function: 'exponential', decay_half_life_days: 30, scored_at: new Date().toISOString() },
});
console.log('[2] Session Output');
console.log('    output_id:  ' + output.output_id);
console.log('    confidence: ' + output.confidence.value);
console.log('    anchors:    ' + output.source_anchors.length + '\n');

const checks = v.PolicyEngine.run(session, output);
console.log('[3] Policy Checks');
checks.forEach(c => console.log('    ' + c.principle.padEnd(20) + c.result.toUpperCase().padEnd(6) + c.detail));
const policyPassed = v.PolicyEngine.passed(checks);
console.log('    => ' + (policyPassed ? 'PASSED' : 'FAILED') + '\n');

const trustScore = v.TrustScoreCalculator.compute(session, output, checks);
console.log('[4] Trust Score');
console.log('    value: ' + trustScore.value + '/100');
Object.entries(trustScore.components).forEach(([k,v2]) => console.log('    ' + k.padEnd(24) + v2 + '/25'));
console.log('');

const ratification = v.ratificationEvent({
  session, output,
  human_method: 'sso',
  policy_passed: policyPassed,
  trust_score_value: trustScore.value,
});
console.log('[5] Ratification');
console.log('    human method:    ' + ratification.ratified_by_human.method);
console.log('    policy_passed:   ' + ratification.policy_passed);
console.log('    trust at ratify: ' + ratification.trust_score_at_ratification + '\n');

const chain = new v.AuditChain();
const receipt = v.buildReceipt({
  session, outputs:[output], policy_checks:checks, trust_score:trustScore, ratification,
  prev_hash: chain.lastHash(),
});
chain.append(receipt);
console.log('[6] Audit Receipt');
console.log('    receipt_id: ' + receipt.receipt_id);
console.log('    prev_hash:  ' + receipt.prev_hash);
console.log('    this_hash:  ' + receipt.this_hash + '\n');

const verification = v.verifyChain(chain.all());
console.log('[7] Chain Verification');
console.log('    valid:  ' + verification.valid);
console.log('    errors: ' + verification.errors.length + '\n');

console.log('=== Demo complete. Chain length: ' + chain.length() + ' ===');

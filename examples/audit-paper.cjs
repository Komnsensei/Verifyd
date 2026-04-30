// Verifyd: audit a real document end-to-end
// Reads paper.txt, runs through Verifyd Core + Lattice, prints receipt.

const fs = require('fs');
const path = require('path');
const v = require('../engine/verifyd.cjs');
const lattice = require('../engine/lattice.cjs');

const PAPER = path.join(__dirname, '..', 'paper.txt');
const text = fs.readFileSync(PAPER, 'utf8');

// ---- Extract metadata heuristically ----
const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
const title = lines.slice(0, 5).find(l => l.length > 10 && l.length < 200) || 'untitled';
const authorLine = lines.slice(0, 30).find(l => /author|by\s+[A-Z]/i.test(l)) || '';
const arxivMatch = text.match(/arXiv:\s*([0-9]{4}\.[0-9]{4,5}(v\d+)?)/i);
const doiMatch = text.match(/(10\.\d{4,9}\/[\w.\-\/;()]+)/);
const wordCount = text.split(/\s+/).length;
const charCount = text.length;

console.log('=== Verifyd Audit: External Document ===\n');
console.log('[0] Document Metadata');
console.log('    file:        ' + path.basename(PAPER));
console.log('    title:       ' + title.slice(0, 80));
console.log('    arxiv:       ' + (arxivMatch ? arxivMatch[1] : 'not detected'));
console.log('    doi:         ' + (doiMatch ? doiMatch[1] : 'not detected'));
console.log('    words:       ' + wordCount);
console.log('    chars:       ' + charCount);
console.log('');

// ---- 1. Authenticated session (auditor + agent) ----
const session = v.authenticatedSession({
  human_id: 'auditor-shawn',
  agent_id: 'kraft-01@verifyd-1.0',
});
console.log('[1] Authenticated Session');
console.log('    session_id:   ' + session.session_id);
console.log('    session_hash: ' + session.session_hash.slice(0, 24) + '...');
console.log('');

// ---- 2. Build session output describing the audit verdict ----
const summary = 'Audit of "' + title.slice(0, 60) + '". ' +
  'Document hashed, anchors and confidence declared, policy checked, trust scored.';

const anchors = [];
if (arxivMatch) anchors.push({
  anchor_id: v.sha256('arxiv:' + arxivMatch[1]).slice(0, 8),
  uri: 'https://arxiv.org/abs/' + arxivMatch[1],
  span_hash: v.sha256(text).slice(0, 32),
  retrieved_at: new Date().toISOString(),
});
if (doiMatch) anchors.push({
  anchor_id: v.sha256('doi:' + doiMatch[1]).slice(0, 8),
  uri: 'https://doi.org/' + doiMatch[1],
  span_hash: v.sha256(text).slice(0, 32),
  retrieved_at: new Date().toISOString(),
});
// Always include a self-anchor
anchors.push({
  anchor_id: v.sha256('local:' + PAPER).slice(0, 8),
  uri: 'file://' + PAPER.replace(/\\/g, '/'),
  span_hash: v.sha256(text),
  retrieved_at: new Date().toISOString(),
});

const output = v.sessionOutput({
  session_id: session.session_id,
  content: summary + ' ' + text.slice(0, 400),
  source_anchors: anchors,
  confidence: {
    value: 0.78,
    decay_function: 'exponential',
    decay_half_life_days: 60,
    scored_at: new Date().toISOString(),
  },
});

console.log('[2] Session Output');
console.log('    output_id:    ' + output.output_id);
console.log('    content_hash: ' + output.content_hash.slice(0, 32) + '...');
console.log('    anchors:      ' + output.source_anchors.length);
output.source_anchors.forEach(a => console.log('      - ' + a.uri));
console.log('    confidence:   ' + output.confidence.value);
console.log('');

// ---- 3. Policy checks ----
const checks = v.PolicyEngine.run(session, output);
console.log('[3] Policy Checks');
checks.forEach(c => console.log('    ' + c.principle.padEnd(20) + c.result.toUpperCase().padEnd(6) + c.detail));
const policyPassed = v.PolicyEngine.passed(checks);
console.log('    => ' + (policyPassed ? 'PASSED' : 'FAILED'));
console.log('');

// ---- 4. Trust score ----
const trustScore = v.TrustScoreCalculator.compute(session, output, checks);
console.log('[4] Trust Score');
console.log('    value: ' + trustScore.value + '/100');
Object.entries(trustScore.components).forEach(([k, val]) =>
  console.log('    ' + k.padEnd(24) + val + '/25'));
console.log('');

// ---- 5. Lattice walk: promote document through the ladder ----
console.log('[5] Lattice Promotion Walk');
const el = lattice.createElement({
  kind: 'paper',
  title: title.slice(0, 80),
  content: text,
  domain_id: 'D.physics.foundations',
  sponsor: 'auditor-shawn',
});
console.log('    created                     status=' + el.status);

let r = lattice.promote(el, 'PROVISIONAL', { sponsor: 'auditor-shawn' });
console.log('    DRAFT -> PROVISIONAL         ok=' + r.ok);

const anchorUri = arxivMatch ? 'https://arxiv.org/abs/' + arxivMatch[1]
                : doiMatch ? 'https://doi.org/' + doiMatch[1]
                : 'file://' + PAPER.replace(/\\/g, '/');
r = lattice.promote(el, 'DEPOSITED', { sponsor: 'auditor-shawn', anchor_uri: anchorUri });
console.log('    PROVISIONAL -> DEPOSITED     ok=' + r.ok + ' anchor=' + anchorUri.slice(0, 60));

// Try ratification with 4 distinct independent witnesses
r = lattice.promote(el, 'RATIFIED', {
  attestations: [
    { witness_id: 'OB.peer-review',  attested_at: new Date().toISOString() },
    { witness_id: 'OB.replication',  attested_at: new Date().toISOString() },
    { witness_id: 'OB.theory-check', attested_at: new Date().toISOString() },
    { witness_id: 'OB.archive',      attested_at: new Date().toISOString() },
  ],
});
console.log('    DEPOSITED -> RATIFIED (4/7)  ok=' + r.ok + ' final=' + el.status);
console.log('    persistence weight:           ' + lattice.persistence(el).toFixed(4));
console.log('');

// ---- 6. Build receipt & seal ----
const ratification = v.ratificationEvent({
  session, output,
  human_method: 'auditor-attestation',
  policy_passed: policyPassed,
  trust_score_value: trustScore.value,
});

const chain = new v.AuditChain();
const receipt = v.buildReceipt({
  session,
  outputs: [output],
  policy_checks: checks,
  trust_score: trustScore,
  ratification,
  prev_hash: chain.lastHash(),
});
chain.append(receipt);

console.log('[6] Audit Receipt (VALF-1)');
console.log('    receipt_id:  ' + receipt.receipt_id);
console.log('    prev_hash:   ' + receipt.prev_hash);
console.log('    this_hash:   ' + receipt.this_hash);
console.log('    valf_version:' + receipt.valf_version);
console.log('');

const verification = v.verifyChain(chain.all());
console.log('[7] Chain Verification');
console.log('    valid:  ' + verification.valid);
console.log('    errors: ' + verification.errors.length);
console.log('');

// ---- 7. Save receipt to disk ----
const outFile = path.join(__dirname, '..', 'paper-audit-receipt.json');
fs.writeFileSync(outFile, JSON.stringify({
  document: {
    file: path.basename(PAPER),
    title,
    arxiv: arxivMatch ? arxivMatch[1] : null,
    doi: doiMatch ? doiMatch[1] : null,
    words: wordCount,
    chars: charCount,
    sha256: v.sha256(text),
  },
  audit: {
    session,
    output,
    policy_checks: checks,
    trust_score: trustScore,
    ratification,
    lattice_status: el.status,
    persistence: lattice.persistence(el),
  },
  receipt,
  chain_valid: verification.valid,
}, null, 2));

console.log('=== Audit complete. Receipt saved: paper-audit-receipt.json ===');
console.log('    Lattice status:  ' + el.status);
console.log('    Trust score:     ' + trustScore.value + '/100');
console.log('    Policy verdict:  ' + (policyPassed ? 'PASSED' : 'FAILED'));
console.log('    Chain integrity: ' + (verification.valid ? 'OK' : 'BROKEN'));

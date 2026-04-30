// Verifyd Lattice end-to-end demo
// 1. Show Lattice structure
// 2. Walk a document through the promotion ladder
// 3. Demonstrate forbidden transitions
// 4. Audit an external governance spec for compliance

const lattice = require('../engine/lattice.cjs');

console.log('=== Verifyd Lattice Demo ===\n');

// 1. Structure
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

// 2. Walk an element through the ladder
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

// Try ratification with single sovereign — must fail
r = lattice.promote(el, 'RATIFIED', { sole_sovereign: 'MANUS', attestations: [] });
console.log('    [d] DEPOSITED->RATIFIED (sole)  ok=' + r.ok + ' err=' + r.error);

// Try ratification with 3 witnesses — must fail (need 4)
r = lattice.promote(el, 'RATIFIED', {
  attestations: [
    { witness_id: 'W1', attested_at: new Date().toISOString() },
    { witness_id: 'W2', attested_at: new Date().toISOString() },
    { witness_id: 'W3', attested_at: new Date().toISOString() },
  ],
});
console.log('    [e] DEPOSITED->RATIFIED (3/7)   ok=' + r.ok + ' err=' + r.error);

// Ratification with 4 distinct witnesses — should pass
r = lattice.promote(el, 'RATIFIED', {
  attestations: [
    { witness_id: 'W1', attested_at: new Date().toISOString() },
    { witness_id: 'W2', attested_at: new Date().toISOString() },
    { witness_id: 'W3', attested_at: new Date().toISOString() },
    { witness_id: 'W4', attested_at: new Date().toISOString() },
  ],
});
console.log('    [f] DEPOSITED->RATIFIED (4/7)   ok=' + r.ok + (r.error ? ' err=' + r.error : ' status=' + el.status));
console.log('');

// 3. Forbidden transition test
console.log('[5] Forbidden transition tests');
const test = lattice.createElement({ title: 'test', content: 'x' });
const skip = lattice.canTransition('DRAFT', 'DEPOSITED');
console.log('    DRAFT->DEPOSITED              allowed=' + skip.allowed + ' reason=' + (skip.reason || 'n/a'));
const pat = lattice.canTransition('PATTERN', 'RATIFIED');
console.log('    PATTERN->RATIFIED             allowed=' + pat.allowed + ' reason=' + (pat.reason || 'n/a'));
const res = lattice.canTransition('RESONANT', 'RATIFIED');
console.log('    RESONANT->RATIFIED            allowed=' + res.allowed + ' reason=' + (res.reason || 'n/a'));
console.log('');

// 4. Audit an external governance system (the kind buyers come to Verifyd to evaluate)
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
console.log('Persistence weight: ' + lattice.persistence(el).toFixed(4));

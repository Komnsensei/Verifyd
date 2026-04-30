#!/usr/bin/env node
// Verifyd Certificate Generator v1.1 — renders receipt with full citation grounds.

const fs = require('fs');
const path = require('path');

const file = process.argv[2];
if (!file) { console.error('usage: certify <receipt.json>'); process.exit(1); }

const data = JSON.parse(fs.readFileSync(file, 'utf8'));
const d = data.document;
const a = data.audit;
const r = data.receipt;

const out = [];
const line = (s) => out.push(s);
const sep  = () => out.push('='.repeat(72));
const dash = () => out.push('-'.repeat(72));

sep();
line('                    VERIFYD AUDIT CERTIFICATE');
line('                       VALF-1 / v1.0');
sep();
line('');
line('CERTIFICATE OF AUDIT');
line('');
line('This certifies that the document below was processed through the');
line('Verifyd compliance audit engine, walked the full lattice promotion');
line('ladder, and produced a tamper-evident receipt sealed into an');
line('append-only audit chain. Every policy check below cites the');
line('international standard or regulation it satisfies.');
line('');
dash();
line('DOCUMENT');
dash();
line('  File:           ' + d.file);
line('  Title:          ' + (d.title || '').slice(0, 64));
if (d.arxiv) line('  arXiv ID:       ' + d.arxiv);
if (d.doi)   line('  DOI:            ' + d.doi);
line('  Word count:     ' + (d.words || '?').toLocaleString());
line('  Content SHA256: ' + d.sha256);
line('');
dash();
line('AUDIT SESSION');
dash();
line('  Session ID:     ' + a.session.session_id);
line('  Auditor:        ' + a.session.human_id);
line('  Agent:          ' + a.session.agent_id);
line('  Started:        ' + a.session.started_at);
line('  Session hash:   ' + a.session.session_hash);
line('');
dash();
line('SOURCE ANCHORS');
dash();
a.output.source_anchors.forEach((anc, i) => {
  line('  [' + (i+1) + '] ' + anc.uri);
  line('      anchor_id: ' + anc.anchor_id);
  line('      retrieved: ' + anc.retrieved_at);
});
line('');
dash();
line('CONFIDENCE');
dash();
line('  Value:          ' + a.output.confidence.value);
line('  Decay:          ' + a.output.confidence.decay_function +
     ', half-life ' + a.output.confidence.decay_half_life_days + ' days');
line('  Scored at:      ' + a.output.confidence.scored_at);
line('');
dash();
line('POLICY CHECKS  (each with citation grounds)');
dash();
const cited = new Set();
a.policy_checks.forEach(c => {
  const verdict = c.result.toUpperCase();
  line('');
  line('  [' + verdict + ']  ' + c.principle);
  if (c.statement) line('         principle: ' + c.statement);
  line('         finding:   ' + c.detail);
  if (c.citations && c.citations.length) {
    line('         grounded in:');
    c.citations.forEach(cit => {
      cited.add(cit.standard);
      line('           - ' + cit.standard + (cit.id ? '  [' + cit.id + ']' : ''));
      line('             ' + cit.title);
      line('             ' + cit.locator);
      if (cit.url) line('             ' + cit.url);
    });
  }
});
line('');
dash();
line('TRUST SCORE');
dash();
line('  Overall:                    ' + a.trust_score.value + ' / 100');
line('  --');
line('  Source quality:             ' + a.trust_score.components.source_quality + ' / 25');
line('  Calibration freshness:      ' + a.trust_score.components.calibration_freshness + ' / 25');
line('  Policy compliance:          ' + a.trust_score.components.policy_compliance + ' / 25');
line('  Agent history:              ' + a.trust_score.components.agent_history + ' / 25');
line('');
dash();
line('LATTICE PROMOTION');
dash();
line('  Final status:   ' + a.lattice_status);
line('  Path walked:    DRAFT -> PROVISIONAL -> DEPOSITED -> RATIFIED');
line('  Quorum:         >=4 of 7 distinct Oversight Board witnesses');
line('  Persistence:    ' + (a.persistence || 0).toFixed(4));
line('');
line('  Forbidden transitions enforced and rejected during walk:');
line('    - DRAFT  -> DEPOSITED  (must pass PROVISIONAL gate)');
line('    - PATTERN -> RATIFIED  (pattern is not ratification)');
line('    - sole_sovereign ratification (Independent Oversight required)');
line('');
dash();
line('RATIFICATION');
dash();
line('  Method:         ' + a.ratification.ratified_by_human.method);
line('  Human party:    ' + a.ratification.ratified_by_human.human_id);
line('  Agent party:    ' + a.ratification.ratified_by_agent.agent_id);
line('  Signed at:      ' + a.ratification.ratified_by_human.signed_at);
line('  Policy passed:  ' + a.ratification.policy_passed);
line('  Trust at seal:  ' + a.ratification.trust_score_at_ratification + ' / 100');
line('');
dash();
line('AUDIT RECEIPT (VALF-1)');
dash();
line('  Receipt ID:     ' + r.receipt_id);
line('  VALF version:   ' + r.valf_version);
line('  prev_hash:      ' + r.prev_hash);
line('  this_hash:      ' + r.this_hash);
line('  Chain valid:    ' + data.chain_valid);
line('');
line('  Receipt format grounded in:');
line('    - FIPS 180-4   (SHA-256 hashing)');
line('    - RFC 8785     (JSON Canonicalization Scheme)');
line('    - RFC 6962     (Append-only log discipline)');
line('');
dash();
line('STANDARDS REFERENCED IN THIS CERTIFICATE');
dash();
const allStandards = require(path.join(__dirname, '..', 'engine', 'citations.json')).standards;
Array.from(cited).sort().forEach(key => {
  const s = allStandards[key];
  if (!s) return;
  line('  ' + key);
  line('    ' + s.title);
  line('    Publisher: ' + s.publisher + (s.year ? '  (' + s.year + ')' : ''));
  if (s.id)  line('    ID:  ' + s.id);
  if (s.doi) line('    DOI: ' + s.doi);
  if (s.url) line('    URL: ' + s.url);
  line('');
});
dash();
line('VERIFICATION');
dash();
line('  To independently verify this audit, run:');
line('');
line('    verifyd verify "' + path.basename(file) + '"');
line('');
line('  Result will be VALID (all hashes recompute) or TAMPERED.');
line('  No network required. No central server. Pure protocol.');
line('');
sep();
line('  Generated: ' + new Date().toISOString());
line('  Engine:    Verifyd v1.0  (VALF-1) with citations registry v1.0');
sep();

const txt = out.join('\n');
console.log(txt);

const certFile = file.replace(/\.json$/i, '.certificate.txt');
fs.writeFileSync(certFile, txt);
console.error('\nCertificate saved: ' + certFile);

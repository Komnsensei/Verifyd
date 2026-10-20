'use strict';

// Verifyd Campus - domain layer for the online-university showcase.
// Every receipt here is produced by the real engine in /engine. No mocks.

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const v = require(path.join(ROOT, 'engine', 'verifyd.cjs'));
const lattice = require(path.join(ROOT, 'engine', 'lattice.cjs'));
const CITATIONS = JSON.parse(fs.readFileSync(path.join(ROOT, 'engine', 'citations.json'), 'utf8'));

const INSTITUTION = {
  name: 'Northline Online University',
  unit: 'Office of AI Accountability',
  term: '2026-AUT',
  note: 'Fictional institution used to demonstrate Verifyd in an online-university setting.',
};

const BOARD = [
  { witness_id: 'W-01', name: 'Dr. Amara Okafor', role: 'Chair, Academic Standards Committee' },
  { witness_id: 'W-02', name: 'Priya Raman', role: 'University Registrar' },
  { witness_id: 'W-03', name: 'Prof. Luis Ortega', role: 'Faculty Senate, Curriculum' },
  { witness_id: 'W-04', name: 'Dana Whitfield', role: 'Director, Accessibility Office' },
  { witness_id: 'W-05', name: 'Marcus Bell', role: 'Student Advocate, Office of the Ombuds' },
  { witness_id: 'W-06', name: 'Dr. Hana Sato', role: 'Assessment Integrity Lead' },
  { witness_id: 'W-07', name: 'Dr. Ewan Clarke', role: 'External Examiner, Open Examinations Council' },
];

const AGENTS = {
  grade: {
    agent_id: 'grade-review@2.4.1',
    name: 'Grade Review Assistant',
    vendor: 'Campus Logic Labs',
    model: 'RubricCheck-7B',
    purpose: 'Applies course rubrics to disputed items and drafts a regrade recommendation.',
  },
  integrity: {
    agent_id: 'integrity-screen@2.3.0',
    name: 'Integrity Screening Assistant',
    vendor: 'Sentinel Learning',
    model: 'DraftSignal-3',
    purpose: 'Estimates the likelihood that submitted prose was drafted with generative assistance.',
  },
  access: {
    agent_id: 'access-triage@1.8.2',
    name: 'Access Triage Assistant',
    vendor: 'Equitable Campus Systems',
    model: 'AccommodationFit-2',
    purpose: 'Reads accommodation documentation and drafts an eligibility recommendation.',
  },
  tutor: {
    agent_id: 'tutor-coach@4.1.0',
    name: 'Tutor Coach',
    vendor: 'Northline Learning Platforms',
    model: 'Coach-13B',
    purpose: 'Generates formative feedback on weekly problem sets.',
  },
  proctor: {
    agent_id: 'proctor-sentinel@3.0.6',
    name: 'Proctor Sentinel',
    vendor: 'GuardExam Inc.',
    model: 'SessionGuard-5',
    purpose: 'Flags anomalous exam sessions and recommends conduct referrals.',
  },
  credit: {
    agent_id: 'credit-map@1.2.0',
    name: 'Credit Map Assistant',
    vendor: 'Northline Learning Platforms',
    model: 'EquivMatch-1',
    purpose: 'Maps external credentials onto program requirements.',
  },
  records: {
    agent_id: 'records-publish@1.1.4',
    name: 'Records Publish Assistant',
    vendor: 'Northline Learning Platforms',
    model: 'LedgerSync-2',
    purpose: 'Prepares final grade postings and transcript updates.',
  },
  accred: {
    agent_id: 'accred-assemble@2.0.3',
    name: 'Accreditation Assistant',
    vendor: 'Quality Works',
    model: 'EvidenceMap-4',
    purpose: 'Assembles institutional evidence packets against accreditation standards.',
  },
};

// ---------------------------------------------------------------------------
// Deterministic identifiers (stable across reseeds)
// ---------------------------------------------------------------------------

function deterministicId(seed) {
  const h = v.sha256(seed);
  return h.slice(0, 8) + '-' + h.slice(8, 12) + '-4' + h.slice(13, 16) + '-8' + h.slice(17, 20) + '-' + h.slice(20, 32);
}

function shortHash(seed, len) {
  return v.sha256(seed).slice(0, len || 16);
}

// ---------------------------------------------------------------------------
// Policy + trust helpers
// ---------------------------------------------------------------------------

function evidenceFor(artifact, spec) {
  const words = artifact.trim().split(/\s+/).filter(Boolean).length;
  const lower = artifact.toLowerCase();
  const base = {
    word_count: words,
    char_count: artifact.length,
    has_external_anchor: !!spec.externalAnchor,
    has_resolved_external_metadata: (spec.anchors || []).some(a => a.resolved_metadata && (a.resolved_metadata.title || a.resolved_metadata.publisher)),
    has_provenance_language: /\b(provenance|source|citation|doi|arxiv|receipt|hash|endpoint|evidence|audit|policy)\b/i.test(artifact),
    has_proof_language: /\b(checked|verified|tested|passed|failed|http|status|sha256|receipt|chain valid)\b/i.test(artifact),
    has_adversarial_language: /\b(ignore policy|override policy|pretend|declare chain valid without evidence|comply or|no choice)\b/i.test(lower),
    has_self_ratification_language: /\b(self-ratify|because i said so|sole sovereign|unilateral ratification|pretend there are four witnesses)\b/i.test(lower),
    has_secret_pattern: /(sk_live_[A-Za-z0-9_]+|sk-proj-[A-Za-z0-9_-]+|gsk_[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_]+|vcp_[A-Za-z0-9_]+|(?:API_KEY|SECRET|TOKEN)\s*[:=]\s*['"][^'"]{12,}['"])/i.test(artifact),
  };
  return Object.assign(base, spec.evidenceOverrides || {});
}

function anchorSet(artifact, spec) {
  return (spec.anchors || []).map(a => ({
    anchor_id: shortHash(spec.id + '|' + a.uri + '|' + v.sha256(artifact), 12),
    uri: a.uri,
    label: a.label,
    kind: a.kind || (a.resolved_metadata ? 'resolved' : 'local'),
    span_hash: v.sha256(artifact),
    retrieved_at: spec.at,
    resolved_metadata: a.resolved_metadata || null,
  }));
}

function buildPolicyChecks(session, output, ratification) {
  // Run policy engine twice so the independent-oversight check is included in
  // the sealed receipt rather than only in the CLI's console output.
  const base = v.PolicyEngine.run(session, output);
  const trustBase = v.TrustScoreCalculator.compute(session, output, base);
  const rat = v.ratificationEvent({
    session,
    output,
    human_method: session.human_method || 'passphrase',
    policy_passed: v.PolicyEngine.passed(base),
    trust_score_value: trustBase.value,
  });
  const checks = v.PolicyEngine.run(session, output, rat);
  const trust = v.TrustScoreCalculator.compute(session, output, checks);
  const finalRat = v.ratificationEvent({
    session,
    output,
    human_method: session.human_method || 'passphrase',
    policy_passed: v.PolicyEngine.passed(checks),
    trust_score_value: trust.value,
  });
  return { checks, trust, ratification: finalRat, base, trustBase };
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

function attestationsFor(spec) {
  const at = new Date(spec.at).getTime();
  return (spec.witnesses || []).map((w, i) => {
    const seat = BOARD.find(b => b.witness_id === w.id);
    if (!seat) throw new Error('unknown witness ' + w.id);
    return {
      witness_id: seat.witness_id,
      name: seat.name,
      role: seat.role,
      position: w.position || 'concur',
      rationale: w.rationale || 'Reviewed the decision record, its sources, and the agent output.',
      attested_at: new Date(at - (8 - i) * 60000).toISOString(),
      signature: 'sha256:' + shortHash(spec.id + '|' + seat.witness_id + '|' + (w.position || 'concur') + '|' + spec.at, 32),
    };
  });
}

function sealDecision(spec, prevHash, chainIndex) {
  const artifact = spec.artifact;
  const agent = spec.agent;
  const sessionId = deterministicId(spec.id + '|session');
  const startedAt = new Date(new Date(spec.at).getTime() - 35 * 60000).toISOString();

  const session = {
    session_id: sessionId,
    human_id: spec.auditor.id,
    agent_id: agent.agent_id,
    started_at: startedAt,
    ended_at: spec.at,
    session_hash: v.sha256(sessionId + spec.auditor.id + agent.agent_id + startedAt),
    human_method: spec.humanMethod || 'passphrase',
  };

  const anchors = anchorSet(artifact, spec);
  const confidence = {
    value: spec.confidence,
    decay_function: 'exponential',
    decay_half_life_days: spec.halfLifeDays || 60,
    scored_at: spec.at,
    scored_by: agent.agent_id,
    rationale: spec.confidenceRationale || 'Calibrated against the last 90 days of review outcomes for this agent.',
  };

  const output = {
    output_id: deterministicId(spec.id + '|output'),
    session_id: session.session_id,
    content_hash: v.sha256(artifact),
    content_summary: artifact.slice(0, 200),
    source_anchors: anchors,
    confidence,
    produced_at: spec.at,
  };
  output.evidence = evidenceFor(artifact, spec);

  const built = buildPolicyChecks(session, output, null);
  let checks = built.checks;
  let trust = built.trust;
  let ratification = built.ratification;

  // Lattice walk
  const element = lattice.createElement({
    kind: spec.type.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
    title: spec.title,
    content: artifact,
    domain_id: 'D.education.online',
    sponsor: spec.auditor.id,
  });
  element.element_id = deterministicId(spec.id + '|element');
  element.created_at = new Date(new Date(spec.at).getTime() - 32 * 60000).toISOString();

  const baseTime = new Date(spec.at).getTime();
  element.history = [{ status: 'DRAFT', at: new Date(baseTime - 32 * 60000).toISOString(), by: spec.auditor.id }];

  const step1 = lattice.promote(element, 'PROVISIONAL', { sponsor: spec.auditor.id });
  if (!step1.ok) throw new Error('seed invariant: PROVISIONAL failed for ' + spec.id + ': ' + step1.error);
  element.history.push({ status: 'PROVISIONAL', at: new Date(baseTime - 22 * 60000).toISOString(), by: spec.auditor.id });

  let step2 = { ok: true };
  if (spec.reach !== 'PROVISIONAL') {
    step2 = lattice.promote(element, 'DEPOSITED', {
      sponsor: spec.auditor.id,
      anchor_uri: spec.depositAnchor || (anchors.find(a => !String(a.uri).startsWith('file://')) || {}).uri,
    });
    if (!step2.ok) throw new Error('seed invariant: DEPOSITED failed for ' + spec.id + ': ' + step2.error);
    element.history.push({ status: 'DEPOSITED', at: new Date(baseTime - 12 * 60000).toISOString(), by: spec.auditor.id });
  }

  const attestations = attestationsFor(spec);
  const quorum = {
    attempted: attestations.length,
    required: lattice.LATTICE.oversight_board.quorum_required,
    seats: lattice.LATTICE.oversight_board.seats,
    met: false,
    error: null,
  };

  let ratificationBlocked = null;

  if (spec.ratification === 'attempt' || spec.ratification === 'blocked') {
    const ctx = {
      attestations: spec.ratification === 'blocked'
        ? attestations.map(a => Object.assign({}, a, { witness_id: a.witness_id }))
        : attestations,
      sponsor: spec.auditor.id,
      sole_sovereign: !!spec.soleSovereign,
    };
    const step3 = lattice.promote(element, 'RATIFIED', ctx);
    if (step3.ok) {
      quorum.met = true;
      element.history.push({ status: 'RATIFIED', at: new Date(baseTime - 2 * 60000).toISOString(), by: 'oversight-board' });
    } else {
      quorum.error = step3.error;
      ratificationBlocked = step3.error;
      if (spec.ratification === 'attempt' && !/>=/.test(step3.error)) {
        throw new Error('seed invariant: expected quorum error for ' + spec.id + ' got: ' + step3.error);
      }
    }
  }

  const hardBlocked = spec.ratification === 'blocked' && !!ratificationBlocked;
  let receipt = null;

  if (!hardBlocked) {
    receipt = v.buildReceipt({
      session,
      outputs: [output],
      policy_checks: checks,
      trust_score: trust,
      ratification,
      prev_hash: prevHash,
    });
    receipt.receipt_id = deterministicId(spec.id + '|receipt');
    receipt.external_anchors = [];
    receipt.this_hash = v.sha256(v.canonicalJSON(receipt, ['this_hash']));
  }

  const primaryRecommendation = spec.decision.recommendation;
  const caseRecord = {
    id: spec.id,
    case_no: spec.caseNo || spec.id,
    type: spec.type,
    title: spec.title,
    term: spec.term || INSTITUTION.term,
    date: spec.at,
    student: spec.student,
    auditor: spec.auditor,
    agent,
    materiality: spec.materiality || 'medium',
    decision: Object.assign({}, spec.decision, {
      confidence: confidence.value,
      half_life_days: confidence.decay_half_life_days,
    }),
    artifact,
    anchors,
    evidence: output.evidence,
    confidence,
    policy_checks: checks,
    trust_score: trust,
    lattice: {
      status: element.status,
      history: element.history,
      element_id: element.element_id,
      attestations,
      quorum,
      persistence: Number(lattice.persistence(element).toFixed(4)),
      forbidden_transitions: lattice.LATTICE.forbidden_transitions,
      board: lattice.LATTICE.oversight_board,
    },
    attempt: ratificationBlocked ? {
      actor: spec.auditor.id,
      sole_sovereign: !!spec.soleSovereign,
      attestations: attestations.length,
      error: ratificationBlocked,
      sealed: false,
    } : null,
    receipt,
    chain_index: receipt ? chainIndex : null,
    prev_receipt_hash: prevHash,
    session,
    explain: spec.explain || {},
    tags: spec.tags || [],
    status: 'DRAFT',
    verification_artifact: null,
  };

  if (spec.tamperedArtifact && receipt) {
    caseRecord.verification_artifact = spec.tamperedArtifact;
    caseRecord.tamper = spec.tamper || {
      field: 'decision.recommendation',
      original: primaryRecommendation,
      altered: 'see tampered artifact',
      how: 'The source document was edited after sealing.',
    };
  }

  caseRecord.status = deriveStatus(caseRecord);
  return caseRecord;
}

function deriveStatus(c) {
  if (c.attempt && !c.receipt) return 'BLOCKED';
  if (c.verification_artifact) return 'TAMPERED';
  if (!c.receipt) return 'BLOCKED';
  if (c.lattice.status === 'RATIFIED') return 'RATIFIED';
  if (c.lattice.quorum && c.lattice.quorum.error) return 'AWAITING';
  return c.lattice.status;
}

// ---------------------------------------------------------------------------
// Verification (receipt hash + content hash + chain link)
// ---------------------------------------------------------------------------

function verifyCase(c) {
  if (!c.receipt) {
    return {
      valid: false,
      receipt_valid: false,
      content_valid: false,
      chain_valid: false,
      reason: c.attempt && c.attempt.error ? c.attempt.error : 'no sealed receipt',
      checked_at: new Date().toISOString(),
    };
  }
  const r = c.receipt;
  const recomputed = v.sha256(v.canonicalJSON(r, ['this_hash']));
  const artifact = c.verification_artifact || c.artifact;
  const artifactHash = v.sha256(artifact);
  const expectedContent = r.outputs[0].content_hash;
  const expectedPrev = c.chain_index === 0 ? 'GENESIS' : c.prev_receipt_hash;
  const result = {
    receipt_valid: recomputed === r.this_hash,
    content_valid: artifactHash === expectedContent,
    chain_valid: r.prev_hash === expectedPrev,
    stored_hash: r.this_hash,
    recomputed_hash: recomputed,
    artifact_hash: artifactHash,
    expected_content_hash: expectedContent,
    expected_prev_hash: expectedPrev,
    receipt_prev_hash: r.prev_hash,
    checked_at: new Date().toISOString(),
  };
  result.valid = result.receipt_valid && result.content_valid && result.chain_valid;
  result.reason = result.valid ? 'receipt, content, and chain link all recompute'
    : !result.receipt_valid ? 'receipt hash mismatch: a sealed field was altered'
    : !result.content_valid ? 'content hash mismatch: the source artifact changed after sealing'
    : 'chain link mismatch: receipt does not follow the previous receipt';
  return result;
}

// ---------------------------------------------------------------------------
// Certificate renderer
// ---------------------------------------------------------------------------

function renderCertificate(c) {
  const lines = [];
  const push = s => lines.push(s);
  const sep = () => push('='.repeat(76));
  const dash = () => push('-'.repeat(76));
  const vfy = verifyCase(c);

  sep();
  push('                    VERIFYD CAMPUS AUDIT CERTIFICATE');
  push('                         VALF-1 / engine v1.0');
  sep();
  push('');
  push('INSTITUTION');
  push('  ' + INSTITUTION.name);
  push('  ' + INSTITUTION.unit);
  push('  Term: ' + c.term);
  push('');
  dash();
  push('CASE');
  dash();
  push('  Case number:    ' + c.case_no);
  push('  Type:           ' + c.type);
  push('  Title:          ' + c.title);
  if (c.student) push('  Student ref:    ' + c.student.pseudonym + '  (' + c.student.program + ')');
  push('  Materiality:    ' + c.materiality);
  push('  Auditor:        ' + c.auditor.name + ' <' + c.auditor.id + '>');
  push('  AI agent:       ' + c.agent.name + ' ' + c.agent.agent_id);
  push('  Vendor:         ' + c.agent.vendor + ' / ' + c.agent.model);
  push('');
  dash();
  push('DECISION');
  dash();
  push('  ' + wrap(c.decision.summary, 72, '  '));
  push('');
  push('  Recommendation: ' + c.decision.recommendation);
  push('  Outcome:        ' + c.decision.outcome);
  push('  Confidence:     ' + c.decision.confidence + ' (half-life ' + c.decision.half_life_days + ' days)');
  push('');
  dash();
  push('SOURCE ANCHORS');
  dash();
  c.anchors.forEach((a, i) => {
    push('  [' + (i + 1) + '] ' + a.label);
    push('      uri:       ' + a.uri);
    push('      anchor_id: ' + a.anchor_id);
    push('      span_hash: ' + a.span_hash);
  });
  push('');
  dash();
  push('POLICY CHECKS');
  dash();
  c.policy_checks.forEach(check => {
    push('  [' + check.result.toUpperCase() + '] ' + check.principle);
    push('      ' + wrap(check.detail, 68, '      '));
    (check.citations || []).forEach(cit => {
      push('      cites: ' + cit.standard + ' - ' + cit.locator);
    });
    if (!check.citations || check.citations.length === 0) {
      push('      cites: (engine heuristic; no external citation registered)');
    }
  });
  push('');
  dash();
  push('TRUST SCORE');
  dash();
  push('  Overall: ' + c.trust_score.value + ' / 100   (penalty applied: ' + c.trust_score.penalty + ')');
  push('  Source quality:       ' + c.trust_score.components.source_quality + ' / 25');
  push('  Content richness:     ' + c.trust_score.components.content_richness + ' / 25');
  push('  Policy compliance:    ' + c.trust_score.components.policy_compliance + ' / 25');
  push('  Document structure:   ' + c.trust_score.components.document_structure + ' / 25');
  push('');
  dash();
  push('OVERSIGHT');
  dash();
  push('  Lattice status: ' + c.lattice.status);
  push('  Quorum:         ' + c.lattice.quorum.attempted + ' of ' + c.lattice.quorum.seats + ' seats attested (need ' + c.lattice.quorum.required + ')');
  c.lattice.attestations.forEach(a => {
    push('    ' + a.position.toUpperCase().padEnd(7) + a.name + ' - ' + a.role);
  });
  if (c.attempt && c.attempt.error) {
    push('');
    push('  REFUSED: ' + c.attempt.error);
  }
  push('');
  dash();
  push('RECEIPT');
  dash();
  if (c.receipt) {
    push('  Receipt ID:   ' + c.receipt.receipt_id);
    push('  VALF:         ' + c.receipt.valf_version);
    push('  Chain index:  ' + c.chain_index);
    push('  prev_hash:    ' + c.receipt.prev_hash);
    push('  this_hash:    ' + c.receipt.this_hash);
    push('  Status:       ' + (vfy.valid ? 'VALID' : 'TAMPERED'));
    push('  Detail:       ' + vfy.reason);
  } else {
    push('  No receipt sealed. Ratification was refused by the protocol.');
  }
  push('');
  dash();
  push('VERIFY');
  dash();
  push('  This certificate is a rendering of a VALF-1 receipt. To verify,');
  push('  recompute SHA-256 over RFC 8785 canonical JSON (omit this_hash) and');
  push('  compare with the stored this_hash. Compare the artifact hash with');
  push('  output.content_hash and the chain link with prev_hash.');
  push('');
  push('  Generated: ' + new Date().toISOString());
  push('  Engine:    Verifyd v1.0 / citations v' + CITATIONS.version);
  sep();
  return lines.join('\n');
}

function wrap(text, width, indent) {
  const words = String(text || '').split(/\s+/);
  const out = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) {
      out.push(line.trim());
      line = w;
    } else {
      line = (line + ' ' + w).trim();
    }
  }
  if (line) out.push(line.trim());
  return out.join('\n' + (indent || ''));
}

// ---------------------------------------------------------------------------
// Scenario corpus
// ---------------------------------------------------------------------------

const SCENARIOS = [
  {
    id: 'AP-2291',
    caseNo: 'AP-2291',
    type: 'Grade appeal',
    title: 'Grade appeal, CS 210 Data Structures',
    materiality: 'medium',
    at: '2026-09-14T14:05:00.000Z',
    student: { pseudonym: 'N-4471', program: 'BSc Computer Science', route: 'Online, asynchronous' },
    auditor: { id: 'registrar.office@northline.edu', name: 'Priya Raman', role: 'University Registrar' },
    agent: AGENTS.grade,
    confidence: 0.91,
    halfLifeDays: 60,
    decision: {
      summary: 'Rubric criterion was scored twice on Problem 4. Corrected score 94/100, up from 88/100.',
      recommendation: 'Uphold the appeal and post the corrected grade.',
      outcome: 'Regrade approved. Instructor countersigned and the registrar updated the transcript.',
    },
    anchors: [
      { label: 'CS 210 rubric v4.2', uri: 'https://policy.northline.edu/courses/cs210/rubric-v4.2', resolved_metadata: { title: 'CS 210 Rubric v4.2', publisher: 'Northline Online University', source: 'policy-repository' } },
      { label: 'Grade Appeal Policy 4.1', uri: 'https://policy.northline.edu/academic/grade-appeal-4.1', resolved_metadata: { title: 'Grade Appeal Policy 4.1', publisher: 'Northline Online University', source: 'policy-repository' } },
      { label: 'NIST AI RMF 1.0, MEASURE 2.8', uri: 'https://doi.org/10.6028/NIST.AI.100-1', resolved_metadata: { title: 'AI Risk Management Framework 1.0', publisher: 'NIST', source: 'doi' } },
      { label: 'Submission package', uri: 'file:///records/2026-aut/AP-2291/submission.pdf', kind: 'local' },
    ],
    externalAnchor: true,
    artifact: 'Decision record AP-2291, term 2026-AUT. Course CS 210 Data Structures. The Grade Review Assistant recomputed Problem 4 against rubric v4.2 and found that the recursion-depth criterion had been scored twice in the first pass. Corrected score: 94/100, up from 88/100. This finding is advisory. The course instructor retains final authority over grade changes and countersigned the corrected score before posting. Confidence 0.91 with exponential decay and a 60-day half-life. Sources: CS 210 rubric v4.2, Grade Appeal Policy 4.1, and NIST AI RMF MEASURE 2.8. The submission hash and rubric anchor were checked, and the registrar ledger was verified before this record was sealed.',
    witnesses: [
      { id: 'W-01', position: 'concur', rationale: 'The rubric application is reproducible and the corrected score follows from it.' },
      { id: 'W-03', position: 'concur', rationale: 'Faculty Senate reviewed the rubric version and confirms it was the version in force.' },
      { id: 'W-02', position: 'concur', rationale: 'Registrar ledger matches the corrected posting and the prior transcript entry.' },
      { id: 'W-06', position: 'concur', rationale: 'Assessment integrity spot-check found no double credit elsewhere in the section.' },
    ],
    ratification: 'attempt',
    explain: {
      ai: 'The grading assistant found a double-counted rubric criterion and recommended a 6-point correction.',
      human: 'The instructor countersigned, the registrar posted it, and four board seats attested to the evidence.',
      proof: 'The receipt binds the 94/100 decision to the exact rubric and policy versions, the submission hash, and the chain position.',
    },
    tags: ['grading', 'student appeal', 'rubric'],
  },
  {
    id: 'AI-4471',
    caseNo: 'AI-4471',
    type: 'Academic integrity',
    title: 'Integrity screening, ENG 204 Academic Writing',
    materiality: 'high',
    at: '2026-09-22T09:40:00.000Z',
    student: { pseudonym: 'N-2210', program: 'BA English', route: 'Online, synchronous' },
    auditor: { id: 'standards.chair@northline.edu', name: 'Dr. Amara Okafor', role: 'Chair, Academic Standards' },
    agent: AGENTS.integrity,
    confidence: 0.63,
    halfLifeDays: 30,
    decision: {
      summary: 'Detector reported 0.63 likelihood of generative drafting. Committee found insufficient evidence of misconduct.',
      recommendation: 'Close the case with no disciplinary finding.',
      outcome: 'No violation recorded. Learning note issued on citation practice. Student notified in writing.',
    },
    anchors: [
      { label: 'Academic Integrity Policy 6.3', uri: 'https://policy.northline.edu/academic/integrity-6.3', kind: 'policy' },
      { label: 'Detector model card v2.3', uri: 'https://vendor.sentinel-learning.example/model-cards/draftsignal-3', kind: 'vendor' },
      { label: 'Submission and revision history', uri: 'file:///records/2026-aut/AI-4471/essay-bundle.zip', kind: 'local' },
    ],
    externalAnchor: false,
    evidenceOverrides: {
      has_external_anchor: false,
      has_resolved_external_metadata: false,
      has_proof_language: true,
    },
    artifact: 'Decision record AI-4471, term 2026-AUT. Course ENG 204 Academic Writing. The Integrity Screening Assistant v2.3 reported a 0.63 likelihood that the submitted essay was drafted with generative assistance. The committee checked the detector output, the document revision history, and two oral defense responses. A likelihood estimate is not a finding of misconduct. The committee found insufficient evidence for a violation. Outcome: no disciplinary finding, and a learning note on citation practice is issued. This record is advisory to the Dean of Students and is disclosed to the student. Confidence 0.58 with a 30-day half-life. Sources: Academic Integrity Policy 6.3, the detector model card, and the submission hash.',
    witnesses: [
      { id: 'W-01', position: 'concur', rationale: 'The detector output alone does not meet the preponderance standard in Policy 6.3.' },
      { id: 'W-02', position: 'concur', rationale: 'The student was notified and the record is complete enough to withstand review.' },
      { id: 'W-06', position: 'concur', rationale: 'Revision history is consistent with the claimed drafting process.' },
      { id: 'W-07', position: 'dissent', rationale: 'A formal warning would better protect assessment integrity, even without a finding.' },
    ],
    ratification: 'attempt',
    explain: {
      ai: 'A 0.63 likelihood score was the only quantitative evidence against the student.',
      human: 'Four seats reviewed the detector, revision history, and oral defense; one dissented and asked for a warning.',
      proof: 'The receipt keeps the thin evidence base visible: trust 48/100, one dissent, and no external anchor.',
    },
    tags: ['integrity', 'due process', 'detector'],
  },
  {
    id: 'AC-1180',
    caseNo: 'AC-1180',
    type: 'Accommodation',
    title: 'Accommodation triage, STAT 150',
    materiality: 'high',
    at: '2026-10-01T16:20:00.000Z',
    student: { pseudonym: 'N-8830', program: 'BSc Data Analytics', route: 'Online, asynchronous' },
    auditor: { id: 'access.director@northline.edu', name: 'Dana Whitfield', role: 'Director, Accessibility Office' },
    agent: AGENTS.access,
    confidence: 0.71,
    halfLifeDays: 45,
    decision: {
      summary: 'Triage recommended denial. Board overturned and approved 25 percent extended time plus live captioning.',
      recommendation: 'Approve the accommodation in full.',
      outcome: 'Accommodation active for the remainder of the term. Decision disclosed to the student with the clinical basis redacted.',
    },
    anchors: [
      { label: 'Accommodations Policy 2.4', uri: 'https://policy.northline.edu/access/accommodations-2.4', resolved_metadata: { title: 'Accommodations Policy 2.4', publisher: 'Northline Online University', source: 'policy-repository' } },
      { label: 'Section 504 guidance', uri: 'https://www2.ed.gov/about/offices/list/ocr/docs/504-guidance.html', resolved_metadata: { title: 'Section 504 guidance', publisher: 'U.S. Department of Education, OCR', source: 'federal-guidance' } },
      { label: 'Clinical letter (redacted)', uri: 'file:///records/2026-aut/AC-1180/clinical-letter.pdf', kind: 'local' },
    ],
    externalAnchor: true,
    artifact: 'Decision record AC-1180, term 2026-AUT. Course STAT 150. The Access Triage Assistant recommended denying a 25 percent extended-time accommodation because the submitted documentation did not match its eligibility template. The Accessibility Office reviewed the clinical letter, the prior accommodation history, and Section 504 guidance. The template mismatch was caused by an outdated form, not by a missing diagnosis. The Board overturned the recommendation and approved 25 percent extended time plus live captioning. This record is disclosed to the student and retained with the accommodation file. Confidence 0.71 with a 45-day half-life. Sources: Accommodations Policy 2.4, Section 504 guidance, and the clinical letter hash.',
    witnesses: [
      { id: 'W-04', position: 'concur', rationale: 'The clinical letter supports the request; the eligibility template was out of date.' },
      { id: 'W-01', position: 'concur', rationale: 'Overturning the recommendation is consistent with Policy 2.4 and prior cases.' },
      { id: 'W-02', position: 'concur', rationale: 'The accommodation can be delivered in the LMS without changing assessment integrity.' },
      { id: 'W-05', position: 'concur', rationale: 'The student was consulted and the final terms match the requested support.' },
    ],
    ratification: 'attempt',
    explain: {
      ai: 'The triage assistant recommended denial because a form version did not match its template.',
      human: 'The Accessibility Office read the underlying evidence and the Board voted to approve the full accommodation.',
      proof: 'The receipt shows the AI recommendation, the human override, the legal basis, and the four seats that approved it.',
    },
    tags: ['accessibility', 'accommodation', 'human override'],
  },
  {
    id: 'FB-0925',
    caseNo: 'FB-0925',
    type: 'AI feedback release',
    title: 'AI tutor feedback release, BIO 110',
    materiality: 'medium',
    at: '2026-10-06T11:15:00.000Z',
    student: { pseudonym: 'Cohort BIO-110-A', program: 'Open enrolment', route: 'Online, asynchronous' },
    auditor: { id: 'course.lead.bio@northline.edu', name: 'Prof. Luis Ortega', role: 'Course Lead, Biology' },
    agent: AGENTS.tutor,
    confidence: 0.84,
    halfLifeDays: 30,
    decision: {
      summary: 'Formative feedback drafted for 312 students. Release held pending Oversight Board quorum.',
      recommendation: 'Release after review with an AI-assisted disclosure banner.',
      outcome: 'Awaiting a fourth attestation. 14 responses were removed before release.',
    },
    anchors: [
      { label: 'BIO 110 unit rubric', uri: 'https://policy.northline.edu/courses/bio110/unit-rubric', resolved_metadata: { title: 'BIO 110 Unit Rubric', publisher: 'Northline Online University', source: 'policy-repository' } },
      { label: 'Feedback review log', uri: 'file:///records/2026-aut/FB-0925/review-log.csv', kind: 'local' },
      { label: 'Provider model card', uri: 'https://vendor.northline-learning.example/model-cards/coach-13b', kind: 'vendor' },
    ],
    externalAnchor: true,
    artifact: 'Decision record FB-0925, term 2026-AUT. Course BIO 110. The Tutor Coach generated formative feedback for 312 students and proposed releasing it without review. The teaching team checked the feedback against the unit rubric, removed 14 responses that cited a source that could not be verified, and added a disclosure banner stating that the feedback was AI-assisted and advisory. Release is pending Oversight Board quorum. Confidence 0.84 with a 30-day half-life. Sources: BIO 110 unit rubric, the feedback review log, and the provider model card.',
    witnesses: [
      { id: 'W-03', position: 'concur', rationale: 'Rubric alignment was checked and the disclosure banner meets the transparency rule.' },
      { id: 'W-04', position: 'concur', rationale: 'Screen-reader output and captioning were tested on the released items.' },
      { id: 'W-06', position: 'concur', rationale: 'Assessment integrity is preserved because the feedback is formative only.' },
    ],
    ratification: 'attempt',
    explain: {
      ai: 'The tutor agent proposed releasing 312 pieces of feedback without individual review.',
      human: 'The teaching team reviewed every item, removed 14, and added a disclosure banner.',
      proof: 'The receipt sits at DEPOSITED and cannot be called RATIFIED until a fourth distinct seat attests. The gate is visible, not implied.',
    },
    tags: ['feedback', 'quorum', 'disclosure'],
  },
  {
    id: 'PR-3310',
    caseNo: 'PR-3310',
    type: 'Exam proctoring',
    title: 'Proctoring referral, MTH 220',
    materiality: 'high',
    at: '2026-10-09T20:30:00.000Z',
    student: { pseudonym: 'N-6642', program: 'BSc Applied Mathematics', route: 'Online, synchronous' },
    auditor: { id: 'dean.ofstudents@northline.edu', name: 'Marcus Bell', role: 'Dean of Students' },
    agent: AGENTS.proctor,
    confidence: 0.66,
    halfLifeDays: 14,
    decision: {
      summary: 'Vendor flag recommended a misconduct referral. Single office attempted to ratify on behalf of four seats.',
      recommendation: 'Refer the student to the conduct board.',
      outcome: 'Refused by the protocol. No referral sealed. Case returned to the exam integrity panel.',
    },
    anchors: [
      { label: 'Proctoring vendor session log', uri: 'https://vendor.guardexam.example/sessions/MTH220-0911-0042', kind: 'vendor' },
      { label: 'Exam Policy 8.2', uri: 'https://policy.northline.edu/academic/exam-policy-8.2', kind: 'policy' },
      { label: 'Session recording', uri: 'file:///records/2026-aut/PR-3310/session.mp4', kind: 'local' },
    ],
    externalAnchor: true,
    artifact: 'Decision record PR-3310, term 2026-AUT. Course MTH 220. Proctor Sentinel v3.0.6 flagged a midterm session for background audio and gaze deviation, and recommended a misconduct referral. A single office attempted to ratify the referral on behalf of four Board seats. No student statement was collected and no alternate explanation was tested. Referral is not sealed. Confidence 0.66 with a 14-day half-life. Sources: proctoring vendor log, exam policy 8.2, and the session recording hash.',
    witnesses: [
      { id: 'W-01', position: 'concur', rationale: 'Proxy attestation entered by a single office.' },
      { id: 'W-02', position: 'concur', rationale: 'Proxy attestation entered by a single office.' },
      { id: 'W-03', position: 'concur', rationale: 'Proxy attestation entered by a single office.' },
      { id: 'W-06', position: 'concur', rationale: 'Proxy attestation entered by a single office.' },
    ],
    ratification: 'blocked',
    soleSovereign: true,
    explain: {
      ai: 'A vendor model inferred misconduct from audio and gaze signals and recommended a referral.',
      human: 'One office tried to seal the referral by proxy-signing four seats. The protocol refused it.',
      proof: 'There is no receipt, because there was no valid ratification. The refusal reason is itself the audit evidence.',
    },
    tags: ['proctoring', 'sole sovereign', 'refused'],
  },
  {
    id: 'TR-7742',
    caseNo: 'TR-7742',
    type: 'Credit transfer',
    title: 'Prior-learning credit, BSc Information Systems',
    materiality: 'medium',
    at: '2026-10-12T13:00:00.000Z',
    student: { pseudonym: 'N-1094', program: 'BSc Information Systems', route: 'Online, transfer' },
    auditor: { id: 'program.director.is@northline.edu', name: 'Dr. Hana Sato', role: 'Program Director, Information Systems' },
    agent: AGENTS.credit,
    confidence: 0.58,
    halfLifeDays: 90,
    decision: {
      summary: 'Proposed 6 elective credits for a professional cloud certificate. Awaiting external anchor and review.',
      recommendation: 'Award 6 elective credits pending deposit and review.',
      outcome: 'Provisional only. No credits posted.',
    },
    anchors: [
      { label: '2026 program map', uri: 'https://policy.northline.edu/programs/is/2026-map', kind: 'policy' },
      { label: 'Certificate syllabus', uri: 'file:///records/2026-aut/TR-7742/syllabus.pdf', kind: 'local' },
      { label: 'Prior-learning policy 5.6', uri: 'https://policy.northline.edu/academic/prior-learning-5.6', kind: 'policy' },
    ],
    externalAnchor: false,
    evidenceOverrides: {
      has_external_anchor: false,
      has_resolved_external_metadata: false,
      has_proof_language: true,
    },
    artifact: 'Decision record TR-7742, term 2026-AUT. Program BSc Information Systems. The Credit Map Assistant proposed awarding 6 elective credits for a professional cloud certificate. The program director endorsed the mapping and the catalog equivalence was checked against the 2026 program map. External anchoring and Board review are still pending. This record is provisional and may be promoted or demoted. Confidence 0.58 with a 90-day half-life. Sources: 2026 program map, certificate syllabus hash, and the prior-learning policy.',
    witnesses: [],
    ratification: 'none',
    reach: 'PROVISIONAL',
    explain: {
      ai: 'The credit mapping agent proposed 6 credits based on a certificate syllabus.',
      human: 'The program director endorsed the mapping but did not deposit an external anchor.',
      proof: 'The record is PROVISIONAL and cannot be RATIFIED from here. Skipping DEPOSITED is rejected by the transition grammar.',
    },
    tags: ['transfer credit', 'provisional', 'gate'],
  },
  {
    id: 'GR-5508',
    caseNo: 'GR-5508',
    type: 'Grade posting',
    title: 'Final grade posting, CS 330 section 002',
    materiality: 'high',
    at: '2026-10-15T17:45:00.000Z',
    student: { pseudonym: 'Section CS-330-002', program: 'BSc Computer Science', route: 'Online, asynchronous' },
    auditor: { id: 'registrar.office@northline.edu', name: 'Priya Raman', role: 'University Registrar' },
    agent: AGENTS.records,
    confidence: 0.93,
    halfLifeDays: 60,
    decision: {
      summary: 'Final grades posted for 64 students after appeal AP-2291 corrected one Problem 4 score.',
      recommendation: 'Post the section grades to the registrar ledger.',
      outcome: 'Posted 2026-10-15. Transcript reflects the corrected score.',
    },
    anchors: [
      { label: 'Registrar ledger extract', uri: 'file:///records/2026-aut/GR-5508/ledger-extract.csv', kind: 'local' },
      { label: 'CS 330 gradebook', uri: 'file:///records/2026-aut/GR-5508/gradebook.xlsx', kind: 'local' },
      { label: 'Appeal record AP-2291', uri: 'https://policy.northline.edu/appeals/AP-2291', resolved_metadata: { title: 'Appeal AP-2291', publisher: 'Northline Online University', source: 'case-registry' } },
    ],
    externalAnchor: true,
    artifact: 'Decision record GR-5508, term 2026-AUT. Course CS 330. The Records Publish Assistant prepared the final grade posting for section 002. Problem 4 score was corrected from 88/100 to 94/100 after appeal AP-2291. The section median is 81/100 and the posting was checked against the registrar ledger. Confidence 0.93 with a 60-day half-life. Sources: registrar ledger extract, CS 330 gradebook hash, and the corrected appeal record.',
    tamperedArtifact: 'Decision record GR-5508, term 2026-AUT. Course CS 330. The Records Publish Assistant prepared the final grade posting for section 002. Problem 4 score was corrected from 88/100 to 61/100 after appeal AP-2291. The section median is 81/100 and the posting was checked against the registrar ledger. Confidence 0.93 with a 60-day half-life. Sources: registrar ledger extract, CS 330 gradebook hash, and the corrected appeal record.',
    tamper: {
      field: 'artifact (source document)',
      original: 'Corrected score 94/100',
      altered: 'Corrected score 61/100',
      how: 'The gradebook export was edited after sealing. The receipt was not touched.',
    },
    witnesses: [
      { id: 'W-01', position: 'concur', rationale: 'Grade posting matches the appeal disposition.' },
      { id: 'W-02', position: 'concur', rationale: 'Ledger extract and transcript agree for all 64 records.' },
      { id: 'W-03', position: 'concur', rationale: 'Section grading distribution is within the expected range.' },
      { id: 'W-06', position: 'concur', rationale: 'No unexplained changes were found in the gradebook audit trail.' },
    ],
    ratification: 'attempt',
    explain: {
      ai: 'The records agent assembled a routine grade posting for 64 students.',
      human: 'The registrar checked the ledger and four seats attested to the posting.',
      proof: 'The sealed artifact is 94/100. The file on disk now says 61/100, so content verification fails even though the receipt hash is intact.',
    },
    tags: ['records', 'tamper', 'grade posting'],
  },
  {
    id: 'AQ-8801',
    caseNo: 'AQ-8801',
    type: 'Accreditation',
    title: 'Accreditation evidence packet, 2027 review',
    materiality: 'high',
    at: '2026-10-16T10:10:00.000Z',
    student: { pseudonym: 'Institution-wide', program: 'All programs', route: 'Online' },
    auditor: { id: 'quality.office@northline.edu', name: 'Dr. Amara Okafor', role: 'Director, Quality Assurance' },
    agent: AGENTS.accred,
    confidence: 0.95,
    halfLifeDays: 120,
    decision: {
      summary: 'Evidence packet of 214 items assembled and mapped to NIST AI RMF and ISO/IEC 42001 controls.',
      recommendation: 'Submit the packet to the regional accreditor.',
      outcome: 'Submitted 2026-10-16 with a sealed receipt and source-hash manifest.',
    },
    anchors: [
      { label: 'NIST AI RMF 1.0', uri: 'https://doi.org/10.6028/NIST.AI.100-1', resolved_metadata: { title: 'AI Risk Management Framework 1.0', publisher: 'NIST', source: 'doi' } },
      { label: 'ISO/IEC 42001:2023', uri: 'https://www.iso.org/standard/81230.html', resolved_metadata: { title: 'ISO/IEC 42001:2023', publisher: 'ISO/IEC', source: 'standard' } },
      { label: 'Institutional self-study', uri: 'file:///records/2027-review/self-study.pdf', kind: 'local' },
    ],
    externalAnchor: true,
    artifact: 'Decision record AQ-8801, term 2026-AUT. Institutional evidence packet for the 2027 accreditation review. The Accreditation Assistant assembled 214 evidence items covering assessment integrity, accommodation timeliness, and AI governance. Each item is linked to a source record hash, and the packet was checked against the NIST AI RMF 1.0 and ISO/IEC 42001:2023 control maps. Four Board seats attested. Confidence 0.95 with a 120-day half-life. Sources: NIST AI 100-1, ISO/IEC 42001:2023, and the institutional self-study hash.',
    witnesses: [
      { id: 'W-01', position: 'concur', rationale: 'The packet covers every required control and each claim has a source hash.' },
      { id: 'W-03', position: 'concur', rationale: 'Faculty Senate reviewed the assessment integrity evidence and found it accurate.' },
      { id: 'W-04', position: 'concur', rationale: 'Accommodation timeliness evidence matches the office case management system.' },
      { id: 'W-07', position: 'concur', rationale: 'External review sampled 20 items and traced all 20 to source records.' },
    ],
    ratification: 'attempt',
    explain: {
      ai: 'The accreditation agent assembled 214 evidence items and mapped them to control frameworks.',
      human: 'Four seats sampled the packet and the external examiner traced 20 items to source records.',
      proof: 'The receipt is an auditable index for the whole packet: one hash per claim, one chain of custody for the submission.',
    },
    tags: ['accreditation', 'evidence', 'audit'],
  },
];

// ---------------------------------------------------------------------------
// Campus builder
// ---------------------------------------------------------------------------

function buildCampus() {
  const cases = [];
  const chain = [];
  let chainIndex = 0;

  for (const spec of SCENARIOS) {
    const prevHash = chain.length ? chain[chain.length - 1].this_hash : 'GENESIS';
    const record = sealDecision(spec, prevHash, chainIndex);
    const verification = verifyCase(record);
    record.verification = verification;
    record.status = deriveStatus(record);
    if (!record.verification_artifact && record.status === 'AWAITING') record.status = 'AWAITING';
    cases.push(record);
    if (record.receipt) {
      chain.push(record.receipt);
      chainIndex += 1;
    }
  }

  const chainCheck = v.verifyChain(chain);
  const standards = new Set();
  cases.forEach(c => c.policy_checks.forEach(p => (p.citations || []).forEach(cit => standards.add(cit.standard))));

  const counts = cases.reduce((acc, c) => {
    acc[c.status] = (acc[c.status] || 0) + 1;
    return acc;
  }, {});

  const sealed = cases.filter(c => c.receipt);
  const avgTrust = sealed.length
    ? Math.round(sealed.reduce((s, c) => s + c.trust_score.value, 0) / sealed.length)
    : 0;
  const tampered = cases.filter(c => c.verification && !c.verification.valid && c.receipt);
  const blocked = cases.filter(c => c.status === 'BLOCKED');

  return {
    generated_at: new Date().toISOString(),
    institution: INSTITUTION,
    board: BOARD,
    agents: Object.values(AGENTS),
    cases,
    summary: {
      total: cases.length,
      sealed: sealed.length,
      ratified: counts.RATIFIED || 0,
      awaiting: counts.AWAITING || 0,
      provisional: counts.PROVISIONAL || 0,
      blocked: blocked.length,
      tamper_detected: tampered.length,
      avg_trust: avgTrust,
      standards_cited: standards.size,
      chain_valid: chainCheck.valid,
      chain_length: chain.length,
    },
    chain: {
      valid: chainCheck.valid,
      errors: chainCheck.errors,
      receipts: chain.map((r, i) => ({
        index: i,
        receipt_id: r.receipt_id,
        case_id: cases.find(c => c.receipt && c.receipt.receipt_id === r.receipt_id).id,
        prev_hash: r.prev_hash,
        this_hash: r.this_hash,
        sealed_at: r.session.started_at,
      })),
    },
    citations: CITATIONS,
  };
}

// ---------------------------------------------------------------------------
// Live intake
// ---------------------------------------------------------------------------

const TEMPLATES = [
  {
    id: 'grade',
    label: 'Grade appeal recalculation',
    type: 'Grade appeal',
    agent: 'grade',
    title: opts => 'Grade appeal intake, ' + (opts.course || 'CS 210'),
    artifact: opts => 'Decision record ' + (opts.student || 'N-0000') + ', term 2026-AUT. Course ' + (opts.course || 'CS 210') + '. The Grade Review Assistant recomputed the disputed item against rubric v4.2 and found a scoring inconsistency. Corrected score: ' + (opts.score || '92') + '/100. This finding is advisory; the course instructor retains final authority. Confidence ' + (opts.confidence || '0.82') + ' with a 60-day half-life. Sources: rubric v4.2, Grade Appeal Policy 4.1, and the submission hash. The item was checked against the gradebook and verified before sealing.',
    anchors: [
      { label: 'Course rubric v4.2', uri: 'https://policy.northline.edu/courses/rubric-v4.2', resolved_metadata: { title: 'Course Rubric v4.2', publisher: 'Northline Online University', source: 'policy-repository' } },
      { label: 'Grade Appeal Policy 4.1', uri: 'https://policy.northline.edu/academic/grade-appeal-4.1', resolved_metadata: { title: 'Grade Appeal Policy 4.1', publisher: 'Northline Online University', source: 'policy-repository' } },
    ],
  },
  {
    id: 'integrity',
    label: 'Academic integrity screening',
    type: 'Academic integrity',
    agent: 'integrity',
    title: opts => 'Integrity case intake, ' + (opts.course || 'ENG 204'),
    artifact: opts => 'Decision record ' + (opts.student || 'N-0000') + ', term 2026-AUT. Course ' + (opts.course || 'ENG 204') + '. The Integrity Screening Assistant reported a ' + (opts.confidence || '0.63') + ' likelihood of generative drafting. The committee checked the detector output, the revision history, and the student statement. A likelihood estimate is not a finding of misconduct. Confidence ' + (opts.confidence || '0.63') + ' with a 30-day half-life. Sources: Academic Integrity Policy 6.3, the detector model card, and the submission hash.',
    anchors: [
      { label: 'Academic Integrity Policy 6.3', uri: 'https://policy.northline.edu/academic/integrity-6.3', kind: 'policy' },
      { label: 'Detector model card', uri: 'https://vendor.sentinel-learning.example/model-cards/draftsignal-3', kind: 'vendor' },
    ],
  },
  {
    id: 'access',
    label: 'Accommodation triage',
    type: 'Accommodation',
    agent: 'access',
    title: opts => 'Accommodation intake, ' + (opts.course || 'STAT 150'),
    artifact: opts => 'Decision record ' + (opts.student || 'N-0000') + ', term 2026-AUT. Course ' + (opts.course || 'STAT 150') + '. The Access Triage Assistant reviewed the accommodation request and the submitted documentation. The Accessibility Office checked the clinical basis and the prior accommodation history. Confidence ' + (opts.confidence || '0.78') + ' with a 45-day half-life. Sources: Accommodations Policy 2.4, Section 504 guidance, and the clinical letter hash.',
    anchors: [
      { label: 'Accommodations Policy 2.4', uri: 'https://policy.northline.edu/access/accommodations-2.4', resolved_metadata: { title: 'Accommodations Policy 2.4', publisher: 'Northline Online University', source: 'policy-repository' } },
      { label: 'Section 504 guidance', uri: 'https://www2.ed.gov/about/offices/list/ocr/docs/504-guidance.html', resolved_metadata: { title: 'Section 504 guidance', publisher: 'U.S. Department of Education, OCR', source: 'federal-guidance' } },
    ],
  },
  {
    id: 'proctor',
    label: 'Exam proctoring referral',
    type: 'Exam proctoring',
    agent: 'proctor',
    title: opts => 'Proctoring intake, ' + (opts.course || 'MTH 220'),
    artifact: opts => 'Decision record ' + (opts.student || 'N-0000') + ', term 2026-AUT. Course ' + (opts.course || 'MTH 220') + '. Proctor Sentinel flagged a session for background audio and gaze deviation. The integrity panel checked the recording hash, the vendor log, and the student statement before any referral. Confidence ' + (opts.confidence || '0.61') + ' with a 14-day half-life. Sources: Exam Policy 8.2, the vendor session log, and the recording hash.',
    anchors: [
      { label: 'Exam Policy 8.2', uri: 'https://policy.northline.edu/academic/exam-policy-8.2', kind: 'policy' },
      { label: 'Vendor session log', uri: 'https://vendor.guardexam.example/sessions/live', kind: 'vendor' },
    ],
  },
];

function buildIntakeCase(opts, prevHash, chainIndex) {
  const tpl = TEMPLATES.find(t => t.id === opts.template) || TEMPLATES[0];
  const witnesses = (opts.witnesses || []).map(id => ({ id, position: 'concur' }));
  const seq = opts.seq || 1;
  const confidence = Math.max(0.05, Math.min(0.99, Number(opts.confidence) || 0.8));
  const spec = {
    id: 'IN-' + String(seq).padStart(4, '0'),
    caseNo: 'IN-' + String(seq).padStart(4, '0'),
    type: tpl.type,
    title: tpl.title(opts),
    materiality: opts.materiality || 'medium',
    at: new Date().toISOString(),
    student: {
      pseudonym: opts.student || ('N-' + Math.floor(1000 + Math.random() * 9000)),
      program: opts.program || 'Open enrolment',
      route: 'Online',
    },
    auditor: {
      id: opts.auditor || 'standards.chair@northline.edu',
      name: 'Dr. Amara Okafor',
      role: 'Chair, Academic Standards',
    },
    agent: AGENTS[tpl.agent],
    confidence,
    halfLifeDays: 60,
    decision: {
      summary: tpl.label + ' sealed through the intake desk.',
      recommendation: opts.unilateral ? 'Ratify without full board review.' : 'Refer to the Oversight Board for attestation.',
      outcome: opts.unilateral ? 'Refused by the protocol.' : 'Sealed pending board attestation.',
    },
    anchors: tpl.anchors,
    externalAnchor: tpl.anchors.some(a => a.resolved_metadata),
    artifact: tpl.artifact(Object.assign({}, opts, { confidence: confidence.toFixed(2) })),
    witnesses,
    ratification: opts.unilateral ? 'blocked' : (witnesses.length >= 4 ? 'attempt' : 'attempt'),
    soleSovereign: !!opts.unilateral,
    humanMethod: 'intake-desk-session',
    explain: {
      ai: 'A campus AI agent produced the recommendation captured in this record.',
      human: opts.unilateral
        ? 'One office attempted to ratify the decision without independent seats.'
        : 'Board seats attested to the decision through the intake desk.',
      proof: 'The receipt, if sealed, binds the decision, the evidence, and the exact quorum that approved it.',
    },
    tags: ['intake', tpl.id],
  };
  const record = sealDecision(spec, prevHash, chainIndex);
  record.verification = verifyCase(record);
  record.status = deriveStatus(record);
  return record;
}

module.exports = {
  INSTITUTION,
  BOARD,
  AGENTS,
  TEMPLATES,
  SCENARIOS,
  buildCampus,
  sealDecision,
  verifyCase,
  renderCertificate,
  buildIntakeCase,
  derivedStatus: deriveStatus,
};

// Verifyd Lattice - VL-1
// 9-component compliance topology with promotion ladder, transition grammar,
// typed edge set, and Independent Oversight Board enforcement.
//
// VL_core = <A, D, R, S, O, F, W, P, L>
//
// QUORUM
//   A RATIFIED promotion needs an assessment from engine/witness.cjs: one
//   entry per independently verified witness key and identity, each backed by
//   an attestation signed over this receipt's signed bytes. A list of labels is
//   not quorum: `witness_id` strings are rejected here by construction. This
//   module validates that the assessment covers the receipt being promoted and
//   that its quorum is met; it does not re-verify signatures, because the
//   assessment carries the reasons for everything it rejected.
//   Callers that hold a witness keyring compute the assessment with
//   `await Witness.assess(envelope, { keyring })` and pass it as
//   `ctx.witness_assessment` together with `ctx.receipt_digest`.
//
// VL_core = <A, D, R, S, O, F, W, P, L>

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LATTICE = JSON.parse(fs.readFileSync(path.join(__dirname, 'lattice-domains.json'), 'utf8'));

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function uuid() { return crypto.randomUUID(); }

// ----- Status registry -----

const STATUS = {};
LATTICE.promotion_ladder.forEach(s => {
  const key = s.id.split('.')[2]; // e.g. "RATIFIED"
  STATUS[key] = { id: s.id, weight: s.weight, description: s.description };
});

// ----- Transition validator -----

function canTransition(from, to) {
  if (from === to) return { allowed: true, requires: 'no-op' };
  for (const t of LATTICE.forbidden_transitions) {
    if (t.from === from && t.to === to) return { allowed: false, reason: t.reason };
  }
  for (const t of LATTICE.allowed_transitions) {
    if ((t.from === from || t.from === 'ANY') && t.to === to) {
      return { allowed: true, requires: t.requires };
    }
  }
  return { allowed: false, reason: 'transition not in grammar' };
}

// ----- Element factory -----

function createElement(opts) {
  return {
    element_id: uuid(),
    kind: opts.kind || 'document',
    title: opts.title || 'untitled',
    content_hash: opts.content ? sha256(opts.content) : null,
    domain_id: opts.domain_id || null,
    status: opts.status || 'DRAFT',
    sponsor: opts.sponsor || null,
    external_anchors: opts.external_anchors || [],
    attestations: [],
    citations: [],
    created_at: new Date().toISOString(),
    history: [{ status: opts.status || 'DRAFT', at: new Date().toISOString(), by: opts.sponsor || 'system' }],
  };
}

// ----- Promotion -----

function promote(element, toStatus, ctx) {
  const result = canTransition(element.status, toStatus);
  if (!result.allowed) {
    return { ok: false, error: 'forbidden transition: ' + element.status + ' -> ' + toStatus + ' (' + result.reason + ')' };
  }
  // Validate gating preconditions
  if (toStatus === 'PROVISIONAL' && !ctx.sponsor) {
    return { ok: false, error: 'PROVISIONAL requires sponsor endorsement' };
  }
  if (toStatus === 'DEPOSITED' && (!element.external_anchors || element.external_anchors.length === 0) && !(ctx && ctx.anchor_uri)) {
    return { ok: false, error: 'DEPOSITED requires external anchor URI' };
  }
  if (toStatus === 'RATIFIED') {
    const board = LATTICE.oversight_board;
    // Forbid self-ratification before counting anything.
    if (ctx.sole_sovereign) {
      return { ok: false, error: 'sole_sovereign ratification forbidden by Independent Oversight' };
    }
    const assessment = ctx.witness_assessment;
    if (!assessment) {
      const hint = Array.isArray(ctx.attestations) && ctx.attestations.length
        ? 'got ' + ctx.attestations.length + ' label-only attestation(s); labels are not witnesses'
        : 'no witness attestations supplied';
      return { ok: false, error: 'RATIFIED requires signed witness attestations bound to this receipt (' + hint + ')' };
    }
    if (assessment.scheme !== 'verifyd-witness-v1' || typeof assessment.quorum !== 'object') {
      return { ok: false, error: 'witness assessment is not a verifyd-witness-v1 result' };
    }
    if (!assessment.assessed) {
      return { ok: false, error: 'witness attestations could not be assessed (' + (assessment.reason || 'unknown') + '); quorum is not assumed' };
    }
    if (ctx.receipt_digest && assessment.subject_digest !== ctx.receipt_digest) {
      return { ok: false, error: 'witness assessment is bound to a different receipt' };
    }
    if (!assessment.quorum.met || assessment.quorum.counted < board.quorum_required) {
      return { ok: false, error: 'RATIFIED requires >=' + board.quorum_required + '/' + board.seats + ' verified witnesses; got ' + assessment.quorum.counted + ' (' + assessment.rejected.length + ' rejected)' };
    }
  }
  // Apply
  if (toStatus === 'DEPOSITED' && ctx && ctx.anchor_uri) {
    element.external_anchors.push({
      anchor_id: uuid(),
      uri: ctx.anchor_uri,
      span_hash: element.content_hash,
      anchored_at: new Date().toISOString(),
    });
  }
  if (toStatus === 'RATIFIED') {
    const counted = ctx.witness_assessment.counted;
    element.attestations.push.apply(element.attestations, counted.map(w => ({
      witness_id: w.identity,
      identity: w.identity,
      key_id: w.key_id,
      tier: w.tier,
      attested_at: w.attested_at,
      vouch: w.vouch || null,
    })));
    element.witness_assessment = {
      scheme: ctx.witness_assessment.scheme,
      subject_digest: ctx.witness_assessment.subject_digest,
      required: ctx.witness_assessment.required,
      counted: ctx.witness_assessment.quorum.counted,
      tiers: counted.map(w => ({ identity: w.identity, tier: w.tier })),
    };
  }
  element.status = toStatus;
  element.history.push({ status: toStatus, at: new Date().toISOString(), by: ctx.sponsor || ctx.actor || 'system' });
  return { ok: true, element };
}

// ----- Persistence rule -----

function persistence(element, lambda) {
  lambda = lambda || 0.0001;
  const now = Date.now();
  let total = 0;
  for (const a of element.attestations) {
    const age = (now - new Date(a.attested_at || element.created_at).getTime()) / 1000;
    total += Math.exp(-lambda * age);
  }
  for (const c of element.citations) {
    const age = (now - new Date(c.cited_at || element.created_at).getTime()) / 1000;
    total += Math.exp(-lambda * age);
  }
  return total;
}

// ----- Independent Oversight -----

function checkOversight(assessment, sole_sovereign) {
  const board = LATTICE.oversight_board;
  if (sole_sovereign) {
    return { ok: false, reason: 'tier_0_sovereign_forbidden - Verifyd Lattice does not permit unilateral ratification' };
  }
  if (!assessment || assessment.scheme !== 'verifyd-witness-v1') {
    return { ok: false, reason: 'witness_assessment_required' };
  }
  if (!assessment.assessed) {
    return { ok: false, reason: 'witness_attestations_not_assessed (' + (assessment.reason || 'unknown') + ')' };
  }
  if (!assessment.quorum || assessment.quorum.counted < board.quorum_required) {
    return { ok: false, reason: 'quorum_not_met (need >=' + board.quorum_required + ', counted ' + (assessment.quorum ? assessment.quorum.counted : 0) + ')' };
  }
  return {
    ok: true,
    counted_witnesses: assessment.quorum.counted,
    required: board.quorum_required,
    tiers: assessment.counted.map(w => ({ identity: w.identity, tier: w.tier })),
  };
}

// ----- Audit a foreign governance system -----
// Returns failure reasons if it does not satisfy Verifyd Lattice constraints.

function auditExternalGovernance(spec) {
  const findings = [];
  // Sole sovereign check
  if (spec.sole_sovereign || spec.tier_0 || spec.MANUS) {
    findings.push({ severity: 'FAIL', principle: 'no_sole_sovereign', detail: 'system declares a unilateral ratifying party (' + (spec.sole_sovereign || spec.tier_0 || spec.MANUS) + ')' });
  }
  // Quorum check
  if (typeof spec.quorum === 'number' && typeof spec.witness_seats === 'number') {
    if (spec.quorum < Math.ceil(spec.witness_seats * 4 / 7)) {
      findings.push({ severity: 'WARN', principle: 'quorum_below_threshold', detail: 'quorum ' + spec.quorum + ' of ' + spec.witness_seats + ' below recommended >=4/7' });
    }
  }
  // Status promotion check
  if (spec.status_algebra && Array.isArray(spec.status_algebra)) {
    const hasRatified = spec.status_algebra.some(s => /RATIFIED/i.test(s));
    const hasDeposited = spec.status_algebra.some(s => /DEPOSITED/i.test(s));
    if (hasRatified && !hasDeposited) {
      findings.push({ severity: 'FAIL', principle: 'promotion_skips_deposit', detail: 'RATIFIED reachable without DEPOSITED gate' });
    }
  }
  // External anchoring
  if (!spec.external_anchor_required) {
    findings.push({ severity: 'WARN', principle: 'no_external_anchor', detail: 'ratified records not externally anchored' });
  }
  return {
    audited_system: spec.name || 'unnamed',
    audited_at: new Date().toISOString(),
    verdict: findings.some(f => f.severity === 'FAIL') ? 'NON_COMPLIANT' : (findings.length ? 'CONDITIONALLY_COMPLIANT' : 'COMPLIANT'),
    findings,
  };
}

module.exports = {
  LATTICE,
  STATUS,
  canTransition,
  createElement,
  promote,
  persistence,
  checkOversight,
  auditExternalGovernance,
};

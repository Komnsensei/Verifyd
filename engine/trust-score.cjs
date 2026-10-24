// Verifyd assurance score - verifyd-trust-assurance-v1
//
// WHAT THIS NUMBER IS
//   A probability, between 0 and 1, that a receipt's assurance claim holds:
//   that the bytes are signed by a trusted key, their time is attested, their
//   inclusion is proven, the witnessing board is real, the declared policy
//   checks pass, and a named reviewer's determination stands. It is produced by
//   a logistic model whose parameters are committed in
//   engine/calibration/trust-model.json, fitted once by scripts/calibrate-trust.cjs
//   and never re-fitted here. Scoring is a dot product: deterministic, offline,
//   no randomness, no state.
//
// VERIFICATION HAS ONE OWNER
//   This module does not re-check anything. engine/evidence.cjs verifies the
//   signature, time token, inclusion proof, batch root, witness quorum and
//   determination once; this file only translates that verdict into the
//   model's feature vector. The same evidence object drives verify's printed
//   report, so the number and the verdict beside it cannot come from different
//   code.
//
// WHAT IT IS NOT
//   - Not a probability that the document's contents are true. Verifyd cannot
//     see truth; it sees sealed bytes and the evidence attached to them.
//   - Not calibrated against real audit outcomes. The labels in the committed
//     corpus are SYNTHETIC, generated from a documented latent rule. Held-out
//     metrics therefore measure whether this machinery is wired and stable,
//     not whether the probability matches the world. A real calibration needs
//     labelled outcomes from real audits, which this repo does not have.
//   - Not a score to maximize. Removing or invalidating a timestamp lowers it
//     because the evidence is genuinely absent or unverified, not because the
//     model is being gamed.
//
// FAILURE NEVER PAYS
//   Each scored dimension is binary: it contributes 1 only when it was checked
//   and passed, and 0 otherwise. An unverifiable result (a signature under an
//   untrusted key, a token whose chain was not checked, a proof with no
//   authenticated root, a partial witness quorum, a warning or untraceable
//   policy result, an unresolved anchor, a non-compliant determination) scores
//   exactly what the absent dimension scores; it can never outrank absence.
//   A failed check is not partial evidence.
//
// MISSING EVIDENCE DEGRADES, IT DOES NOT VANISH
//   Every failed or absent dimension is named in `absent`; the five verification
//   dimensions are also counted by the model's fitted `missing` term, and policy
//   and anchors are priced at zero. The output says which evidence would move it.
//
// PROVENANCE TRAVELS WITH THE NUMBER
//   Every result carries the scheme, model version, corpus SHA-256, feature
//   vector and the labels' origin, so a reader can tell exactly which model
//   produced a value and what it was fitted on.
//
// The hand-tuned 0-100 index that used to be called the trust score is kept as
// `documentQuality` below. It is a heuristic about document substance, it is
// NOT calibrated, it never leaves the audit path, and it is never presented as
// a probability.

'use strict';

const fs = require('fs');
const path = require('path');

const CITATIONS = require('./citations.json');
const Evidence = require('./evidence.cjs');

const MODEL_PATH = path.join(__dirname, 'calibration', 'trust-model.json');
const MODEL = JSON.parse(fs.readFileSync(MODEL_PATH, 'utf8'));

const SCHEME = MODEL.scheme;
const MODEL_VERSION = MODEL.model_version;
const DATASET_SHA256 = MODEL.dataset.sha256;
const LABELS_ORIGIN = MODEL.dataset.labels_origin;
const FEATURES = MODEL.features.slice();
const INTERCEPT = MODEL.parameters.intercept;
const WEIGHTS = MODEL.parameters.weights.slice();

if (FEATURES.length !== WEIGHTS.length) {
  throw new Error('trust model feature vector does not match its weights');
}

// The one sentence that must travel with every probability.
const MEANING = 'Estimated probability that this receipt\'s assurance claim holds, ' +
  'fitted on synthetic labels; not a real-world accuracy claim and not a judgement of content truth.';

// ----- deterministic inference -----

function sigmoid(z) {
  if (z >= 0) return 1 / (1 + Math.exp(-z));
  const e = Math.exp(z);
  return e / (1 + e);
}

function round(value, places) {
  const f = Math.pow(10, places);
  return Math.round(value * f) / f;
}

// Pure: feature values in the model's committed order -> probability.
function probability(featureValues) {
  if (!Array.isArray(featureValues) || featureValues.length !== FEATURES.length) {
    throw new Error('expected ' + FEATURES.length + ' feature values, got ' +
      (Array.isArray(featureValues) ? featureValues.length : typeof featureValues));
  }
  let z = INTERCEPT;
  for (let i = 0; i < FEATURES.length; i++) {
    const value = Number(featureValues[i]);
    if (!Number.isFinite(value)) throw new Error('feature ' + FEATURES[i] + ' is not a finite number');
    z += WEIGHTS[i] * value;
  }
  return round(sigmoid(z), 6);
}

function featureRecord(featureValues) {
  const out = {};
  FEATURES.forEach((name, i) => { out[name] = featureValues[i]; });
  return out;
}

// ----- evidence -> features -----
// Time, inclusion, batch roots, witness quorums and determinations were
// verified by engine/evidence.cjs. These functions only translate verdicts.

function signatureFeature(signature) {
  if (!signature || !signature.checks || !signature.checks.signature_present) {
    return { value: 0, status: 'unsigned' };
  }
  if (signature.ok) return { value: 1, status: 'valid', key_id: signature.key_id };
  // Only a verified signature pays. A signature this machine cannot tie to a
  // trusted key is a failed check, not partial evidence: it scores exactly what
  // no signature scores, and `missing` counts it. Paying 0.5 here let an
  // untrusted signer outrank a receipt with no signature at all.
  if (signature.code === 'UNTRUSTED_KEY' || signature.code === 'PUBLIC_KEY_MISMATCH') {
    return { value: 0, status: 'key_untrusted', detail: signature.code };
  }
  if (signature.code === 'KEYRING_NOT_FOUND' || signature.code === 'KEYRING_ERROR') {
    return { value: 0, status: 'keyring_unavailable', detail: signature.code };
  }
  return { value: 0, status: 'invalid', detail: signature.code };
}

function timeFeature(time) {
  if (!time || time.status === 'unattested') return { value: 0, status: 'unattested' };
  if (time.status === 'attested') {
    return { value: 1, status: 'attested', gen_time: time.analysis && time.analysis.gen_time };
  }
  if (time.status === 'unverified') {
    // The token exists but its chain was not checked. That is not attested
    // time, so it pays nothing and counts as missing, exactly like no token.
    return { value: 0, status: 'unverified', detail: 'token signature valid, chain unchecked (--tsa-ca not configured)' };
  }
  return {
    value: 0,
    status: time.caError ? 'invalid_root' : 'invalid',
    detail: time.caError || (time.analysis && (time.analysis.reasons || []).join(', ')) || 'token failed verification',
  };
}

function inclusionFeature(evidence) {
  const inclusion = evidence.inclusion;
  if (!inclusion.present) return { value: 0, status: 'absent' };
  if (!inclusion.proofOk) return { value: 0, status: 'invalid', detail: inclusion.reason };

  const batch = evidence.batch;
  if (!batch.present) {
    // Arithmetic inclusion without an authenticated root proves nothing about
    // who committed the batch, so it cannot pay. It is reported, and `missing`
    // counts it like an absent proof.
    return { value: 0, status: 'unauthenticated_root', detail: 'pass --batch <root.json> to authenticate the root' };
  }
  if (!batch.authenticated) {
    return { value: 0, status: 'invalid_root', detail: batch.error || batch.reason };
  }
  return { value: 1, status: 'proven', detail: batch.reason };
}

// Ledger membership pays only when a trusted checkpoint is the one the proof
// lands in. Unanchored membership is arithmetic over an unsigned block, the
// same distinction inclusion-without-a-batch-root already makes.
function ledgerFeature(raw) {
  const ledger = raw && raw.ledger;
  if (!ledger || !ledger.requested) return { value: 0, status: 'absent', detail: null };
  if (ledger.status !== 'IN CHAIN') {
    return {
      value: 0,
      status: ledger.status === 'NOT RECORDED' ? 'not_recorded' : 'invalid',
      detail: ledger.reason,
    };
  }
  if (!ledger.anchored) {
    return { value: 0, status: 'unanchored', detail: 'membership proven, checkpoint not anchored' };
  }
  return { value: 1, status: 'anchored', detail: null };
}

function witnessFeature(evidence) {
  const envelope = evidence.envelope;
  const listed = envelope && Array.isArray(envelope.attestations) ? envelope.attestations : [];
  const required = evidence.quorumRequired;
  if (listed.length === 0) {
    return { count: 0, tier: 0, status: 'absent', counted: 0, required, met: false };
  }

  const assessment = evidence.witnesses;
  if (!assessment.assessed) {
    return {
      count: 0, tier: 0, status: 'unassessed',
      counted: 0, required, met: false,
      detail: assessment.detail || assessment.reason,
    };
  }

  const q = assessment.quorum;
  if (!q.met) {
    // A partial quorum is a failed check, not a percentage of one. It pays
    // nothing (including no tier credit) and counts as missing, so three
    // witnesses can never outrank no witnesses.
    return {
      count: 0, tier: 0, status: 'below_quorum',
      counted: q.counted, required: q.required, met: false,
      detail: q.counted + '/' + q.required + ' verified witnesses',
      conflicts: assessment.conflicts.length,
      rejected: assessment.rejected.length,
    };
  }
  let tier = 0;
  for (const w of assessment.counted) {
    if (w.tier === 'vouched') tier = Math.max(tier, 1);
    else if (w.tier === 'key') tier = Math.max(tier, 0.5);
  }
  return {
    count: 1, tier, status: 'assessed',
    counted: q.counted, required: q.required, met: true,
    conflicts: assessment.conflicts.length,
    rejected: assessment.rejected.length,
  };
}

// A policy result pays only when it was evaluated, passed, and can be traced
// to a citation that is registered for that principle. A warning, a failure, a
// skipped/unevaluated result, a missing timestamp, or a citation that does not
// resolve to a ground in engine/citations.json all score zero: a policy set is
// not partially checked, and an untraceable result is not evidence.
function citationTraced(principle, citation) {
  const entry = CITATIONS.policy_check_citations[principle];
  if (!entry) return false;
  if (!citation || typeof citation !== 'object') return false;
  if (!CITATIONS.standards[citation.standard]) return false;
  if (typeof citation.locator !== 'string' || citation.locator.length === 0) return false;
  return (entry.grounds || []).some(g => g.ref === citation.standard && g.locator === citation.locator);
}

function policyFeature(envelope) {
  const receipt = envelope && envelope.receipt && typeof envelope.receipt === 'object' ? envelope.receipt : {};
  const checks = Array.isArray(receipt.policy_checks) ? receipt.policy_checks : [];
  if (checks.length === 0) return { value: 0, status: 'absent', detail: 'no policy checks recorded' };

  const problems = [];
  for (const check of checks) {
    const principle = check && typeof check === 'object' ? check.principle : null;
    if (!principle) { problems.push('unnamed policy check'); continue; }
    if (!CITATIONS.policy_check_citations[principle]) {
      problems.push(principle + ': unregistered principle');
      continue;
    }
    if (check.result !== 'pass') {
      problems.push(principle + ': ' + (check.result || 'not evaluated'));
      continue;
    }
    if (typeof check.checked_at !== 'string' || Number.isNaN(Date.parse(check.checked_at))) {
      problems.push(principle + ': no checked_at');
      continue;
    }
    const citations = Array.isArray(check.citations) ? check.citations : [];
    if (citations.length === 0) {
      problems.push(principle + ': no citation');
      continue;
    }
    for (const citation of citations) {
      if (!citationTraced(principle, citation)) {
        problems.push(principle + ': citation not traced');
        break;
      }
    }
  }

  return {
    value: problems.length === 0 ? 1 : 0,
    status: problems.length === 0 ? 'recorded' : 'unverified',
    passed: checks.filter(c => c.result === 'pass').length,
    warned: checks.filter(c => c.result === 'warn').length,
    failed: checks.filter(c => c.result === 'fail').length,
    detail: problems.length ? problems.join('; ') : null,
  };
}

function ratificationFeature(envelope, witnesses) {
  const receipt = envelope && envelope.receipt && typeof envelope.receipt === 'object' ? envelope.receipt : {};
  const status = receipt.lattice && receipt.lattice.status ? receipt.lattice.status : null;
  if (status !== 'RATIFIED') return { value: 0, status: status || 'none' };
  if (witnesses.status !== 'assessed') {
    return { value: 0, status: 'unbacked', detail: 'RATIFIED claimed; witness quorum could not be assessed' };
  }
  if (!witnesses.met) {
    return { value: 0, status: 'unbacked', detail: 'RATIFIED claimed; quorum is ' + witnesses.counted + '/' + witnesses.required };
  }
  return { value: 1, status: 'backed' };
}

// An anchor pays only when it points at an external http(s) source, carries a
// span hash, and records a resolution that is internally checkable: a known
// resolver, a resolution time, a non-empty title, and a URI host matching that
// resolver. An unresolved anchor, an empty metadata object, an unknown source
// or a resolver/URI mismatch scores zero.
function anchorHost(uri) {
  try {
    return new URL(uri).hostname.toLowerCase();
  } catch (_) {
    return null;
  }
}

function anchorResolutionVerified(anchor) {
  const uri = anchor && anchor.uri;
  if (typeof uri !== 'string' || !/^https?:\/\//i.test(uri)) return false;
  if (typeof anchor.span_hash !== 'string' || anchor.span_hash.length === 0) return false;

  const meta = anchor.resolved_metadata;
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return false;
  if (typeof meta.title !== 'string' || meta.title.trim().length === 0) return false;
  if (typeof meta.resolved_at !== 'string' || Number.isNaN(Date.parse(meta.resolved_at))) return false;

  const host = anchorHost(uri);
  if (!host) return false;
  if (meta.source === 'arxiv') return host === 'arxiv.org' || host.endsWith('.arxiv.org');
  if (meta.source === 'crossref') return host === 'doi.org' || host === 'dx.doi.org' || host === 'www.doi.org';
  return false;
}

function anchorFeature(envelope) {
  const receipt = envelope && envelope.receipt && typeof envelope.receipt === 'object' ? envelope.receipt : {};
  const outputs = Array.isArray(receipt.outputs) ? receipt.outputs : [];
  const anchors = [];
  for (const output of outputs) {
    if (output && Array.isArray(output.source_anchors)) anchors.push.apply(anchors, output.source_anchors);
  }
  if (anchors.length === 0) return { value: 0, status: 'absent', detail: 'no source anchors recorded' };

  // file:// and doc:// anchors are internal references, not external evidence.
  const external = anchors.filter(a => a && typeof a.uri === 'string' && !a.uri.startsWith('file://'));
  if (external.length === 0) return { value: 0, status: 'local_only', detail: 'no external anchor' };

  const verified = external.filter(anchorResolutionVerified);
  if (verified.length !== external.length) {
    return {
      value: 0,
      status: 'unresolved',
      external: external.length,
      resolved: verified.length,
      detail: verified.length + '/' + external.length + ' external anchors have a verified resolution',
    };
  }
  return { value: 1, status: 'resolved', external: external.length, resolved: verified.length };
}

function determinationFeature(determination) {
  if (!determination || !determination.requested) return { value: 0, status: 'absent' };
  if (determination.error) {
    const status = determination.error === 'determination file not found' ? 'missing' : 'unreadable';
    return { value: 0, status, detail: determination.error };
  }

  const res = determination.result;
  if (!res) return { value: 0, status: 'unreadable' };
  if (res.status === 'compliant' && res.ok !== false) {
    return { value: 1, status: 'compliant', reviewer: res.reviewer };
  }
  // Only a compliant determination contributes positively. An adverse
  // conclusion, an incomplete or undetermined record, and a validity failure
  // are all zero: a worse review can never raise the assurance number. They
  // are still reported by status and named through `absent`.
  return {
    value: 0,
    status: res.status,
    detail: (res.reasons || []).join(', ') || null,
  };
}

// `missing` counts every verification dimension that did not pass, so a failed
// check is priced exactly like an absent one. Five dimensions: signature trust,
// attested time, proven inclusion (which requires an authenticated root),
// witness quorum, and a compliant determination.
function missingDimensions(evidence) {
  const missing = [];
  if (evidence.signature.value === 0) missing.push('signature');
  if (evidence.time.value === 0) missing.push('attested_time');
  if (evidence.inclusion.value === 0) missing.push('proven_inclusion');
  if (evidence.witnesses.count === 0) missing.push('witness_quorum');
  if (evidence.determination.value === 0) missing.push('compliant_determination');
  return missing;
}

function absentDimensions(evidence) {
  const absent = missingDimensions(evidence);
  if (evidence.policy.value === 0) absent.push('verified_policy');
  if (evidence.anchors.value === 0) absent.push('resolved_anchor');
  // Named only when the question was asked: a receipt checked without --ledger
  // makes no membership claim, so there is no absent evidence to report.
  if (evidence.ledger.status !== 'absent' && evidence.ledger.value === 0) {
    absent.push('authenticated_ledger_membership');
  }
  return absent;
}

function buildVector(evidence) {
  return [
    evidence.signature.value,
    evidence.time.value,
    evidence.inclusion.value,
    evidence.witnesses.count,
    evidence.witnesses.tier,
    evidence.policy.value,
    evidence.ratification.value,
    evidence.anchors.value,
    evidence.determination.value,
    evidence.ledger.value,
    round(missingDimensions(evidence).length / 5, 2),
  ];
}

function featureEvidence(envelope, raw) {
  const witnesses = witnessFeature(raw);
  return {
    signature: signatureFeature(raw.signature),
    time: timeFeature(raw.time),
    inclusion: inclusionFeature(raw),
    witnesses,
    policy: policyFeature(envelope),
    ratification: ratificationFeature(envelope, witnesses),
    anchors: anchorFeature(envelope),
    determination: determinationFeature(raw.determination),
    ledger: ledgerFeature(raw),
  };
}

// Translate the single verification pass into features. `opts.evidence` lets a
// caller such as verify share exactly the object it already displayed.
async function assess(envelope, opts) {
  opts = opts || {};
  const raw = opts.evidence || await Evidence.collect(envelope, opts);
  const evidence = featureEvidence(envelope, raw);

  const vector = buildVector(evidence);
  const p = probability(vector);
  const absent = absentDimensions(evidence);
  const notes = [];

  if (evidence.witnesses.status === 'unassessed') {
    notes.push({ code: 'witnesses_unassessed', detail: evidence.witnesses.detail });
  }
  if (evidence.witnesses.status === 'below_quorum') {
    notes.push({ code: 'witness_quorum_unmet', detail: evidence.witnesses.detail });
  }
  if (evidence.time.status === 'unverified') {
    notes.push({ code: 'time_chain_unchecked', detail: evidence.time.detail });
  }
  if (evidence.inclusion.status === 'unauthenticated_root') {
    notes.push({ code: 'inclusion_root_unauthenticated', detail: evidence.inclusion.detail });
  }
  if (evidence.ratification.status === 'unbacked') {
    notes.push({ code: 'ratified_claim_unbacked', detail: evidence.ratification.detail });
  }
  if (evidence.signature.status === 'key_untrusted') {
    notes.push({ code: 'signer_key_untrusted', detail: evidence.signature.detail });
  }
  if (evidence.determination.status !== 'absent' && evidence.determination.status !== 'compliant') {
    notes.push({ code: 'determination_not_compliant', detail: evidence.determination.status });
  }
  if (evidence.policy.status === 'unverified') {
    notes.push({ code: 'policy_unverified', detail: evidence.policy.detail });
  }
  if (evidence.anchors.status === 'unresolved') {
    notes.push({ code: 'anchors_unresolved', detail: evidence.anchors.detail });
  }
  if (evidence.ledger.status === 'unanchored') {
    notes.push({ code: 'ledger_membership_unanchored', detail: evidence.ledger.detail });
  }

  return {
    scheme: SCHEME,
    model_version: MODEL_VERSION,
    dataset_sha256: DATASET_SHA256,
    labels_origin: LABELS_ORIGIN,
    probability: p,
    percent: Math.round(p * 100),
    meaning: MEANING,
    features: featureRecord(vector),
    evidence,
    absent,
    notes,
  };
}

// The documented held-out metrics, read straight from the committed artifact.
function metrics() {
  return JSON.parse(JSON.stringify(MODEL.metrics));
}

// ----- legacy document-quality heuristic (uncalibrated) -----
//
// Kept only for the audit-time lattice gates, which ask "is this document
// substantial enough to promote", not "how likely is its assurance claim".
// Never written as a probability and never shown without UNCALIBRATED.

function scoreSourceQuality(output) {
  const anchors = output.source_anchors || [];

  const external = anchors.filter(a =>
    a.uri &&
    !String(a.uri).startsWith('file://') &&
    a.span_hash
  );

  const resolved = external.filter(a =>
    a.resolved_metadata &&
    (a.resolved_metadata.title || a.resolved_metadata.publisher || a.resolved_metadata.source)
  );

  if (external.length === 0) return 4;       // local file only
  if (resolved.length === 0) return 12;      // external-looking but unresolved
  return Math.min(25, 15 + Math.round((resolved.length / external.length) * 10));
}

function scoreContentRichness(output) {
  const e = output.evidence || {};
  let score = 0;

  const words = e.word_count || 0;
  if (words >= 3000) score += 10;
  else if (words >= 1000) score += 7;
  else if (words >= 300) score += 4;
  else if (words >= 50) score += 2;

  if (e.has_resolved_external_metadata) score += 8;
  if (e.has_provenance_language) score += 4;
  if (e.has_proof_language) score += 3;

  return Math.min(25, score);
}

function scorePolicyCompliance(checks) {
  if (!checks || checks.length === 0) return 0;

  let total = 0;
  for (const c of checks) {
    if (c.result === 'pass') total += 25 / checks.length;
    else if (c.result === 'warn') total += 10 / checks.length;
  }

  return Math.round(total);
}

function scoreDocumentStructure(output) {
  const e = output.evidence || {};
  let score = 0;

  if (e.has_external_anchor) score += 8;
  if (e.has_provenance_language && e.has_proof_language) score += 5;

  const anchors = output.source_anchors || [];
  if (anchors.length >= 2) score += 4;
  else if (anchors.length === 1) score += 2;

  if (output.content_summary && output.content_summary.length > 50) score += 3;

  return Math.min(25, score);
}

function evidencePenalty(output) {
  const e = output.evidence || {};
  let penalty = 0;

  if (e.word_count && e.word_count < 20) penalty += 6;
  if (!e.has_external_anchor) penalty += 10;
  if (!e.has_provenance_language) penalty += 8;
  if (!e.has_proof_language) penalty += 6;
  if (e.has_adversarial_language) penalty += 25;
  if (e.has_self_ratification_language) penalty += 20;
  if (e.has_secret_pattern) penalty += 35;

  return penalty;
}

function documentQuality(session, output, policyChecks) {
  const components = {
    source_quality: scoreSourceQuality(output),
    content_richness: scoreContentRichness(output),
    policy_compliance: scorePolicyCompliance(policyChecks),
    document_structure: scoreDocumentStructure(output),
  };

  const raw = components.source_quality + components.content_richness +
    components.policy_compliance + components.document_structure;
  const penalty = evidencePenalty(output);

  return {
    value: Math.max(0, Math.min(100, raw - penalty)),
    scale: '0-100-heuristic',
    calibrated: false,
    status: 'UNCALIBRATED',
    note: 'Document-substance heuristic. Not a probability and not assurance evidence.',
    components,
    penalty,
    computed_at: new Date().toISOString(),
  };
}

module.exports = {
  SCHEME,
  MODEL_VERSION,
  MODEL,
  MEANING,
  metrics,
  probability,
  assess,
  documentQuality,
};

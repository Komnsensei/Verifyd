// Verifyd Reference Implementation v1.0 - VALF-1
// No external dependencies. Node.js 18+.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PolicyEngine = require('./policy.cjs');
const AuditChain = require('./audit-chain.cjs');
const TrustScoreCalculator = require('./trust-score.cjs');

const Canonical = require('./canonicalize.cjs');
const EngineTrace = require('./engine-trace.cjs');
const SecretScan = require('./secret-scan.cjs');
const FileType = require('./file-type.cjs');
const FolderManifest = require('./folder-manifest.cjs');
const LightExif = require('./light-exif.cjs');
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function uuid() { return crypto.randomUUID(); }

function canonicalJSON(obj, omitKeys) {
  return Canonical.canonicalJSON(obj, { omitKeys: omitKeys || [] });
}
function authenticatedSession(opts) {
  const session_id = uuid();
  const started_at = new Date().toISOString();
  const session_hash = sha256(session_id + opts.human_id + opts.agent_id + started_at);
  return {
    session_id,
    human_id: opts.human_id,
    agent_id: opts.agent_id,
    started_at,
    ended_at: null,
    session_hash,
  };
}

function sessionOutput(opts) {
  return {
    output_id: uuid(),
    session_id: opts.session_id,
    content_hash: sha256(opts.content),
    content_summary: opts.content.slice(0, 200),
    source_anchors: opts.source_anchors || [],
    confidence: opts.confidence || {
      value: 0.5,
      decay_function: 'exponential',
      decay_half_life_days: 30,
      scored_at: new Date().toISOString(),
    },
    produced_at: new Date().toISOString(),
  };
}

function ratificationEvent(opts) {
  return {
    ratified_by_human: {
      human_id: opts.session.human_id,
      signed_at: new Date().toISOString(),
      method: opts.human_method || 'passphrase',
    },
    ratified_by_agent: {
      agent_id: opts.session.agent_id,
      signed_at: new Date().toISOString(),
      completion_hash: sha256(opts.output.content_hash + opts.session.session_hash),
    },
    policy_passed: !!opts.policy_passed,
    trust_score_at_ratification: opts.trust_score_value,
  };
}

function buildReceipt(opts) {
  const receipt = {
    valf_version: '1.0',
    receipt_id: uuid(),
    session: opts.session,
    outputs: opts.outputs,
    policy_checks: opts.policy_checks,
    trust_score: opts.trust_score,
    ratification: opts.ratification,
    prev_hash: opts.prev_hash,
    external_anchors: [],
  };
  receipt.this_hash = sha256(canonicalJSON(receipt, ['this_hash']));
  return receipt;
}

function verifyChain(chain) {
  const errors = [];
  for (let i = 0; i < chain.length; i++) {
    const r = chain[i];
    const recomputed = sha256(canonicalJSON(r, ['this_hash']));
    if (recomputed !== r.this_hash) errors.push('receipt ' + i + ': this_hash mismatch');
    const expected_prev = i === 0 ? 'GENESIS' : chain[i - 1].this_hash;
    if (r.prev_hash !== expected_prev) errors.push('receipt ' + i + ': prev_hash mismatch');
  }
  return { valid: errors.length === 0, errors };
}

module.exports = {
  authenticatedSession,
  sessionOutput,
  ratificationEvent,
  buildReceipt,
  verifyChain,
  canonicalJSON,
  sha256,
  PolicyEngine,
  AuditChain,
  TrustScoreCalculator,
  Canonical,
  EngineTrace,
  SecretScan,
  FileType,
  FolderManifest,
  LightExif,
};
if (require.main === module) {
  const arg = process.argv[2];
  if (arg === '--demo') {
    require(path.join(__dirname, '..', 'examples', 'run-example.cjs'));
  } else {
    console.log('Verifyd v1.0 - VALF-1 reference implementation');
    console.log('Usage:');
    console.log('  node verifyd.cjs --demo       Run end-to-end example');
  }
}

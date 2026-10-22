// Verifyd assurance evidence - one owner for every verification check.
//
// Both the human-readable report (bin/verifyd.cjs) and the assurance score
// (engine/trust-score.cjs) read this object. The display may explain more than
// the scorer needs, but neither re-implements a check: a change to timestamp,
// inclusion, batch-root, witness-quorum or determination verification lands
// here and nowhere else.
//
// The evidence object records the raw material as well as the verdict:
//   signature     the Signing.open result (code, key id, checks, message)
//   time          token status, TSA analysis and CA error
//   inclusion     the Merkle proof verdict and record
//   batch         root signature, root time, identity checks, authenticated
//   witnesses     the Witness.assess result (counted, rejected, quorum)
//   determination the Determination.verify result and the parsed artifact
//
// Quorum comes from lattice-domains.json, the same configuration the display
// reads. It is not a constant here.

'use strict';

const path = require('path');

const Artifacts = require('./artifacts.cjs');
const Lattice = require('./lattice.cjs');
const Merkle = require('./merkle.cjs');
const Signing = require('./signing.cjs');
const TSA = require('./tsa.cjs');
const Witness = require('./witness.cjs');
const Determination = require('./determination.cjs');

function quorumRequired() {
  return Lattice.LATTICE.oversight_board.quorum_required;
}

function collectSignature(envelope, keyring) {
  try {
    return Signing.open(envelope, { dir: keyring });
  } catch (e) {
    return {
      ok: false,
      code: e.code || 'VERIFICATION_FAILED',
      message: e.message,
      key_id: null,
      signer_trusted: false,
      checks: {
        signature_present: !!(envelope && envelope.signature && envelope.signature.value),
        key_known: false,
        public_key_matches_keyring: false,
        signature_valid: false,
        receipt_hash_valid: false,
      },
    };
  }
}

// `domain` selects which signed payload the token covers: the receipt envelope
// by default, or the Merkle root with Merkle.ROOT_DOMAIN.
function collectTime(envelope, opts, domain) {
  const stored = envelope && envelope.timestamp && typeof envelope.timestamp === 'object'
    ? envelope.timestamp
    : null;
  if (!stored || typeof stored.token !== 'string' || stored.token.length === 0) {
    return { status: 'unattested', analysis: null, caError: null, recorded: stored };
  }

  const caPath = TSA.configuredCaPath(opts && opts.tsaCa);
  let roots = [];
  if (caPath) {
    try {
      roots = TSA.loadRoots(caPath);
    } catch (e) {
      return {
        status: 'invalid',
        analysis: null,
        caError: (e.code || e.message) + ': ' + e.message,
        recorded: stored,
      };
    }
  }

  let analysis;
  try {
    const expected = TSA.sha256(Signing.signingPayload(envelope, { domain }));
    analysis = TSA.verifyToken(Buffer.from(stored.token, 'base64'), expected, { roots });
  } catch (e) {
    return { status: 'invalid', analysis: null, caError: e.code || e.message, recorded: stored };
  }

  return { status: analysis.status, analysis, caError: null, recorded: stored };
}

function collectInclusion(envelope, payloadDigest) {
  const record = envelope && envelope.inclusion && typeof envelope.inclusion === 'object'
    ? envelope.inclusion
    : null;
  if (!record) {
    return { present: false, record: null, proofOk: false, reason: null, payloadDigest: payloadDigest || null };
  }
  let proof;
  try {
    proof = Merkle.verifyInclusion({
      index: record.leaf_index,
      size: record.tree_size,
      leafDigest: payloadDigest,
      path: record.path,
      root: record.root_hash,
    });
  } catch (e) {
    proof = { ok: false, reason: e.code || e.message };
  }
  return {
    present: true,
    record,
    proofOk: !!proof.ok,
    reason: proof.reason || null,
    payloadDigest: payloadDigest || null,
  };
}

// The root is authenticated only when its signature covers it, it names this
// batch, this proof, this tree size, and its own timestamp token (if present)
// is not invalid. The display and the score both read `authenticated`.
function collectBatch(batchPath, inclusion, keyring, opts) {
  if (!batchPath) {
    return {
      present: false,
      path: null,
      error: null,
      reason: 'no batch root supplied',
      authenticated: false,
      root: null,
      opened: null,
      rootTime: null,
    };
  }

  const file = path.resolve(batchPath);
  const record = {
    present: true,
    path: file,
    error: null,
    reason: null,
    authenticated: false,
    root: null,
    opened: null,
    rootTime: null,
  };

  const read = Artifacts.readJsonObject(file, {
    messages: {
      notFound: 'batch root not found',
      directory: 'batch root path is a directory',
      invalidJson: 'batch root is not valid JSON',
      notObject: 'batch root is not an object',
      readError: 'batch root could not be read',
    },
  });
  if (!read.ok) {
    record.error = read.message;
    record.reason = record.error;
    record.root = null;
    return record;
  }
  record.root = read.value;
  record.path = read.file;

  const root = record.root;
  if (typeof root.batch_id !== 'string' ||
      typeof root.root_hash !== 'string' ||
      typeof root.tree_size !== 'number') {
    record.error = 'batch root is missing required fields';
    record.reason = record.error;
    record.root = null;
    return record;
  }

  record.opened = Signing.open(root, { dir: keyring, domain: Merkle.ROOT_DOMAIN });
  record.rootTime = collectTime(root, opts, Merkle.ROOT_DOMAIN);
  const proof = inclusion.record;

  if (!inclusion.present) {
    record.reason = 'receipt carries no inclusion proof';
  } else if (String(root.batch_id) !== String(proof.batch_id)) {
    record.reason = 'batch_id mismatch: proof is from another batch';
  } else if (String(root.root_hash).toLowerCase() !== String(proof.root_hash).toLowerCase()) {
    record.reason = 'root mismatch';
  } else if (String(root.tree_size) !== String(proof.tree_size)) {
    record.reason = 'tree size mismatch';
  } else if (!record.opened.ok) {
    record.reason = 'root signature ' + record.opened.code;
  } else if (!inclusion.proofOk) {
    record.reason = 'inclusion proof ' + (inclusion.reason || 'invalid');
  } else if (record.rootTime.status === 'invalid') {
    record.reason = 'root timestamp token invalid';
  } else {
    record.authenticated = true;
    record.reason = 'root signature and batch identity match';
  }

  return record;
}

async function collectWitnesses(envelope, witnessKeys) {
  return Witness.assess(envelope, {
    keyring: witnessKeys || null,
    required: quorumRequired(),
  });
}

function collectDetermination(envelope, opts) {
  if (!opts || !opts.determination) {
    return { requested: false, file: null, det: null, result: null, error: null };
  }

  const file = path.resolve(opts.determination);
  const record = { requested: true, file, det: null, result: null, error: null };

  const read = Artifacts.readJsonObject(file, {
    messages: {
      notFound: 'determination file not found',
      directory: 'determination path is a directory',
      invalidJson: 'determination is not valid JSON',
      notObject: 'determination is not a JSON object',
      readError: 'determination could not be read',
    },
  });
  if (!read.ok) {
    record.error = read.message;
    return record;
  }
  record.det = read.value;

  const reviewerKeyring = opts.reviewerKeyring || opts.keyring || Signing.defaultKeyringDir();
  try {
    record.result = Determination.verify(record.det, {
      receipt: envelope,
      dir: reviewerKeyring,
      now: opts.now,
    });
  } catch (e) {
    record.error = e.code || e.message;
  }
  return record;
}

// The one place that turns the evidence pass into a pass/fail verdict. verify
// uses this to set Status; certify uses the same call so a certificate can
// never print a stronger outcome than verify would.
function witnessVerdict(envelope, evidence) {
  const latticeStatus = envelope && envelope.receipt && envelope.receipt.lattice
    ? envelope.receipt.lattice.status
    : null;
  if (latticeStatus !== 'RATIFIED') return { ok: true, reason: null };

  const attestations = envelope && Array.isArray(envelope.attestations) ? envelope.attestations : [];
  if (attestations.length === 0) {
    return { ok: false, reason: 'RATIFIED claimed with no witness attestations' };
  }

  const assessment = evidence && evidence.witnesses;
  if (!assessment || !assessment.assessed) {
    return { ok: false, reason: 'RATIFIED claim cannot be checked without a witness keyring (--witness-keys)' };
  }
  const q = assessment.quorum;
  if (!q || !q.met) {
    const counted = q ? q.counted : 0;
    const required = q ? q.required : evidence.quorumRequired;
    return { ok: false, reason: 'RATIFIED claim is not backed by quorum (' + counted + '/' + required + ')' };
  }
  return { ok: true, reason: null };
}

function determinationVerdict(evidence) {
  const record = evidence && evidence.determination;
  if (!record || !record.requested) return { ok: true, reason: null };
  if (record.error) return { ok: false, reason: record.error };
  if (!record.result) return { ok: false, reason: 'determination could not be checked' };
  if (!record.result.ok) {
    return {
      ok: false,
      reason: (record.result.reasons || []).join('; ') || 'determination is not compliant',
    };
  }
  return { ok: true, reason: null };
}

function verdict(envelope, evidence) {
  const reasons = [];
  const signature = evidence && evidence.signature;
  if (!signature || !signature.ok) {
    reasons.push((signature && signature.message) || 'signature is not valid');
  }

  const time = evidence && evidence.time;
  if (time && time.status === 'invalid') {
    reasons.push(time.caError ||
      (time.analysis && (time.analysis.reasons || []).join(', ')) ||
      'timestamp token could not be verified');
  }

  const inclusion = evidence && evidence.inclusion;
  if (inclusion && inclusion.present && !inclusion.proofOk) {
    reasons.push('inclusion proof ' + (inclusion.reason || 'is invalid'));
  }

  const batch = evidence && evidence.batch;
  if (batch && batch.present && !batch.authenticated) {
    reasons.push(batch.error || batch.reason || 'batch root is not authenticated');
  }

  const witnesses = witnessVerdict(envelope, evidence);
  if (!witnesses.ok) reasons.push(witnesses.reason);

  const determination = determinationVerdict(evidence);
  if (!determination.ok) reasons.push(determination.reason);

  return { ok: reasons.length === 0, reasons };
}

async function collect(envelope, opts) {
  opts = opts || {};
  const keyring = path.resolve(opts.keyring || Signing.defaultKeyringDir());

  let payloadDigest = null;
  try {
    payloadDigest = TSA.sha256(Signing.signingPayload(envelope || {}));
  } catch (_) {
    payloadDigest = null;
  }

  const inclusion = collectInclusion(envelope || {}, payloadDigest);
  const evidence = {
    envelope: envelope || null,
    keyring,
    quorumRequired: quorumRequired(),
    payloadDigest,
    signature: collectSignature(envelope || {}, keyring),
    time: collectTime(envelope, opts),
    inclusion,
    batch: collectBatch(opts.batch, inclusion, keyring, opts),
    witnesses: await collectWitnesses(envelope, opts.witnessKeys),
    determination: collectDetermination(envelope, opts),
  };
  return evidence;
}

module.exports = {
  collect,
  quorumRequired,
  verdict,
  witnessVerdict,
  determinationVerdict,
};

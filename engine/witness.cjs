// Verifyd witness identity proofing - verifyd-witness-v1
// Zero dependencies. Reuses engine/signing.cjs keyrings and Ed25519 code.
//
// WHY THIS EXISTS
//   The lattice counted quorum over `witness_id` strings, so one party could
//   type four names and pass as four witnesses. Quorum here is counted over
//   independently verified keys and identities, never over labels alone.
//
// BINDING
//   An attestation signs a canonical, domain-separated payload that contains
//   the SHA-256 of the receipt's signed bytes (Signing.signingPayload). Attach
//   it to a different receipt and the digest no longer matches; that is a
//   rejection, not a warning. Attestations live in `envelope.attestations`,
//   which Signing.signingPayload omits, so adding or removing one never changes
//   what the receipt signature covers and never breaks signing, batching or
//   timestamping.
//
// TIERS (what each one actually proves)
//   label   (tier 0) - the attestation is signed, but carries no identity proof
//                      material. Proves only that a key holder typed a label.
//                      REJECTED for quorum: `label_only`.
//   key     (tier 1) - the attestation is signed and names a controlled
//                      resource (https:// or file://) whose exact bytes are
//                      committed in the attestation and which publish the line
//                      `verifyd-witness: <key_id> <identity>`. Proves the
//                      holder of that key can write to that resource now, and
//                      that the key id and label appear together there. It does
//                      NOT prove the resource owner is the natural person the
//                      label names, only that whoever controls the resource
//                      publishes this key/label binding.
//   vouched (tier 2) - tier 1 plus a second, different key (never the witness
//                      key and never the audited party's key) signs a voucher
//                      binding the witness key id to the identity. Proves a
//                      second trusted key asserts the binding. Whether that
//                      assertion is worth anything depends entirely on who owns
//                      the voucher key; the verifier's keyring decides that.
//
// WHAT NO TIER PROVES
//   - That the witness was honest, independent in interest, or competent.
//   - That the witness actually read the document; an attestation says what it
//     says, nothing more.
//   - That the resource hosting the proof was not later altered; the
//     attestation commits to the bytes as fetched, not to their future.
//   - That the receipt is true. Ratification records who attested, not truth.
//
// HONEST FAILURES
//   Missing proof material, an unreachable resource, a voucher key the verifier
//   does not hold, a missing witness keyring: each is reported with its own
//   reason and counted as nothing. No branch assumes the best case.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');

const Signing = require('./signing.cjs');

const SCHEME = 'verifyd-witness-v1';
const VOUCH_SCHEME = 'verifyd-witness-voucher-v1';
const ATTESTATION_DOMAIN = 'verifyd-witness-attestation-v1\n';
const VOUCH_DOMAIN = 'verifyd-witness-voucher-v1\n';
const PROOF_LINE_PREFIX = 'verifyd-witness:';
const TIERS = { label: 0, key: 1, vouched: 2 };
const MIN_COUNTED_TIER = 'key';
const IDENTITY_RE = /^[A-Za-z0-9][A-Za-z0-9._@:/-]{0,199}$/;
const HEX64_RE = /^[0-9a-f]{64}$/i;
const MAX_RESOURCE_BYTES = 64 * 1024;
const RESOURCE_TIMEOUT_MS = 5000;

function sha256hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function receiptDigest(envelope) {
  return sha256hex(Signing.signingPayload(envelope));
}

function bindingLine(keyId, identity) {
  return PROOF_LINE_PREFIX + ' ' + keyId + ' ' + identity;
}

function proofBinds(content, keyId, identity) {
  const text = Buffer.isBuffer(content) ? content.toString('utf8') : String(content);
  const wanted = bindingLine(keyId, identity);
  return text.split(/\r?\n/).some(line => line.trim() === wanted);
}

// ----- Attestation / voucher payloads -----

function attestationSubject(att) {
  return {
    scheme: SCHEME,
    attestation_id: att.attestation_id,
    identity: att.identity,
    witness_key_id: att.witness_key_id,
    receipt_digest: att.receipt_digest,
    attested_at: att.attested_at,
    statement: att.statement || '',
    // A signed attestation with no proof material is still a valid signature
    // over a self-asserted label. It is signed as `proof: null` so verification
    // can recompute the same bytes and then reject it as label_only.
    proof: att.proof
      ? { kind: att.proof.kind, uri: att.proof.uri, content_sha256: att.proof.content_sha256 }
      : null,
  };
}

function voucherSubject(v) {
  return {
    scheme: VOUCH_SCHEME,
    witness_key_id: v.witness_key_id,
    identity: v.identity,
    receipt_digest: v.receipt_digest,
    method: v.method || '',
    issued_at: v.issued_at,
    statement: v.statement || '',
  };
}

// ----- Resource reading -----

function readFileResource(file) {
  let stat;
  try {
    stat = fs.statSync(file);
  } catch (e) {
    return { ok: false, reason: 'resource_missing', detail: e.code || e.message };
  }
  if (!stat.isFile()) return { ok: false, reason: 'resource_not_a_file', detail: file };
  if (stat.size > MAX_RESOURCE_BYTES) {
    return { ok: false, reason: 'resource_too_large', detail: stat.size + ' bytes' };
  }
  try {
    return { ok: true, content: fs.readFileSync(file) };
  } catch (e) {
    return { ok: false, reason: 'resource_unreadable', detail: e.code || e.message };
  }
}

function readNetworkResource(target) {
  const client = target.protocol === 'http:' ? require('http') : require('https');
  return new Promise(resolve => {
    let settled = false;
    const done = value => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    let req;
    try {
      req = client.get(target, res => {
        if (res.statusCode >= 300 && res.statusCode < 400) {
          res.resume();
          return done({ ok: false, reason: 'resource_redirected', detail: 'status ' + res.statusCode });
        }
        if (res.statusCode !== 200) {
          res.resume();
          return done({ ok: false, reason: 'resource_http_status', detail: String(res.statusCode) });
        }
        const chunks = [];
        let total = 0;
        res.on('data', chunk => {
          total += chunk.length;
          if (total > MAX_RESOURCE_BYTES) {
            res.destroy();
            return done({ ok: false, reason: 'resource_too_large', detail: total + ' bytes' });
          }
          chunks.push(chunk);
        });
        res.on('end', () => done({ ok: true, content: Buffer.concat(chunks) }));
        res.on('error', e => done({ ok: false, reason: 'resource_unreachable', detail: e.code || e.message }));
      });
      req.setTimeout(RESOURCE_TIMEOUT_MS, () => {
        req.destroy();
        done({ ok: false, reason: 'resource_timeout', detail: 'no answer in ' + RESOURCE_TIMEOUT_MS + 'ms' });
      });
      req.on('error', e => done({ ok: false, reason: 'resource_unreachable', detail: e.code || e.message }));
    } catch (e) {
      done({ ok: false, reason: 'resource_invalid_uri', detail: e.message });
    }
  });
}

function parseUri(uri) {
  if (typeof uri !== 'string' || uri.length === 0) {
    return { ok: false, reason: 'resource_invalid_uri', detail: 'missing uri' };
  }
  if (/^[A-Za-z]:[\\/]/.test(uri) || uri.startsWith('\\\\')) {
    return { ok: true, file: path.resolve(uri) };
  }
  let parsed;
  try {
    parsed = new URL(uri);
  } catch (e) {
    return { ok: false, reason: 'resource_invalid_uri', detail: e.message };
  }
  if (parsed.protocol === 'file:') {
    try {
      return { ok: true, file: url.fileURLToPath(parsed) };
    } catch (e) {
      return { ok: false, reason: 'resource_invalid_uri', detail: e.message };
    }
  }
  if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
    return { ok: true, target: parsed };
  }
  return { ok: false, reason: 'resource_unsupported_scheme', detail: parsed.protocol };
}

async function loadResource(uri) {
  const parsed = parseUri(uri);
  if (!parsed.ok) return parsed;
  if (parsed.file) return readFileResource(parsed.file);
  return readNetworkResource(parsed.target);
}

// ----- Creating attestations -----

function currentKeyId(opts) {
  const dir = path.resolve(opts.dir);
  const key = Signing.activeKeyId({ dir });
  if (!key) {
    const e = new Error('no active key in witness keyring ' + dir);
    e.code = 'NO_WITNESS_KEY';
    throw e;
  }
  return key;
}

function attest(envelope, opts) {
  opts = opts || {};
  if (!opts.dir) {
    const e = new Error('attest needs a witness keyring dir');
    e.code = 'NO_WITNESS_KEY';
    throw e;
  }
  if (!IDENTITY_RE.test(String(opts.identity || ''))) {
    const e = new Error('identity must be a non-empty token (letters, digits, ._@:/-)');
    e.code = 'INVALID_IDENTITY';
    throw e;
  }
  if (!envelope || typeof envelope !== 'object') {
    const e = new Error('attest needs a receipt envelope');
    e.code = 'MALFORMED_RECEIPT';
    throw e;
  }

  const keyId = opts.keyId || currentKeyId(opts);
  const content = opts.proofContent !== undefined
    ? Buffer.from(opts.proofContent)
    : (opts.proofPath ? fs.readFileSync(opts.proofPath) : null);
  if (!content) {
    const e = new Error('attest needs proof material (proofContent or proofPath); a signature alone is label-only');
    e.code = 'NO_PROOF_MATERIAL';
    throw e;
  }
  const uri = opts.proofUri || (opts.proofPath ? url.pathToFileURL(path.resolve(opts.proofPath)).href : null);
  if (!uri) {
    const e = new Error('attest needs a proof uri: where the proof bytes are published');
    e.code = 'NO_PROOF_URI';
    throw e;
  }
  if (!proofBinds(content, keyId, opts.identity)) {
    const e = new Error('proof resource does not contain the line: ' + bindingLine(keyId, opts.identity));
    e.code = 'PROOF_DOES_NOT_BIND';
    throw e;
  }

  const att = {
    scheme: SCHEME,
    attestation_id: crypto.randomUUID(),
    identity: opts.identity,
    witness_key_id: keyId,
    receipt_digest: receiptDigest(envelope),
    attested_at: opts.attestedAt || new Date().toISOString(),
    statement: opts.statement || '',
    proof: {
      kind: 'resource',
      uri,
      content_sha256: sha256hex(content),
    },
  };
  const sealed = Signing.seal(attestationSubject(att), { dir: opts.dir, keyId, domain: ATTESTATION_DOMAIN });
  att.signature = sealed.signature;
  return att;
}

function attach(envelope, attestation) {
  if (!Array.isArray(envelope.attestations)) envelope.attestations = [];
  envelope.attestations.push(attestation);
  return envelope;
}

function vouch(envelope, attestation, opts) {
  opts = opts || {};
  if (!opts.dir) {
    const e = new Error('vouch needs a voucher keyring dir');
    e.code = 'NO_VOUCH_KEY';
    throw e;
  }
  if (!attestation || typeof attestation !== 'object' || !attestation.witness_key_id) {
    const e = new Error('vouch needs an attestation to vouch for');
    e.code = 'MALFORMED_ATTESTATION';
    throw e;
  }
  const keyId = opts.keyId || currentKeyId(opts);
  if (keyId === attestation.witness_key_id) {
    const e = new Error('a witness cannot vouch for itself');
    e.code = 'VOUCH_IS_WITNESS';
    throw e;
  }
  const subject = {
    scheme: VOUCH_SCHEME,
    witness_key_id: attestation.witness_key_id,
    identity: attestation.identity,
    receipt_digest: receiptDigest(envelope),
    method: opts.method || 'manual',
    issued_at: opts.issuedAt || new Date().toISOString(),
    statement: opts.statement || '',
  };
  const sealed = Signing.seal(subject, { dir: opts.dir, keyId, domain: VOUCH_DOMAIN });
  attestation.vouch = Object.assign({}, subject, { signature: sealed.signature });
  return attestation;
}

// ----- Verification -----

function reject(entry, reason, detail) {
  entry.status = 'rejected';
  entry.reason = reason;
  entry.detail = detail || null;
  return entry;
}

function checkVoucher(envelope, att, entry, ctx) {
  const v = att.vouch;
  if (!v || typeof v !== 'object') {
    entry.vouch = { status: 'absent' };
    return;
  }
  const fail = (reason, detail) => {
    entry.vouch = { status: 'unverified', reason, detail: detail || null, key_id: v.signature && v.signature.key_id || null };
    ctx.notes.push({ code: 'voucher_unverified', identity: entry.identity, key_id: entry.key_id, reason });
  };

  if (v.scheme !== VOUCH_SCHEME) return fail('voucher_scheme_mismatch');
  if (!v.signature || !v.signature.value) return fail('voucher_unsigned');
  if (v.witness_key_id !== att.witness_key_id) return fail('voucher_targets_another_witness_key');
  if (v.identity !== att.identity) return fail('voucher_identity_mismatch');
  if (v.receipt_digest !== ctx.digest) return fail('voucher_wrong_receipt');
  const voucherKeyId = v.signature.key_id;
  if (!Signing.KEY_ID_RE.test(voucherKeyId || '')) return fail('voucher_invalid_key_id');
  if (voucherKeyId === att.witness_key_id) return fail('voucher_is_witness');
  if (ctx.subjectKey && voucherKeyId === ctx.subjectKey) return fail('voucher_is_audited_party');

  const record = ctx.keys.find(k => k.key_id === voucherKeyId);
  if (!record) return fail('voucher_key_unknown', 'add the voucher key to the witness keyring');
  if (record.status === 'revoked') return fail('voucher_key_revoked');
  if (record.status !== 'active' && record.status !== 'retired') return fail('voucher_key_untrusted_status', record.status);
  if (record.expires_at && ctx.referenceTime && Date.parse(ctx.referenceTime) > Date.parse(record.expires_at)) {
    return fail('voucher_key_expired', record.expires_at);
  }

  const opened = Signing.open(Object.assign({}, voucherSubject(v), { signature: v.signature }), {
    dir: ctx.dir,
    domain: VOUCH_DOMAIN,
  });
  if (!opened.ok) return fail('voucher_signature_invalid', opened.code);

  entry.tier = 'vouched';
  entry.vouch = { status: 'verified', key_id: voucherKeyId, method: v.method || null };
}

async function assess(envelope, opts) {
  opts = opts || {};
  const required = Number.isInteger(opts.required) && opts.required > 0 ? opts.required : 4;
  const digest = receiptDigest(envelope);
  const subjectKey = envelope && envelope.signature ? envelope.signature.key_id : null;
  const referenceTime = envelope && envelope.signed_at ? envelope.signed_at : null;
  const dir = opts.keyring ? path.resolve(opts.keyring) : null;

  const result = {
    scheme: SCHEME,
    subject_digest: digest,
    subject_key_id: subjectKey,
    required,
    required_tier: MIN_COUNTED_TIER,
    assessed: false,
    reason: null,
    quorum: { required, counted: 0, met: false },
    counted: [],
    rejected: [],
    conflicts: [],
    notes: [],
  };

  if (!dir) {
    result.reason = 'witness_keyring_missing';
    result.detail = 'no witness keyring configured; pass --witness-keys <dir> or set $VERIFYD_WITNESS_KEYS';
    return result;
  }
  if (!Signing.keyringExists(dir)) {
    result.reason = 'witness_keyring_not_found';
    result.detail = dir;
    return result;
  }

  let keys;
  try {
    keys = Signing.listKeys({ dir });
  } catch (e) {
    result.reason = e.code || 'WITNESS_KEYRING_ERROR';
    result.detail = e.message;
    return result;
  }

  const list = Array.isArray(envelope.attestations) ? envelope.attestations : [];
  result.assessed = true;
  if (list.length === 0) return result;

  const ctx = { dir, keys, digest, subjectKey, referenceTime, notes: result.notes };
  const accepted = [];

  for (const att of list) {
    const entry = {
      attestation_id: att && att.attestation_id || null,
      identity: att && typeof att.identity === 'string' ? att.identity : null,
      key_id: att && (att.witness_key_id || (att.signature && att.signature.key_id)) || null,
      tier: 'label',
      status: 'rejected',
      reason: null,
      detail: null,
      attested_at: att && att.attested_at || null,
      outcome: 'rejected',
    };

    if (!att || typeof att !== 'object' || Array.isArray(att)) {
      result.rejected.push(reject(entry, 'malformed'));
      continue;
    }
    if (att.scheme !== SCHEME) {
      result.rejected.push(reject(entry, 'unsupported_scheme', String(att.scheme)));
      continue;
    }
    if (!att.signature || !att.signature.value || !att.signature.key_id) {
      result.rejected.push(reject(entry, 'unsigned', 'an attestation without a signature proves nothing'));
      continue;
    }
    if (att.witness_key_id !== att.signature.key_id) {
      result.rejected.push(reject(entry, 'key_id_mismatch', 'claim key ' + att.witness_key_id + ' vs signature key ' + att.signature.key_id));
      continue;
    }
    if (!IDENTITY_RE.test(String(att.identity || ''))) {
      result.rejected.push(reject(entry, 'invalid_identity'));
      continue;
    }
    if (att.receipt_digest !== digest) {
      result.rejected.push(reject(entry, 'wrong_receipt', 'attestation is bound to another receipt (replay)'));
      continue;
    }
    if (subjectKey && att.witness_key_id === subjectKey) {
      result.rejected.push(reject(entry, 'self_witness', 'the audited party signed this receipt and cannot witness it'));
      continue;
    }

    const record = keys.find(k => k.key_id === att.witness_key_id);
    if (!record) {
      result.rejected.push(reject(entry, 'unknown_witness_key', 'register the key in the witness keyring'));
      continue;
    }
    if (record.status === 'revoked') {
      result.rejected.push(reject(entry, 'key_revoked', record.revoked_at || null));
      continue;
    }
    if (record.status !== 'active' && record.status !== 'retired') {
      result.rejected.push(reject(entry, 'key_untrusted_status', record.status));
      continue;
    }
    if (record.expires_at && referenceTime && Date.parse(referenceTime) > Date.parse(record.expires_at)) {
      result.rejected.push(reject(entry, 'key_expired', 'expired ' + record.expires_at + ' before receipt ' + referenceTime));
      continue;
    }

    const opened = Signing.open(Object.assign({}, attestationSubject(att), { signature: att.signature }), {
      dir,
      domain: ATTESTATION_DOMAIN,
    });
    if (!opened.ok) {
      result.rejected.push(reject(entry, 'signature_invalid', opened.code));
      continue;
    }

    if (!att.proof || typeof att.proof !== 'object') {
      result.rejected.push(reject(entry, 'label_only', 'signed, but carries no identity proof material'));
      continue;
    }
    if (att.proof.kind !== 'resource') {
      result.rejected.push(reject(entry, 'unsupported_proof', String(att.proof.kind)));
      continue;
    }
    if (!HEX64_RE.test(String(att.proof.content_sha256 || ''))) {
      result.rejected.push(reject(entry, 'malformed_proof', 'content_sha256 is not a SHA-256 hex digest'));
      continue;
    }
    const fetched = await loadResource(att.proof.uri);
    if (!fetched.ok) {
      result.rejected.push(reject(entry, 'proof_unavailable', fetched.reason + (fetched.detail ? ': ' + fetched.detail : '')));
      continue;
    }
    if (sha256hex(fetched.content) !== String(att.proof.content_sha256).toLowerCase()) {
      result.rejected.push(reject(entry, 'proof_mismatch', 'resource bytes do not match the attested hash'));
      continue;
    }
    if (!proofBinds(fetched.content, att.witness_key_id, att.identity)) {
      result.rejected.push(reject(entry, 'proof_no_binding', 'resource does not publish "' + bindingLine(att.witness_key_id, att.identity) + '"'));
      continue;
    }

    entry.status = 'counted';
    entry.outcome = 'counted';
    entry.tier = 'key';
    entry.proof = { kind: 'resource', uri: att.proof.uri, verified: true };
    checkVoucher(envelope, att, entry, ctx);
    accepted.push(entry);
  }

  // One vote per key. Same key under several labels is still one witness.
  const byKey = new Map();
  for (const entry of accepted) {
    const previous = byKey.get(entry.key_id);
    if (!previous) {
      entry.aliases = [];
      byKey.set(entry.key_id, entry);
      continue;
    }
    result.notes.push({
      code: 'duplicate_attestation',
      identity: entry.identity,
      key_id: entry.key_id,
      detail: 'the same key counted once',
    });
    if (entry.identity !== previous.identity) {
      previous.aliases.push(entry.identity);
      result.notes.push({
        code: 'same_key_multiple_labels',
        identity: entry.identity,
        key_id: entry.key_id,
        detail: 'key already counted as ' + previous.identity + '; extra label not counted',
      });
    }
    if (TIERS[entry.tier] > TIERS[previous.tier]) {
      previous.tier = entry.tier;
      if (entry.vouch) previous.vouch = entry.vouch;
    }
  }

  const counted = Array.from(byKey.values());

  // One vote per identity. Two keys claiming one label is a conflict, not two
  // witnesses: the identity counts once and the conflict is surfaced.
  const byIdentity = new Map();
  for (const entry of counted) {
    const group = byIdentity.get(entry.identity) || [];
    group.push(entry);
    byIdentity.set(entry.identity, group);
  }
  for (const [identity, group] of byIdentity) {
    if (group.length > 1) {
      result.conflicts.push({
        identity,
        key_ids: group.map(e => e.key_id),
        counted_as: 1,
        detail: 'multiple keys claim one identity; counted once',
      });
      result.notes.push({ code: 'label_conflict', identity, detail: 'keys: ' + group.map(e => e.key_id).join(', ') });
    }
  }

  result.counted = counted;
  result.quorum = {
    required,
    counted: byIdentity.size,
    met: byIdentity.size >= required,
  };
  return result;
}

module.exports = {
  SCHEME,
  VOUCH_SCHEME,
  ATTESTATION_DOMAIN,
  VOUCH_DOMAIN,
  TIERS,
  MIN_COUNTED_TIER,
  IDENTITY_RE,
  bindingLine,
  proofBinds,
  receiptDigest,
  attestationSubject,
  voucherSubject,
  loadResource,
  attest,
  attach,
  vouch,
  assess,
};

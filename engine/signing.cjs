// Verifyd signing and key management - VALF-1 Section 8.1
// Zero dependencies: Node built-in crypto only (Ed25519).
//
// WHAT A SIGNATURE PROVES
//   That whoever held the private key for `key_id` signed the exact canonical
//   bytes of this envelope, and that those bytes have not changed since.
//   It proves possession of a key, not honesty, diligence, or authorization.
//
// WHAT A SIGNATURE DOES NOT PROVE
//   - That the audited document is true, complete, or lawfully obtained.
//   - That the signer was entitled to sign: authorization is the verifier's
//     policy, expressed by which keys they put in their keyring.
//   - That `signed_at` is correct: it is the signer's clock, not a third-party
//     timestamp. Only an external timestamp authority can attest to time, and
//     engine/tsa.cjs is where that happens.
//   - That a receipt is unique or never replayed.
//
// KEYRING
//   Default directory: $VERIFYD_KEYRING or ~/.verifyd/keys
//   - <key-slug>.key      private key, PKCS#8 PEM, mode 0600 (POSIX)
//   - <key-slug>.pub.json public record, mode 0644
//   - active              key_id used for new signatures
//   Rotation keeps retired public keys, so receipts signed before a rotation
//   continue to verify. Verification trusts every key listed in the keyring;
//   a receipt signed by any other key is rejected as an unexpected signer.
//
// On Windows, Node cannot apply POSIX modes. The private key inherits the ACL
// of the user profile directory; protect that profile and do not copy the
// keyring to shared or synced storage.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const Artifacts = require('./artifacts.cjs');
const Canonical = require('./canonicalize.cjs');

const ALGORITHM = 'ed25519';
const DOMAIN = 'verifyd-receipt-v1\n';
const KEY_ID_RE = /^ed25519:[0-9a-f]{64}$/;
const ACTIVE_FILE = 'active';

function defaultKeyringDir() {
  return process.env.VERIFYD_KEYRING
    ? path.resolve(process.env.VERIFYD_KEYRING)
    : path.join(os.homedir(), '.verifyd', 'keys');
}

function fail(code, detail) {
  const e = new Error(detail || code);
  e.code = code;
  return e;
}

function fingerprintOfPublicKey(publicKeyObject) {
  const der = publicKeyObject.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

function fingerprintOfPem(publicPem) {
  return fingerprintOfPublicKey(crypto.createPublicKey(publicPem));
}

function keyIdFromPem(publicPem) {
  return ALGORITHM + ':' + fingerprintOfPem(publicPem);
}

function slugFor(keyId) {
  if (!KEY_ID_RE.test(keyId || '')) throw fail('INVALID_KEY_ID', 'malformed key id: ' + keyId);
  return keyId.replace(':', '-');
}

function normalizePem(pem) {
  return String(pem || '').replace(/\r\n/g, '\n').trim();
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(dir, 0o700); } catch (_) { /* Windows: inherited ACL */ }
}

function restrictFile(file) {
  try { fs.chmodSync(file, 0o600); } catch (_) { /* Windows: inherited ACL */ }
}

function writeAtomic(file, contents) {
  const tmp = file + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, contents);
  fs.renameSync(tmp, file);
}

function generateKeyPair() {
  const pair = crypto.generateKeyPairSync(ALGORITHM);
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const key_id = ALGORITHM + ':' + fingerprintOfPublicKey(pair.publicKey);
  return { key_id, publicPem, privatePem };
}

function keyringExists(dir) {
  try { return fs.statSync(dir).isDirectory(); } catch (_) { return false; }
}

function isEmptyDir(dir) {
  try { return keyringExists(dir) && fs.readdirSync(dir).length === 0; } catch (_) { return false; }
}

// Return the winning key id when an empty directory was claimed by another
// process; otherwise remove the empty directory so a fresh build can rename
// into place. A non-empty directory with no active key is never overwritten.
function clearEmptyKeyring(dir) {
  if (!isEmptyDir(dir)) return null;
  try {
    fs.rmdirSync(dir);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    const winner = activeKeyId({ dir });
    if (winner) return winner;
    throw fail('KEYRING_RACE', 'keyring changed while being created: ' + dir);
  }
  return null;
}

function createFreshKeyring(dir) {
  const parent = path.dirname(dir);
  const tmp = path.join(parent, '.verifyd-keys-' + process.pid + '-' + crypto.randomBytes(8).toString('hex'));
  fs.mkdirSync(parent, { recursive: true });
  fs.mkdirSync(tmp, { mode: 0o700 });
  try { fs.chmodSync(tmp, 0o700); } catch (_) { /* Windows: inherited ACL */ }

  let key;
  try {
    key = generateKeyPair();
    writeKeyRecord(tmp, key, 'active');
  } catch (e) {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) { /* best effort */ }
    throw e;
  }

  try {
    fs.renameSync(tmp, dir);
  } catch (e) {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) { /* best effort */ }
    if (keyringExists(dir)) {
      const winner = activeKeyId({ dir });
      if (winner) return { dir, key_id: winner, created: false };
      throw fail('KEYRING_RACE', 'keyring exists but has no readable active key: ' + dir);
    }
    throw e;
  }

  const slug = slugFor(key.key_id);
  return {
    dir,
    key_id: key.key_id,
    created: true,
    public_path: path.join(dir, slug + '.pub.json'),
    private_path: path.join(dir, slug + '.key'),
  };
}

function readActive(dir) {
  const file = path.join(dir, ACTIVE_FILE);
  try {
    const keyId = fs.readFileSync(file, 'utf8').trim();
    return KEY_ID_RE.test(keyId) ? keyId : null;
  } catch (_) {
    return null;
  }
}

function listKeys(opts) {
  const dir = path.resolve((opts && opts.dir) || defaultKeyringDir());
  if (!keyringExists(dir)) return [];
  const keys = [];
  for (const name of fs.readdirSync(dir).sort()) {
    if (!name.endsWith('.pub.json')) continue;
    let record;
    try {
      record = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
    } catch (e) {
      throw fail('KEYRING_CORRUPT', 'unreadable key record ' + name + ': ' + e.message);
    }
    if (!record || !record.key_id || !record.public_key_pem) {
      throw fail('KEYRING_CORRUPT', 'key record missing key_id or public_key_pem: ' + name);
    }
    keys.push({
      key_id: record.key_id,
      algorithm: record.algorithm || ALGORITHM,
      public_key_pem: record.public_key_pem,
      fingerprint: record.key_id.slice(ALGORITHM.length + 1),
      created_at: record.created_at || null,
      status: record.status || 'active',
      expires_at: record.expires_at || null,
      revoked_at: record.revoked_at || null,
      record_path: path.join(dir, name),
    });
  }
  const active = readActive(dir);
  return keys.map(k => Object.assign({}, k, { active: k.key_id === active }));
}

function activeKeyId(opts) {
  const dir = path.resolve((opts && opts.dir) || defaultKeyringDir());
  const explicit = readActive(dir);
  if (explicit) return explicit;
  const keys = listKeys({ dir }).filter(k => k.status === 'active');
  if (keys.length === 1) return keys[0].key_id;
  return null;
}

function writeKeyRecord(dir, key, status) {
  const slug = slugFor(key.key_id);
  const pubPath = path.join(dir, slug + '.pub.json');
  const keyPath = path.join(dir, slug + '.key');
  fs.writeFileSync(keyPath, key.privatePem, { mode: 0o600 });
  restrictFile(keyPath);
  const record = {
    key_id: key.key_id,
    algorithm: ALGORITHM,
    public_key_pem: key.publicPem,
    created_at: new Date().toISOString(),
    status: status || 'active',
  };
  fs.writeFileSync(pubPath, JSON.stringify(record, null, 2) + '\n', { mode: 0o644 });
  writeAtomic(path.join(dir, ACTIVE_FILE), key.key_id + '\n');
  return { key_id: key.key_id, public_path: pubPath, private_path: keyPath };
}

function createKey(opts) {
  const dir = path.resolve((opts && opts.dir) || defaultKeyringDir());
  // A missing or empty directory is a fresh keyring: build it in a sibling
  // temporary directory and rename it into place, so two creators cannot both
  // install a key. A rename is atomic; the loser reuses the winner or throws.
  if (!keyringExists(dir)) return createFreshKeyring(dir);
  if (isEmptyDir(dir)) {
    const winner = clearEmptyKeyring(dir);
    if (winner) return { dir, key_id: winner, created: false };
    return createFreshKeyring(dir);
  }

  ensureDir(dir);
  const key = generateKeyPair();
  for (const existing of listKeys({ dir })) {
    if (existing.status === 'active') setStatus(dir, existing.key_id, 'retired');
  }
  const written = writeKeyRecord(dir, key, 'active');
  return Object.assign({ dir, key_id: key.key_id, created_at: new Date().toISOString() }, written);
}

function setStatus(dir, keyId, status) {
  const slug = slugFor(keyId);
  const file = path.join(dir, slug + '.pub.json');
  const record = JSON.parse(fs.readFileSync(file, 'utf8'));
  record.status = status;
  record.updated_at = new Date().toISOString();
  fs.writeFileSync(file, JSON.stringify(record, null, 2) + '\n');
}

function ensureKeyring(opts) {
  const dir = path.resolve((opts && opts.dir) || defaultKeyringDir());
  const existing = activeKeyId({ dir });
  if (existing) return { dir, key_id: existing, created: false };

  if (keyringExists(dir)) {
    if (isEmptyDir(dir)) {
      const winner = clearEmptyKeyring(dir);
      if (winner) return { dir, key_id: winner, created: false };
    } else {
      throw fail('KEYRING_INCOMPLETE', 'keyring has no active key: ' + dir);
    }
  }

  return createFreshKeyring(dir);
}

function rotateKey(opts) {
  const dir = path.resolve((opts && opts.dir) || defaultKeyringDir());
  const previous = activeKeyId({ dir });
  ensureDir(dir);
  const created = createKey({ dir });
  return { dir, previous_key_id: previous, key_id: created.key_id };
}

function signingKey(opts) {
  const dir = path.resolve((opts && opts.dir) || defaultKeyringDir());
  const requested = opts && opts.keyId;
  const keyId = requested || activeKeyId({ dir });
  if (!keyId) throw fail('NO_SIGNING_KEY', 'no active key in keyring ' + dir);
  if (!KEY_ID_RE.test(keyId)) throw fail('INVALID_KEY_ID', 'malformed key id: ' + keyId);

  const known = listKeys({ dir }).find(k => k.key_id === keyId);
  if (!known) throw fail('UNKNOWN_SIGNING_KEY', 'key not in keyring ' + dir + ': ' + keyId);
  if (known.status !== 'active' && !(opts && opts.allowRetired)) {
    throw fail('KEY_NOT_ACTIVE', 'key is ' + known.status + '; rotate or select an active key: ' + keyId);
  }

  const keyFile = path.join(dir, slugFor(keyId) + '.key');
  if (!fs.existsSync(keyFile)) throw fail('PRIVATE_KEY_MISSING', 'private key file missing: ' + keyFile);
  const privatePem = fs.readFileSync(keyFile, 'utf8');
  return {
    key_id: keyId,
    public_key_pem: known.public_key_pem,
    privateKey: crypto.createPrivateKey(privatePem),
  };
}

// The signed payload is a single canonical document: the envelope with the
// `signature`, `timestamp`, `inclusion` and `attestations` members removed,
// prefixed with a protocol domain tag.
//
// `timestamp` is excluded because an RFC 3161 token covers the hash of these
// bytes; putting the token inside them would be circular. The token is bound
// instead by requiring its messageImprint to equal SHA-256 of this payload, so
// it cannot be moved between receipts. `inclusion` is excluded for the same
// reason: a Merkle proof is computed over the digest of these bytes after the
// receipt is signed, and attaching it must not change what was signed.
// `attestations` is excluded because each witness attestation signs these same
// bytes itself (see engine/witness.cjs); collecting signatures must not require
// re-signing the receipt, and must not invalidate its batch proof or token.
//
// `opts.domain` lets a caller sign a different object (the Merkle root) with
// its own domain tag, so a root can never be replayed as a receipt.
function signingPayload(envelope, opts) {
  const domain = (opts && opts.domain) || DOMAIN;
  return Buffer.from(domain + Canonical.canonicalJSON(envelope, { omitKeys: ['signature', 'timestamp', 'inclusion', 'attestations'] }), 'utf8');
}

function seal(envelope, opts) {
  const dir = path.resolve((opts && opts.dir) || defaultKeyringDir());
  const ensured = ensureKeyring({ dir });
  const key = signingKey({ dir, keyId: (opts && opts.keyId) || ensured.key_id });
  const payload = signingPayload(envelope, { domain: opts && opts.domain });
  const value = crypto.sign(null, payload, key.privateKey).toString('base64');
  return Object.assign({}, envelope, {
    signature: {
      algorithm: ALGORITHM,
      key_id: key.key_id,
      public_key: key.public_key_pem,
      value,
    },
  });
}

function result(ok, code, message, extra) {
  return Object.assign({
    ok,
    code,
    message,
    key_id: null,
    signer_trusted: false,
    checks: {
      signature_present: false,
      key_known: false,
      public_key_matches_keyring: false,
      signature_valid: false,
      receipt_hash_valid: false,
    },
  }, extra || {});
}

function open(envelope, opts) {
  if (!envelope || typeof envelope !== 'object') {
    return result(false, 'MALFORMED', 'receipt is not a JSON object');
  }

  const sig = envelope.signature;
  if (!sig || typeof sig !== 'object' || !sig.value || !sig.key_id) {
    return result(false, 'UNSIGNED', 'receipt has no signature');
  }
  if (sig.algorithm !== ALGORITHM) {
    return result(false, 'UNSUPPORTED_ALGORITHM', 'unsupported signature algorithm: ' + sig.algorithm, { key_id: sig.key_id || null });
  }
  if (!KEY_ID_RE.test(sig.key_id)) {
    return result(false, 'INVALID_KEY_ID', 'malformed key id: ' + sig.key_id);
  }

  const checks = {
    signature_present: true,
    key_known: false,
    public_key_matches_keyring: false,
    signature_valid: false,
    receipt_hash_valid: false,
  };

  const dir = path.resolve((opts && opts.dir) || defaultKeyringDir());
  let known;
  try {
    known = listKeys({ dir }).find(k => k.key_id === sig.key_id);
  } catch (e) {
    return result(false, e.code || 'KEYRING_ERROR', e.message, { key_id: sig.key_id, checks });
  }
  if (!known) {
    return result(false, 'UNTRUSTED_KEY', 'signer key is not in the keyring (' + dir + '): ' + sig.key_id, { key_id: sig.key_id, checks });
  }
  checks.key_known = true;

  if (known.status !== 'active' && known.status !== 'retired') {
    return result(false, 'UNTRUSTED_KEY', 'signer key status is ' + known.status + ': ' + sig.key_id, { key_id: sig.key_id, checks });
  }

  if (normalizePem(sig.public_key) !== normalizePem(known.public_key_pem)) {
    return result(false, 'PUBLIC_KEY_MISMATCH', 'embedded public key does not match the keyring record for ' + sig.key_id, { key_id: sig.key_id, checks });
  }
  checks.public_key_matches_keyring = true;

  let payload;
  try {
    payload = signingPayload(envelope, { domain: opts && opts.domain });
  } catch (e) {
    return result(false, e.code || 'CANONICALIZATION_FAILED', e.message, { key_id: sig.key_id, checks });
  }

  let signatureValid = false;
  try {
    signatureValid = crypto.verify(
      null,
      payload,
      crypto.createPublicKey(known.public_key_pem),
      Buffer.from(sig.value, 'base64')
    );
  } catch (_) {
    signatureValid = false;
  }
  if (!signatureValid) {
    return result(false, 'SIGNATURE_INVALID', 'signature does not match the receipt bytes', { key_id: sig.key_id, checks });
  }
  checks.signature_valid = true;

  const receipt = envelope.receipt;
  if (receipt && typeof receipt === 'object' && typeof receipt.this_hash === 'string') {
    const recomputed = crypto.createHash('sha256')
      .update(Canonical.canonicalJSON(receipt, { omitKeys: ['this_hash'] }))
      .digest('hex');
    if (recomputed !== receipt.this_hash) {
      return result(false, 'RECEIPT_HASH_MISMATCH', 'receipt.this_hash does not match the receipt body', { key_id: sig.key_id, checks });
    }
    checks.receipt_hash_valid = true;
  }

  return result(true, 'OK', 'signature and receipt hash are valid', {
    key_id: sig.key_id,
    signer_trusted: true,
    checks,
  });
}

function openFile(file, opts) {
  const read = Artifacts.readJsonObject(file, {
    messages: { notFound: 'receipt not found', directory: 'not a receipt file', notObject: 'not a receipt' },
  });
  if (!read.ok) throw fail(read.code, read.message);
  return { envelope: read.value, result: open(read.value, opts) };
}

module.exports = {
  ALGORITHM,
  DOMAIN,
  KEY_ID_RE,
  defaultKeyringDir,
  keyringExists,
  keyIdFromPem,
  fingerprintOfPem,
  listKeys,
  activeKeyId,
  ensureKeyring,
  createKey,
  rotateKey,
  signingKey,
  signingPayload,
  seal,
  open,
  openFile,
};

// Verifyd receipt ledger - frozen formats and canonical hashing (Phase A).
//
// This file is the byte-level contract and nothing else: domain-separation
// tags, the object shapes for entries, checkpoints, policies, cosignatures and
// publication statements, and the hashes and signing preimages over them.
// Editing anything that changes a preimage changes the scheme, and the pinned
// vectors in engine/test/ledger-format.test.cjs with it.
//
// LAYERS (dependency direction is down this list; nothing here requires them)
//   engine/ledger-format.cjs   this file: shapes, hashes, signing preimages
//   engine/ledger-store.cjs    lock, durable appends, state cache, one read model
//   engine/ledger-recovery.cjs fsck inspection and the one automatic repair
//   engine/ledger-verify.cjs   the local verification walk
//   engine/ledger.cjs          public entry point, re-exporting the four layers
//
// This module performs no I/O.
//
// WHAT THIS LEDGER DOES NOT DO
//   Per CHAIN-DESIGN.md section 14, the rest of the ledger is later phases:
//   - Phase C: receipt membership, consistency proofs, CLI verification.
//   - Phase D: writer authorization, witness quorum, key lifecycle.
//   - Phase E: external anchoring and publication to a real sink.
//   No code here writes a ledger block onto a receipt, and no receipt format
//   changed in Phase B. Every hash is arithmetic: producing one proves that
//   these bytes hash to this value, nothing more. Without a checkpoint signature
//   a verifier already trusts, it is not evidence that anything was recorded.
//
// CANONICAL FORM
//   RFC 8785 JCS via engine/canonicalize.cjs, with one added restriction: every
//   number in a ledger object must be a safe integer. Floats, NaN and Infinity
//   are refused with LEDGER_NON_INTEGER_NUMBER rather than rounded, because JCS
//   on floats is a cross-runtime hazard and no ledger field needs one.
//
//   That restriction applies to the objects defined here, not to receipts: a
//   receipt carries floats (confidence, document quality), it is hashed by the
//   receipt scheme, and the ledger only ever sees the resulting payload_digest.
//
// DOMAIN SEPARATION
//   Every preimage is exactly one tag followed by canonical bytes. A hash or
//   signature produced under one tag cannot be replayed as another, so a
//   checkpoint cannot be passed off as a receipt or as a batch root. The ten
//   tags are pinned byte-for-byte in engine/test/ledger-format.test.cjs; a
//   silent change to one of them is a test failure, not a refactor.
//
// STRUCTURE, NOT TRUST
//   A ledger block on a receipt is an unsigned claim, exactly like inclusion,
//   and nothing built here authenticates it. Only a checkpoint signature that a
//   verifier already trusts turns membership arithmetic into evidence.

'use strict';

const crypto = require('crypto');

const Canonical = require('./canonicalize.cjs');
const Merkle = require('./merkle.cjs');
const Signing = require('./signing.cjs');

const SCHEME = 'verifyd-ledger-v1';
const PUBLICATION_SCHEME = 'verifyd-chain-publication-v1';
const CHECKPOINT_TYPE = 'ledger';
const GENESIS = 'GENESIS';

const HASH_HEX_RE = /^[0-9a-f]{64}$/;
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

// The single registry of ledger domain tags. Every preimage in this scheme is
// one of these followed by canonical bytes, and nothing else is allowed to
// introduce an eleventh prefix without changing this table and its vectors.
const TAG = Object.freeze({
  RECEIPT: 'verifyd-receipt-v1\n',
  MERKLE_ROOT: 'verifyd-merkle-root-v1\n',
  ENTRY_HASH: 'verifyd-ledger-entry-v1\nhash\n',
  ENTRY_SIG: 'verifyd-ledger-entry-v1\nsig\n',
  CHECKPOINT_HASH: 'verifyd-chain-checkpoint-v1\nhash\n',
  CHECKPOINT_SIG: 'verifyd-chain-checkpoint-v1\nsig\n',
  POLICY: 'verifyd-ledger-policy-v1\n',
  COSIGN: 'verifyd-chain-cosign-v1\n',
  PUBLICATION: 'verifyd-chain-publication-v1\n',
  REVOCATION: 'verifyd-ledger-revocation-v1\n',
});

const TAG_REGISTRY = Object.freeze([
  { name: 'receipt', tag: TAG.RECEIPT, covers: 'receipt envelope signature (existing)' },
  { name: 'merkle_root', tag: TAG.MERKLE_ROOT, covers: 'batch root signature (existing)' },
  { name: 'entry_hash', tag: TAG.ENTRY_HASH, covers: 'entry hash' },
  { name: 'entry_sig', tag: TAG.ENTRY_SIG, covers: 'entry signature' },
  { name: 'checkpoint_hash', tag: TAG.CHECKPOINT_HASH, covers: 'checkpoint hash' },
  { name: 'checkpoint_sig', tag: TAG.CHECKPOINT_SIG, covers: 'checkpoint signature' },
  { name: 'policy', tag: TAG.POLICY, covers: 'genesis policy hash' },
  { name: 'cosign', tag: TAG.COSIGN, covers: 'witness cosignature' },
  { name: 'publication', tag: TAG.PUBLICATION, covers: 'publication statement' },
  { name: 'revocation', tag: TAG.REVOCATION, covers: 'admin-signed writer revocation' },
]);

function fail(code, detail) {
  const e = new Error(detail || code);
  e.code = code;
  return e;
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

// Walks the value before canonicalization so a float is refused by this scheme
// with its own code, rather than being stringified into whatever the runtime
// does with it. canonicalize.cjs still runs afterwards and keeps ownership of
// cycles, depth, size and unsupported types.
function assertIntegerNumbers(value, path, seen) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw fail('LEDGER_NON_INTEGER_NUMBER', path + ': ' + String(value));
    }
    return;
  }
  if (!value || typeof value !== 'object') return;

  seen = seen || new WeakSet();
  if (seen.has(value)) return;
  seen.add(value);

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      assertIntegerNumbers(value[i], path + '[' + i + ']', seen);
    }
  } else {
    for (const key of Object.keys(value)) {
      assertIntegerNumbers(value[key], path + '.' + key, seen);
    }
  }

  seen.delete(value);
}

function canonical(value, omitKeys) {
  assertIntegerNumbers(value, '$');
  return Canonical.canonicalJSON(value, { omitKeys: omitKeys || [] });
}

function preimage(tag, body, omitKeys) {
  return Buffer.from(tag + canonical(body, omitKeys), 'utf8');
}

function assertObject(doc, what) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw fail('LEDGER_MALFORMED', (what || 'object') + ' is not a JSON object');
  }
  return doc;
}

// Unknown scheme or version is refused, never best-effort parsed: a verifier
// that does not recognise the format cannot claim to have checked it.
function assertScheme(doc, what) {
  assertObject(doc, what);
  if (doc.scheme !== SCHEME) {
    throw fail('LEDGER_UNSUPPORTED', (what || 'object') + ' scheme is not ' + SCHEME + ': ' + String(doc.scheme));
  }
  return doc;
}

function assertPublicationScheme(doc) {
  assertObject(doc, 'publication statement');
  if (doc.scheme !== PUBLICATION_SCHEME) {
    throw fail('LEDGER_UNSUPPORTED', 'publication statement scheme is not ' + PUBLICATION_SCHEME + ': ' + String(doc.scheme));
  }
  return doc;
}

function requireHex(value, field) {
  if (typeof value !== 'string' || !HASH_HEX_RE.test(value)) {
    throw fail('LEDGER_MALFORMED', field + ' must be 64 lowercase hex characters');
  }
  return value;
}

function requireChainRef(value, field) {
  if (value === GENESIS) return GENESIS;
  return requireHex(value, field);
}

function requireInteger(value, field, min) {
  const floor = min === undefined ? 0 : min;
  // A float gets the numeric code wherever it appears, so a caller can tell
  // "this is not an integer" from "this is not a number at all".
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw fail('LEDGER_NON_INTEGER_NUMBER', field + ': ' + String(value));
  }
  if (!Number.isSafeInteger(value)) {
    throw fail('LEDGER_MALFORMED', field + ' must be a safe integer');
  }
  if (value < floor) throw fail('LEDGER_MALFORMED', field + ' must be >= ' + floor);
  return value;
}

function requireTimestamp(value, field) {
  if (typeof value !== 'string' || !ISO_UTC_RE.test(value) || Number.isNaN(Date.parse(value))) {
    throw fail('LEDGER_MALFORMED', field + ' must be an ISO 8601 UTC timestamp');
  }
  return value;
}

function requireKeyId(value, field) {
  if (typeof value !== 'string' || !Signing.KEY_ID_RE.test(value)) {
    throw fail('LEDGER_MALFORMED', field + ' must be an ed25519 key id');
  }
  return value;
}

function requireText(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throw fail('LEDGER_MALFORMED', field + ' must be a non-empty string');
  }
  return value;
}

function requireKeyList(value, field) {
  if (!Array.isArray(value)) throw fail('LEDGER_MALFORMED', field + ' must be an array of key ids');
  const keys = value.map((k, i) => requireKeyId(k, field + '[' + i + ']'));
  if (new Set(keys).size !== keys.length) throw fail('LEDGER_MALFORMED', field + ' contains a duplicate key id');
  return keys.slice().sort();
}

// Genesis tree root: SHA-256(0x02 || uint64be(0) || SHA-256("")).
//
// Merkle.buildTree refuses an empty leaf list, so this cannot be produced by
// calling it with []. It is built from the same exported primitives, which is
// why it cannot drift from the leaf/node rules the rest of the scheme uses.
function emptyRoot() {
  return Merkle.rootHash(0, Merkle.sha256(Buffer.alloc(0)));
}

// --- entries -------------------------------------------------------------

function entryBody(fields) {
  fields = assertObject(fields, 'entry fields');
  const seq = requireInteger(fields.seq, 'seq', 1);
  const prev = requireChainRef(fields.prev_entry_hash, 'prev_entry_hash');
  // In v1 an entry's seq equals the tree_size of the checkpoint that follows
  // it, so the first entry is seq 1 and names GENESIS. Anything else would
  // describe an entry that cannot be appended without a gap.
  if (seq === 1 && prev !== GENESIS) {
    throw fail('LEDGER_MALFORMED', 'seq 1 must name GENESIS as prev_entry_hash');
  }
  if (seq > 1 && prev === GENESIS) {
    throw fail('LEDGER_MALFORMED', 'only seq 1 may name GENESIS as prev_entry_hash');
  }
  return {
    scheme: SCHEME,
    ledger_id: requireHex(fields.ledger_id, 'ledger_id'),
    seq,
    payload_digest: requireHex(fields.payload_digest, 'payload_digest'),
    receipt_id: fields.receipt_id === undefined || fields.receipt_id === null
      ? null
      : requireText(fields.receipt_id, 'receipt_id'),
    recorded_at: requireTimestamp(fields.recorded_at, 'recorded_at'),
    writer_key_id: requireKeyId(fields.writer_key_id, 'writer_key_id'),
    prev_entry_hash: prev,
  };
}

function entryHashPreimage(entry) {
  assertScheme(entry, 'entry');
  return preimage(TAG.ENTRY_HASH, entry, ['entry_hash', 'signature']);
}

function entryHash(entry) {
  return sha256Hex(entryHashPreimage(entry));
}

function buildEntry(fields) {
  const body = entryBody(fields);
  return Object.assign({}, body, { entry_hash: entryHash(body) });
}

// The signature covers entry_hash as well, so the digest a writer signed and
// the digest a verifier recomputes are the same value under one preimage.
function entrySigningPayload(entry) {
  assertScheme(entry, 'entry');
  if (typeof entry.entry_hash !== 'string') {
    throw fail('LEDGER_MALFORMED', 'entry.entry_hash is required before signing');
  }
  return preimage(TAG.ENTRY_SIG, entry, ['signature']);
}

// --- checkpoints ---------------------------------------------------------

function checkpointBody(fields) {
  fields = assertObject(fields, 'checkpoint fields');
  const ledgerId = fields.ledger_id === GENESIS ? GENESIS : requireHex(fields.ledger_id, 'ledger_id');
  const treeSize = requireInteger(fields.tree_size, 'tree_size', 0);
  const rootHash = requireHex(fields.root_hash, 'root_hash');
  const createdAt = requireTimestamp(fields.created_at, 'created_at');
  const prev = requireChainRef(fields.prev_checkpoint_hash, 'prev_checkpoint_hash');
  const policyHash = requireHex(fields.policy_hash, 'policy_hash');

  // Genesis is the only size-0 checkpoint, and it is the only one whose id is
  // the GENESIS placeholder. A later checkpoint that carried it would claim to
  // be a second genesis for the same ledger.
  if (ledgerId === GENESIS) {
    if (treeSize !== 0) throw fail('LEDGER_MALFORMED', 'only the genesis checkpoint may carry ledger_id GENESIS');
    if (prev !== GENESIS) throw fail('LEDGER_MALFORMED', 'the genesis checkpoint must name GENESIS as prev_checkpoint_hash');
    if (rootHash !== emptyRoot().toString('hex')) {
      throw fail('LEDGER_MALFORMED', 'a size-0 checkpoint must carry the empty tree root');
    }
  } else {
    if (treeSize === 0) throw fail('LEDGER_MALFORMED', 'a size-0 checkpoint is the genesis checkpoint and carries ledger_id GENESIS');
    if (prev === GENESIS) {
      throw fail('LEDGER_MALFORMED', 'a checkpoint after genesis must name the previous checkpoint hash');
    }
  }

  return {
    scheme: SCHEME,
    checkpoint_type: CHECKPOINT_TYPE,
    ledger_id: ledgerId,
    tree_size: treeSize,
    root_hash: rootHash,
    created_at: createdAt,
    prev_checkpoint_hash: prev,
    policy_hash: policyHash,
  };
}

// Genesis is the only checkpoint with tree_size 0 and ledger_id "GENESIS".
// Its hash is what every later checkpoint and entry carries as ledger_id, so
// the id is content-bound to the genesis body and cannot be chosen freely.
// The placeholder keeps ledger_id out of its own preimage: deriving the id from
// the id would be circular.
function genesisBody(fields) {
  fields = assertObject(fields, 'genesis fields');
  return {
    scheme: SCHEME,
    checkpoint_type: CHECKPOINT_TYPE,
    ledger_id: GENESIS,
    tree_size: 0,
    root_hash: emptyRoot().toString('hex'),
    created_at: requireTimestamp(fields.created_at, 'created_at'),
    prev_checkpoint_hash: GENESIS,
    policy_hash: requireHex(fields.policy_hash, 'policy_hash'),
  };
}

// checkpoint_hash is excluded from its own preimage, exactly as entry_hash is:
// the digest cannot be an input to itself. It is covered by the signature
// preimage instead, so a verifier that recomputes the digest also holds what
// the writer signed.
function checkpointHashPreimage(checkpoint) {
  assertScheme(checkpoint, 'checkpoint');
  return preimage(TAG.CHECKPOINT_HASH, checkpoint, ['signature', 'checkpoint_hash']);
}

function checkpointHash(checkpoint) {
  return sha256Hex(checkpointHashPreimage(checkpoint));
}

function checkpointSigningPayload(checkpoint) {
  assertScheme(checkpoint, 'checkpoint');
  return preimage(TAG.CHECKPOINT_SIG, checkpoint, ['signature']);
}

function ledgerIdFromGenesis(genesis) {
  assertScheme(genesis, 'genesis checkpoint');
  if (genesis.ledger_id !== GENESIS || genesis.tree_size !== 0) {
    throw fail('LEDGER_MALFORMED', 'not a genesis checkpoint: ledger_id and tree_size must be GENESIS and 0');
  }
  return checkpointHash(genesis);
}

// --- genesis policy ------------------------------------------------------

// The policy body is committed by policy_hash inside genesis. Key lists are
// sorted so that two operators writing the same policy in a different order do
// not produce two ledger ids; duplicates are refused rather than collapsed.
// The witness_policy shape is fixed when genesis is created (Phase D), so it is
// canonicalized as given here rather than guessed at in Phase A.
function policyBody(fields) {
  fields = assertObject(fields, 'policy fields');
  if (fields.witness_policy !== undefined && fields.witness_policy !== null
      && (typeof fields.witness_policy !== 'object' || Array.isArray(fields.witness_policy))) {
    throw fail('LEDGER_MALFORMED', 'witness_policy must be a JSON object');
  }
  return {
    writer_keys: requireKeyList(fields.writer_keys, 'writer_keys'),
    admin_keys: requireKeyList(fields.admin_keys, 'admin_keys'),
    witness_policy: fields.witness_policy === undefined ? null : fields.witness_policy,
  };
}

function policyBytes(policy) {
  return preimage(TAG.POLICY, policyBody(policy));
}

function policyHash(policy) {
  return sha256Hex(policyBytes(policy));
}

// --- writer revocations --------------------------------------------------

// A revocation is an admin-signed statement that a writer key's authority ends
// at `revoked_at`. The record binds itself to the head it was issued against
// (`head_tree_size`, `head_checkpoint_hash`), so a verifier can check that
// `revoked_at` does not reach back behind records that already existed. That is
// what stops a revocation from retroactively invalidating written history.
function revocationBody(fields) {
  fields = assertObject(fields, 'revocation fields');
  return {
    scheme: SCHEME,
    ledger_id: requireHex(fields.ledger_id, 'ledger_id'),
    key_id: requireKeyId(fields.key_id, 'key_id'),
    revoked_at: requireTimestamp(fields.revoked_at, 'revoked_at'),
    recorded_at: requireTimestamp(fields.recorded_at, 'recorded_at'),
    head_tree_size: requireInteger(fields.head_tree_size, 'head_tree_size', 0),
    head_checkpoint_hash: requireHex(fields.head_checkpoint_hash, 'head_checkpoint_hash'),
    reason: fields.reason === undefined || fields.reason === null
      ? null
      : requireText(fields.reason, 'reason'),
  };
}

function revocationSigningPayload(record) {
  assertScheme(record, 'revocation');
  return preimage(TAG.REVOCATION, record, ['signature']);
}

function buildRevocation(fields) {
  return revocationBody(fields);
}

function signRevocation(record, signer) {
  return Object.assign({}, record, {
    signature: signatureObject(signer, revocationSigningPayload(record)),
  });
}

// A revocation is evidence only after the ledger itself records it. The
// commitment is an ordinary entry whose payload digest is the digest of the
// signed record and whose receipt_id carries this reserved prefix. The entry
// sits inside the Merkle tree and the checkpoint chain, so dropping the
// revocation file cannot drop the fact that a revocation existed: the entry
// remains and verification fails closed until the record is restored.
const REVOCATION_COMMITMENT_PREFIX = 'verifyd-revocation:v1:';

function revocationCommitmentDigest(record) {
  return sha256Hex(revocationSigningPayload(record));
}

// --- witness cosignatures ------------------------------------------------

// Binding ledger_id and checkpoint_hash is the replay defence: the same
// statement cannot be moved onto another head or another ledger.
function cosignStatement(fields) {
  fields = assertObject(fields, 'cosignature fields');
  return {
    scheme: SCHEME,
    ledger_id: requireHex(fields.ledger_id, 'ledger_id'),
    checkpoint_hash: requireHex(fields.checkpoint_hash, 'checkpoint_hash'),
    tree_size: requireInteger(fields.tree_size, 'tree_size', 0),
    root_hash: requireHex(fields.root_hash, 'root_hash'),
    witness_key_id: requireKeyId(fields.witness_key_id, 'witness_key_id'),
    identity: requireText(fields.identity, 'identity'),
    cosigned_at: requireTimestamp(fields.cosigned_at, 'cosigned_at'),
  };
}

function cosignSigningPayload(statement) {
  assertScheme(statement, 'cosignature statement');
  return preimage(TAG.COSIGN, statement);
}

function cosignDigest(statement) {
  return sha256Hex(cosignSigningPayload(statement));
}

// --- publication statements ---------------------------------------------

// Minimal by design: no receipt ids, no document names, no org_id. A published
// statement therefore reveals the ledger head, not what is in the ledger.
function publicationStatement(fields) {
  fields = assertObject(fields, 'publication fields');
  return {
    scheme: PUBLICATION_SCHEME,
    ledger_id: requireHex(fields.ledger_id, 'ledger_id'),
    tree_size: requireInteger(fields.tree_size, 'tree_size', 0),
    root_hash: requireHex(fields.root_hash, 'root_hash'),
    checkpoint_hash: requireHex(fields.checkpoint_hash, 'checkpoint_hash'),
  };
}

function publicationStatementBytes(statement) {
  assertPublicationScheme(statement);
  return preimage(TAG.PUBLICATION, statement);
}

function publicationStatementDigest(statement) {
  return sha256Hex(publicationStatementBytes(statement));
}

// --- signing adapters ----------------------------------------------------

function normalizeSigner(signer) {
  assertObject(signer, 'signer');
  const keyId = requireKeyId(signer.key_id, 'signer.key_id');
  if (typeof signer.sign !== 'function') {
    throw fail('LEDGER_MALFORMED', 'signer.sign must be a function');
  }
  return { key_id: keyId, public_key: signer.public_key || null, sign: signer.sign };
}

// Wraps an existing keyring key. No new crypto: the same Ed25519 primitive and
// the same key files the receipt path uses, over a different domain tag.
function keyringSigner(opts) {
  const dir = (opts && opts.dir) || Signing.defaultKeyringDir();
  const key = Signing.signingKey({ dir, keyId: opts && opts.keyId });
  return {
    key_id: key.key_id,
    public_key: key.public_key_pem,
    // The write path re-reads this keyring before appending, so a signer made
    // here describes where its current status can be established.
    keyring: dir,
    sign(payload) {
      return crypto.sign(null, payload, key.privateKey).toString('base64');
    },
  };
}

function signatureObject(signer, preimage) {
  const value = signer.sign(preimage);
  if (typeof value !== 'string' || value.length === 0) {
    throw fail('LEDGER_MALFORMED', 'signer returned no signature value');
  }
  const signature = { algorithm: 'ed25519', key_id: signer.key_id, value };
  if (signer.public_key) signature.public_key = signer.public_key;
  return signature;
}

function signEntry(entry, signer) {
  if (entry.writer_key_id !== signer.key_id) {
    throw fail('LEDGER_MALFORMED', 'entry.writer_key_id must name the signing key');
  }
  return Object.assign({}, entry, { signature: signatureObject(signer, entrySigningPayload(entry)) });
}

function signCheckpoint(checkpoint, signer) {
  return Object.assign({}, checkpoint, { signature: signatureObject(signer, checkpointSigningPayload(checkpoint)) });
}

function buildCheckpoint(fields) {
  const body = checkpointBody(fields);
  return Object.assign({}, body, { checkpoint_hash: checkpointHash(body) });
}

function buildGenesis(fields) {
  const body = genesisBody(fields);
  return Object.assign({}, body, { checkpoint_hash: checkpointHash(body) });
}

function normalizePem(pem) {
  return String(pem || '').replace(/\r\n/g, '\n').trim();
}

function verifySignatureOf(kind, record, publicPem) {
  const signature = record && record.signature;
  if (!signature || signature.algorithm !== 'ed25519' || typeof signature.value !== 'string') return false;
  let preimage;
  try {
    preimage = kind === 'entry'
      ? entrySigningPayload(record)
      : kind === 'revocation'
        ? revocationSigningPayload(record)
        : checkpointSigningPayload(record);
  } catch (_) {
    return false;
  }
  try {
    return crypto.verify(null, preimage, crypto.createPublicKey(publicPem), Buffer.from(signature.value, 'base64'));
  } catch (_) {
    return false;
  }
}

module.exports = {
  SCHEME,
  PUBLICATION_SCHEME,
  CHECKPOINT_TYPE,
  GENESIS,
  TAG,
  TAG_REGISTRY,
  canonical,
  sha256Hex,
  emptyRoot,
  entryBody,
  buildEntry,
  entryHash,
  entryHashPreimage,
  entrySigningPayload,
  checkpointBody,
  genesisBody,
  buildCheckpoint,
  buildGenesis,
  signEntry,
  signCheckpoint,
  checkpointHash,
  checkpointHashPreimage,
  checkpointSigningPayload,
  ledgerIdFromGenesis,
  keyringSigner,
  signatureObject,
  normalizeSigner,
  normalizePem,
  verifySignatureOf,
  policyBody,
  policyBytes,
  policyHash,
  REVOCATION_COMMITMENT_PREFIX,
  revocationBody,
  buildRevocation,
  signRevocation,
  revocationSigningPayload,
  revocationCommitmentDigest,
  cosignStatement,
  cosignSigningPayload,
  cosignDigest,
  publicationStatement,
  publicationStatementBytes,
  publicationStatementDigest,
  assertScheme,
  assertPublicationScheme,
  // Lower-layer helpers the store needs to validate and seal records. They are
  // not part of the public surface (engine/ledger.cjs does not re-export them).
  fail,
  requireHex,
  requireText,
  requireInteger,
  requireKeyId,
  requireChainRef,
  assertObject,
};

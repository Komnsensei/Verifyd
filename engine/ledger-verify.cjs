// Verifyd receipt ledger - verification modes 1-3 (sections 6.1-6.4).
//
//   verifyLocal()    the full local walk: both chains, the counts, the prefix
//                    roots (one inspection), then signatures.
//   verifyReceipt()  receipt membership: does this receipt's unsigned ledger
//                    block prove into a checkpoint this verifier trusts?
//   verifyChain()    the local walk plus an anchor and/or retained heads: fork,
//                    rollback and prefix consistency between two heads.
//
// Anchors and witness cosignatures are later phases. An anchor supplied here is
// a checkpoint file the verifier was given; its absence is reported, never
// assumed. This file writes nothing, except the opt-in retained-heads append in
// verifyChain when the caller asks for it.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const Merkle = require('./merkle.cjs');
const Signing = require('./signing.cjs');
const Policy = require('./ledger-policy.cjs');
const {
  GENESIS,
  checkpointBody,
  normalizePem,
  verifySignatureOf,
} = require('./ledger-format.cjs');
const { ledgerPaths, readLedger } = require('./ledger-store.cjs');

const BLOCK_SCHEME = 'verifyd-ledger-v1';

function trustedKeyMap(opts) {
  const keys = new Map();
  const source = opts && opts.trustedKeys;
  if (source instanceof Map) {
    for (const [keyId, pem] of source) keys.set(keyId, pem);
  } else if (source && typeof source === 'object') {
    for (const keyId of Object.keys(source)) keys.set(keyId, source[keyId]);
  }
  if (opts && opts.keyring) {
    for (const key of Signing.listKeys({ dir: opts.keyring })) keys.set(key.key_id, key.public_key_pem);
  }
  return keys.size ? keys : null;
}

// A checkpoint is trusted only when its signature verifies under a key the
// caller supplied and the embedded public key matches that key. Returns null
// when trusted, or the failure to report.
function checkpointSignatureFailure(checkpoint, keys) {
  const signature = checkpoint && checkpoint.signature;
  if (!signature || typeof signature.key_id !== 'string') {
    return { code: 'LEDGER_SIGNATURE_INVALID', message: 'checkpoint carries no signature' };
  }
  const pem = keys.get(signature.key_id);
  if (!pem) {
    return { code: 'LEDGER_UNTRUSTED_KEY', message: 'checkpoint signed by a key outside the trusted set: ' + signature.key_id };
  }
  if (signature.public_key && normalizePem(signature.public_key) !== normalizePem(pem)) {
    return { code: 'LEDGER_SIGNATURE_INVALID', message: 'checkpoint embeds a public key that does not match the trusted key: ' + signature.key_id };
  }
  if (!verifySignatureOf('checkpoint', checkpoint, pem)) {
    return { code: 'LEDGER_SIGNATURE_INVALID', message: 'checkpoint ' + checkpoint.checkpoint_hash + ' signature does not match its bytes' };
  }
  return null;
}

// Section 6.1 steps 1-5. Anchors and cosignatures are later phases and are
// absent in Phase B logs; their absence is reported as not checked, never as a
// pass.
function verifyLocal(ledgerPath, opts) {
  opts = opts || {};
  const io = opts.fs || fs;
  const pathsOf = ledgerPaths(ledgerPath);
  const checks = [];
  const push = (name, ok, detail) => { checks.push({ name, ok, detail: detail || null }); return ok; };
  let read = null;
  let code = 'OK';
  let message = 'the ledger is internally consistent';
  let authorization = {
    ok: false,
    source: null,
    policy_hash: null,
    writers: 0,
    reason: 'not checked: signatures were not verified',
  };

  try {
    read = readLedger(pathsOf, io);
    push('structure', true, read.entries.length + ' entries, ' + read.checkpoints.length + ' checkpoints');
    push('checkpoint_chain', true, 'chained from genesis ' + read.ledgerId);

    const keys = trustedKeyMap(opts);
    if (!keys) {
      code = 'LEDGER_UNTRUSTED_KEY';
      message = 'signatures were not checked: no keyring or trusted key map was supplied';
      push('checkpoint_signatures', false, message);
      push('entry_signatures', false, message);
    } else {
      let failure = null;
      for (const checkpoint of read.checkpoints) {
        failure = checkpointSignatureFailure(checkpoint, keys);
        if (failure) break;
      }
      if (failure) {
        code = failure.code;
        message = failure.message;
        push('checkpoint_signatures', false, failure.message);
      } else {
        push('checkpoint_signatures', true, read.checkpoints.length + ' signatures verify under trusted keys');
      }

      failure = null;
      for (const entry of read.entries) {
        const signature = entry.signature;
        const pem = keys.get(signature.key_id);
        if (!pem) {
          failure = { code: 'LEDGER_UNTRUSTED_KEY', message: 'entry ' + entry.seq + ' is signed by a key outside the trusted set: ' + signature.key_id };
          break;
        }
        if (!verifySignatureOf('entry', entry, pem)) {
          failure = { code: 'LEDGER_SIGNATURE_INVALID', message: 'entry ' + entry.seq + ' signature does not match its bytes' };
          break;
        }
      }
      if (failure) {
        if (code === 'OK') { code = failure.code; message = failure.message; }
        push('entry_signatures', false, failure.message);
      } else {
        push('entry_signatures', true, read.entries.length + ' entry signatures verify under trusted keys');
      }

      // With every signature valid, authority is decided from the record: the
      // signing key must be a writer under the policy genesis committed to, and
      // a revoked or expired key status is judged at the record's own signed
      // timestamp. No wall clock and no state outside the log's own bytes.
      if (!failure) {
        let verdict;
        try {
          verdict = Policy.authorizeLedger(pathsOf, read, io, opts);
        } catch (e) {
          // A key source that cannot be read is still a named failure, not a
          // pass; the policy module leaves that error to its callers.
          verdict = {
            ok: false,
            code: e.code || 'LEDGER_POLICY_MISSING',
            message: e.message,
            source: null,
            policy_hash: null,
            writers: 0,
          };
        }
        if (!verdict.ok) {
          code = verdict.code;
          message = verdict.message;
        }
        authorization = {
          ok: verdict.ok,
          source: verdict.source,
          policy_hash: verdict.policy_hash,
          writers: verdict.writers,
          reason: verdict.ok ? null : verdict.message,
        };
      }
    }
  } catch (e) {
    code = e.code || 'LEDGER_CORRUPT';
    message = e.message;
  }

  const head = read ? {
    seq: read.entries.length,
    tree_size: read.head.tree_size,
    checkpoint_hash: read.head.checkpoint_hash,
    root_hash: read.head.root_hash,
  } : null;

  return { ok: code === 'OK' && checks.every(c => c.ok), code, message, checks, authorization, head, paths: pathsOf };
}

// --- receipt membership (section 6.2) -------------------------------------

function payloadDigestOf(receipt) {
  return crypto.createHash('sha256').update(Signing.signingPayload(receipt)).digest('hex');
}

function membershipResult(status, reason, extra) {
  return Object.assign({
    status,
    reason: reason || null,
    anchored: false,
    record: null,
    checkpoint: null,
  }, extra || {});
}

function validBlock(block) {
  if (!block || typeof block !== 'object') return 'ledger block is not an object';
  if (block.scheme !== BLOCK_SCHEME) return 'unsupported ledger block scheme: ' + block.scheme;
  if (typeof block.ledger_id !== 'string' || !/^[0-9a-f]{64}$/.test(block.ledger_id)) return 'ledger_id is not 64 lowercase hex characters';
  if (!Number.isSafeInteger(block.seq) || block.seq < 1) return 'seq is not a positive integer';
  const cp = block.checkpoint;
  if (!cp || typeof cp !== 'object') return 'ledger block has no checkpoint';
  if (!Number.isSafeInteger(cp.tree_size) || cp.tree_size < 1) return 'checkpoint tree_size is not a positive integer';
  if (cp.tree_size < block.seq) return 'checkpoint tree_size is smaller than seq';
  if (typeof cp.root_hash !== 'string' || !/^[0-9a-f]{64}$/.test(cp.root_hash)) return 'checkpoint root_hash is not 64 lowercase hex characters';
  if (!Array.isArray(block.path)) return 'ledger block path is not an array';
  for (const item of block.path) {
    if (typeof item !== 'string' || !/^[0-9a-f]{64}$/.test(item)) return 'ledger block path carries a malformed hash';
  }
  return null;
}

function readJson(file, what) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    const err = new Error(what + ' could not be read: ' + (e.code || e.message));
    err.code = 'LEDGER_ANCHOR_MISSING';
    throw err;
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (e) {
    const err = new Error(what + ' is not valid JSON: ' + e.message);
    err.code = 'LEDGER_ANCHOR_MALFORMED';
    throw err;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    const err = new Error(what + ' is not a JSON object');
    err.code = 'LEDGER_ANCHOR_MALFORMED';
    throw err;
  }
  return value;
}

// A checkpoint file the verifier was handed. Its signature must verify; its
// fields must be a valid checkpoint body. Returns the parsed record.
function readAnchor(file, keys) {
  const anchor = readJson(path.resolve(file), 'anchor checkpoint');
  checkpointBody(anchor);
  if (!keys) {
    const err = new Error('anchor checkpoint was not authenticated: no keyring or trusted key map was supplied');
    err.code = 'LEDGER_UNTRUSTED_KEY';
    throw err;
  }
  const failure = checkpointSignatureFailure(anchor, keys);
  if (failure) {
    const err = new Error(failure.message);
    err.code = failure.code;
    throw err;
  }
  return anchor;
}

// Does the receipt's unsigned ledger block prove into a checkpoint that this
// verifier trusts? The block is evidence only when a trusted checkpoint's root
// is the one the inclusion path recomputes. Without an anchor the checkpoint is
// authenticated by its signature and is otherwise unanchored.
function verifyReceipt(receipt, opts) {
  opts = opts || {};
  const record = receipt && receipt.ledger;

  if (!record) {
    return membershipResult('NOT RECORDED', 'receipt has no ledger block');
  }

  const malformed = validBlock(record);
  if (malformed) return membershipResult('NOT IN CHAIN', malformed, { record });

  let digest;
  try {
    digest = payloadDigestOf(receipt);
  } catch (e) {
    return membershipResult('NOT IN CHAIN', 'receipt bytes could not be canonicalized: ' + (e.code || e.message), { record });
  }

  const keys = trustedKeyMap(opts);
  let read;
  try {
    read = readLedger(ledgerPaths(opts.ledger), fs);
  } catch (e) {
    const status = (e.code === 'ENOENT' || /no checkpoint log/.test(e.message)) ? 'UNKNOWN LEDGER' : 'INCONSISTENT';
    return membershipResult(status, e.code || e.message, { record });
  }

  if (read.ledgerId !== record.ledger_id) {
    return membershipResult('UNKNOWN LEDGER', 'the ledger at this path is a different ledger (' + read.ledgerId + ')', { record });
  }

  if (read.entries.length < record.checkpoint.tree_size) {
    return membershipResult('NOT IN CHAIN', 'the ledger holds ' + read.entries.length
      + ' entries, fewer than the claimed tree size ' + record.checkpoint.tree_size, { record });
  }
  if (!read.entries[record.seq - 1] || read.entries[record.seq - 1].payload_digest !== digest) {
    return membershipResult('NOT IN CHAIN', 'seq ' + record.seq + ' does not hold this receipt digest', { record });
  }

  const checkpoint = read.checkpoints.find(c => c.tree_size === record.checkpoint.tree_size
    && c.root_hash === record.checkpoint.root_hash);
  if (!checkpoint) {
    return membershipResult('NOT IN CHAIN', 'no checkpoint at tree size ' + record.checkpoint.tree_size
      + ' carries root ' + record.checkpoint.root_hash, { record });
  }
  if (!keys) {
    return membershipResult('NOT IN CHAIN', 'checkpoint signature was not checked: no keyring or trusted key map was supplied', { record });
  }
  const failure = checkpointSignatureFailure(checkpoint, keys);
  if (failure) {
    return membershipResult('NOT IN CHAIN', failure.message, { record });
  }

  // A valid signature under a trusted key is not authority. The checkpoint's
  // signer must be a writer under the policy genesis committed to, or the proof
  // lands in a head nobody was entitled to publish. Membership authorizes one
  // checkpoint, not the whole ledger prefix; the local walk covers that.
  const authorized = Policy.authorizeRecord(ledgerPaths(opts.ledger), read, fs,
    { key: checkpoint.signature.key_id, at: checkpoint.created_at }, opts);
  if (!authorized.ok) {
    return membershipResult('NOT IN CHAIN', authorized.message, { record });
  }

  const proof = Merkle.verifyInclusion({
    index: record.seq - 1,
    size: record.checkpoint.tree_size,
    leafDigest: Buffer.from(digest, 'hex'),
    root: record.checkpoint.root_hash,
    path: record.path,
  });
  if (!proof.ok) {
    return membershipResult('NOT IN CHAIN', 'inclusion proof ' + (proof.reason || 'is invalid'), { record });
  }

  const landed = {
    record,
    checkpoint: {
      tree_size: checkpoint.tree_size,
      root_hash: checkpoint.root_hash,
      checkpoint_hash: checkpoint.checkpoint_hash,
    },
  };

  if (!opts.anchor) {
    return membershipResult('IN CHAIN', null, landed);
  }

  // The anchor is the checkpoint the verifier already trusts. Membership is
  // anchored when the proof lands in that checkpoint, or in a later checkpoint
  // the same ledger chains to it.
  let anchor;
  try {
    anchor = readAnchor(opts.anchor, keys);
  } catch (e) {
    return membershipResult('INCONSISTENT', e.message, Object.assign({ anchored: false }, landed));
  }
  if (anchor.ledger_id !== GENESIS && anchor.ledger_id !== record.ledger_id) {
    return membershipResult('INCONSISTENT', 'anchor names a different ledger', Object.assign({ anchored: false }, landed));
  }
  // A size-0 checkpoint is the genesis record, not a tree head: it commits to
  // an empty tree and says nothing about any history, so accepting it would
  // print ANCHORED for a ledger with no anchored position at all.
  if (anchor.tree_size < 1) {
    return membershipResult('INCONSISTENT', 'a size-0 checkpoint is not a tree head and cannot anchor membership',
      Object.assign({ anchored: false }, landed));
  }
  if (anchor.tree_size > record.checkpoint.tree_size) {
    return membershipResult('INCONSISTENT', 'anchor tree size ' + anchor.tree_size
      + ' is newer than the checkpoint the receipt proves (' + record.checkpoint.tree_size + ')',
      Object.assign({ anchored: false }, landed));
  }

  const atAnchor = read.checkpoints.find(c => c.tree_size === anchor.tree_size
    && c.checkpoint_hash === anchor.checkpoint_hash);
  if (!atAnchor) {
    return membershipResult('INCONSISTENT', 'the ledger has no checkpoint with the anchor hash at tree size ' + anchor.tree_size,
      Object.assign({ anchored: false }, landed));
  }
  if (atAnchor.root_hash !== anchor.root_hash) {
    return membershipResult('INCONSISTENT', 'the ledger root at tree size ' + anchor.tree_size + ' does not match the anchor',
      Object.assign({ anchored: false }, landed));
  }

  return membershipResult('IN CHAIN', null, Object.assign({ anchored: true }, landed));
}

// --- anchored incremental verification (sections 6.3, 6.4, 13.5) ----------

function digestBuffers(read) {
  return read.digests.map(hex => Buffer.from(hex, 'hex'));
}

function readHeads(file) {
  if (typeof file !== 'string' || file.length === 0) return [];
  const text = fs.readFileSync(path.resolve(file), 'utf8');
  const heads = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    let head;
    try {
      head = JSON.parse(line);
    } catch (e) {
      const err = new Error('retained head line ' + (i + 1) + ' is not valid JSON: ' + e.message);
      err.code = 'LEDGER_HEADS_MALFORMED';
      throw err;
    }
    if (!head || typeof head !== 'object' || !Number.isSafeInteger(head.tree_size)
        || typeof head.root_hash !== 'string' || typeof head.ledger_id !== 'string') {
      const err = new Error('retained head line ' + (i + 1) + ' is not a head record');
      err.code = 'LEDGER_HEADS_MALFORMED';
      throw err;
    }
    heads.push(head);
  }
  return heads;
}

function headOf(read) {
  return {
    ledger_id: read.ledgerId,
    tree_size: read.entries.length,
    root_hash: read.head.root_hash,
    checkpoint_hash: read.head.checkpoint_hash,
  };
}

// Section 6.1 plus the checks that need a second head: an anchor file the
// verifier was given, and retained heads from an append-only file. Fork rules
// are applied in order and the first failure names the code.
function verifyChain(ledgerPath, opts) {
  opts = opts || {};
  const local = verifyLocal(ledgerPath, opts);
  const result = Object.assign({}, local, {
    mode: opts.anchor ? 'anchored incremental' : 'full local',
    anchor: null,
    retained: null,
  });
  if (!local.ok) return result;

  const checks = local.checks;
  const io = opts.fs || fs;
  const read = readLedger(ledgerPaths(ledgerPath), io);
  const head = headOf(read);
  const keys = trustedKeyMap(opts);

  const fault = (code, message) => {
    checks.push({ name: 'heads', ok: false, detail: message });
    return Object.assign({}, result, { ok: false, code, message, checks });
  };

  if (opts.anchor) {
    let anchor;
    try {
      anchor = readAnchor(opts.anchor, keys);
    } catch (e) {
      return fault(e.code || 'LEDGER_ANCHOR_MALFORMED', e.message);
    }
    result.anchor = {
      tree_size: anchor.tree_size,
      root_hash: anchor.root_hash,
      checkpoint_hash: anchor.checkpoint_hash,
    };

    // Genesis is not a head. It proves the ledger exists, not that any history
    // was retained, so it cannot turn an unanchored walk into an anchored one.
    if (anchor.tree_size < 1) {
      return fault('LEDGER_INCONSISTENT', 'a size-0 checkpoint is not a tree head and cannot anchor a ledger');
    }

    if (anchor.tree_size > head.tree_size) {
      return fault('LEDGER_ROLLBACK', 'observed head is smaller than the anchor ('
        + head.tree_size + ' < ' + anchor.tree_size + ')');
    }

    const atAnchor = read.checkpoints.find(c => c.tree_size === anchor.tree_size);
    if (!atAnchor) {
      return fault('LEDGER_INCONSISTENT', 'the ledger has no checkpoint at the anchor tree size ' + anchor.tree_size);
    }
    if (atAnchor.root_hash !== anchor.root_hash) {
      return fault('LEDGER_FORK', 'the ledger root at tree size ' + anchor.tree_size + ' does not match the anchor');
    }
    if (atAnchor.checkpoint_hash !== anchor.checkpoint_hash) {
      return fault('LEDGER_FORK_EQUIVOCATION', 'two checkpoint hashes exist at tree size ' + anchor.tree_size);
    }

    // Prefix consistency from the anchored head to the observed head. The proof
    // is derived from the ledger's own entries, so a rewritten prefix cannot
    // reproduce the anchored root.
    const proof = Merkle.consistency(anchor.tree_size, digestBuffers(read));
    const verdict = Merkle.verifyConsistency({
      m: anchor.tree_size,
      n: head.tree_size,
      rootM: anchor.root_hash,
      rootN: head.root_hash,
      prefixMth: proof.prefix_mth,
      path: proof.path,
    });
    if (!verdict.ok) {
      return fault('LEDGER_FORK', 'no consistency proof from the anchor to the observed head: ' + verdict.reason);
    }
    checks.push({ name: 'anchor_consistency', ok: true, detail: 'tree size ' + anchor.tree_size + ' is a prefix of ' + head.tree_size });
  }

  if (opts.heads) {
    let retained;
    try {
      retained = readHeads(opts.heads);
    } catch (e) {
      return fault(e.code || 'LEDGER_HEADS_MALFORMED', e.message);
    }
    result.retained = retained.length;

    // A non-empty retained-heads file that knows nothing about the observed
    // ledger is evidence the local file was replaced (a new genesis changes the
    // ledger id), not an absence of evidence. Fail closed; a first run with no
    // retained head yet has an empty file and is unaffected.
    if (retained.length > 0 && !retained.some(old => old.ledger_id === head.ledger_id)) {
      return fault('LEDGER_UNKNOWN_LEDGER',
        'the retained heads belong to a different ledger (' + retained[0].ledger_id
        + '), not the one at this path (' + head.ledger_id + ')');
    }

    for (const old of retained) {
      if (old.ledger_id !== head.ledger_id) continue;
      if (old.tree_size === head.tree_size) {
        if (old.root_hash !== head.root_hash) {
          return fault('LEDGER_FORK', 'two roots at tree size ' + head.tree_size + ' for one ledger');
        }
        if (old.checkpoint_hash && old.checkpoint_hash !== head.checkpoint_hash) {
          return fault('LEDGER_FORK_EQUIVOCATION', 'two checkpoint hashes at tree size ' + head.tree_size);
        }
        continue;
      }
      if (old.tree_size > head.tree_size) {
        return fault('LEDGER_ROLLBACK', 'observed head is smaller than a retained head ('
          + head.tree_size + ' < ' + old.tree_size + ')');
      }
      const proof = Merkle.consistency(old.tree_size, digestBuffers(read));
      const verdict = Merkle.verifyConsistency({
        m: old.tree_size,
        n: head.tree_size,
        rootM: old.root_hash,
        rootN: head.root_hash,
        prefixMth: proof.prefix_mth,
        path: proof.path,
      });
      if (!verdict.ok) {
        return fault('LEDGER_FORK', 'no consistency proof from retained head at tree size ' + old.tree_size + ': ' + verdict.reason);
      }
    }
    checks.push({ name: 'retained_heads', ok: true, detail: retained.length + ' retained head(s) checked' });
  }

  // Recording is opt-in: verification is read-only unless the caller asked for
  // the head to be retained.
  if (opts.recordHead) {
    if (!opts.heads) {
      return fault('LEDGER_HEADS_REQUIRED', 'recording a head needs a retained-heads file');
    }
    fs.appendFileSync(path.resolve(opts.heads), JSON.stringify(head) + '\n');
    checks.push({ name: 'head_recorded', ok: true, detail: 'tree size ' + head.tree_size });
  }

  return Object.assign({}, result, { checks, head, ok: true, code: 'OK' });
}

module.exports = { verifyLocal, verifyReceipt, verifyChain, readAnchor };

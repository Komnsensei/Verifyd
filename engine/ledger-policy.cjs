// Verifyd receipt ledger - committed policy resolution and writer authority.
//
// Genesis commits to the writer/admin/witness policy by `policy_hash` only; it
// cannot carry the body, because the body's hash is what makes the ledger id.
// This layer carries the policy alongside the ledger as `<ledger>.policy.json`,
// and refuses any body whose hash is not the one genesis committed. The file is
// transport, not trust: swapping it for a different policy changes the hash and
// fails closed.
//
// Reference resolution is deliberately conservative:
//   - no policy file and no `opts.policy`  -> LEDGER_POLICY_MISSING
//   - body that does not hash to genesis   -> LEDGER_POLICY_MISMATCH
//   - key absent from `writer_keys`        -> LEDGER_POLICY_MISMATCH
//   - key record revoked/expired at the
//     record's own signed timestamp        -> LEDGER_KEY_NOT_ACTIVE
//   - a write whose signer has no readable
//     status record (`requireStatus`)      -> LEDGER_KEY_NOT_ACTIVE
//
// The timestamp used for status is the record's own `recorded_at`/`created_at`,
// so a verifier reaches the same verdict as the writer from the signed bytes
// plus the public key records, with no wall clock of its own. A `retired` key
// is not a compromised key: past signatures stay valid. A revocation that
// cannot be dated fails closed rather than being assumed harmless.
//
// Phase D2 is read here: revocation records (`<ledger>.revocations.jsonl`),
// their commitment seals, and the narrow repair authority for those seals.
// Checkpoint cosignatures and successor ledgers stay Phase D3-D4.

'use strict';

const Signing = require('./signing.cjs');
const {
  REVOCATION_COMMITMENT_PREFIX,
  fail,
  normalizePem,
  policyBody,
  policyHash,
  revocationBody,
  revocationCommitmentDigest,
  verifySignatureOf,
} = require('./ledger-format.cjs');

const POLICY_SUFFIX = '.policy.json';
const REVOCATION_SUFFIX = '.revocations.jsonl';

function policyPathFor(ledgerFile) {
  return ledgerFile + POLICY_SUFFIX;
}

function revocationPathFor(ledgerFile) {
  return ledgerFile + REVOCATION_SUFFIX;
}

function pathOf(pathsOf) {
  if (pathsOf && typeof pathsOf.policy === 'string') return pathsOf.policy;
  return policyPathFor(pathsOf.ledger);
}

function readPolicyBody(io, file) {
  let buf;
  try {
    buf = io.readFileSync(file);
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') {
      throw fail('LEDGER_POLICY_MISSING',
        'no policy file at ' + file + '; the policy committed by genesis cannot be resolved');
    }
    throw fail('LEDGER_IO', 'cannot read policy file ' + file + ': ' + (e.code || e.message));
  }

  let doc;
  try {
    doc = JSON.parse(Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf));
  } catch (e) {
    throw fail('LEDGER_MALFORMED', 'policy file is not valid JSON: ' + e.message);
  }
  try {
    return policyBody(doc);
  } catch (e) {
    throw fail(e.code || 'LEDGER_MALFORMED', 'policy file is not a policy body: ' + e.message);
  }
}

// The one place a policy becomes usable: the body must hash to the value inside
// genesis, whether it came from the sidecar or from the caller.
function resolvePolicy(pathsOf, genesis, io, opts) {
  const supplied = opts && opts.policy;
  const file = pathOf(pathsOf);
  const policy = supplied ? policyBody(supplied) : readPolicyBody(io, file);

  const committed = genesis && genesis.policy_hash;
  if (typeof committed !== 'string') {
    throw fail('LEDGER_MALFORMED', 'genesis carries no policy hash');
  }

  const actual = policyHash(policy);
  if (actual !== committed) {
    throw fail('LEDGER_POLICY_MISMATCH',
      'the policy ' + (supplied ? 'supplied by the caller' : 'at ' + file)
      + ' hashes to ' + actual + ', but genesis committed ' + committed);
  }

  return {
    policy,
    hash: actual,
    source: supplied ? 'supplied' : 'file',
    path: supplied ? null : file,
  };
}

// Called once, under the init lock, before the genesis line is written, so a
// ledger is never committed without the body its policy hash names.
function writePolicy(pathsOf, policy, io) {
  const file = pathOf(pathsOf);
  Signing.writeAtomic(file, JSON.stringify(policyBody(policy)) + '\n', { fs: io, fsync: true });
  return file;
}

// Public key records, when the caller named a keyring. A trusted key map alone
// carries no status, so authorization falls back to membership and says so.
function keyRecordsOf(opts) {
  if (!opts || !opts.keyring) return null;
  const records = new Map();
  for (const record of Signing.listKeys({ dir: opts.keyring })) {
    records.set(record.key_id, record);
  }
  return records;
}

// Shared by writers and admins: a keyring record is judged at the timestamp of
// the record it signed, never at the verifier's clock.
function keyStatusFailure(record, at, role) {
  if (record.status === 'revoked') {
    // A dated revocation orders the evidence: records signed before it stay
    // valid, anything at or after it does not. An undated one cannot be
    // ordered, so it is refused rather than assumed harmless.
    if (record.revoked_at && at && Date.parse(at) < Date.parse(record.revoked_at)) return null;
    return {
      code: 'LEDGER_KEY_NOT_ACTIVE',
      message: role + ' key is revoked and the revocation does not postdate the record: ' + record.key_id,
    };
  }
  if (record.expires_at && at && Date.parse(at) >= Date.parse(record.expires_at)) {
    return {
      code: 'LEDGER_KEY_NOT_ACTIVE',
      message: role + ' key had expired before the record was signed: ' + record.key_id,
    };
  }
  return null;
}

function authorizeWriter(policy, keyId, opts) {
  opts = opts || {};
  if (!policy || !Array.isArray(policy.writer_keys) || policy.writer_keys.indexOf(keyId) === -1) {
    return {
      ok: false,
      code: 'LEDGER_POLICY_MISMATCH',
      message: 'key is not a writer under the policy committed by genesis: ' + keyId,
    };
  }

  // A ledger revocation record is authoritative for ordering: a record up to
  // the head it binds stays valid, and anything past that head was written
  // later and is refused on position. This check runs before the keyring record
  // so the ledger's own evidence decides, not the local keyring's current
  // status.
  const revocation = opts.revocations ? opts.revocations.get(keyId) : null;
  if (revocation) {
    const at = opts.at;
    // Position, not the writer's clock, is what decides whether a record came
    // after the revocation was issued. The record binds the head it was issued
    // against, so any entry beyond that head was appended later, whatever
    // `recorded_at` claims. Refusing it here closes the backdating window: a
    // writer that turns its clock back cannot place a new entry before the
    // boundary. The one exception is the commitment entry that carries the
    // signer's own revocation, identified by digest and only after the record
    // has been authenticated. A commitment for another key is not that entry.
    if (opts.commitment !== true && typeof opts.seq === 'number'
        && opts.seq > revocation.head_tree_size) {
      return {
        ok: false,
        code: 'LEDGER_WRITER_REVOKED',
        message: 'writer key was revoked at ' + revocation.revoked_at + '; record at position '
          + opts.seq + ' appears after the head the revocation was issued against (tree '
          + revocation.head_tree_size + '), so its timestamp cannot place it before the boundary: '
          + keyId,
      };
    }
    if (!at || Date.parse(at) >= Date.parse(revocation.revoked_at)) {
      return {
        ok: false,
        code: 'LEDGER_WRITER_REVOKED',
        message: 'writer key was revoked at ' + revocation.revoked_at + ': ' + keyId,
      };
    }
  }

  const record = opts.records ? opts.records.get(keyId) : null;
  if (!record) {
    // A write path sets this: membership is not a status, so a signer whose
    // record cannot be read is refused rather than assumed active.
    if (opts.requireStatus) {
      return {
        ok: false,
        code: 'LEDGER_KEY_NOT_ACTIVE',
        message: 'writer key status could not be established for ' + keyId
          + '; the append path needs the keyring that holds it',
      };
    }
    return {
      ok: true,
      code: 'OK',
      message: 'listed writer key; key status was not available',
    };
  }

  const failure = keyStatusFailure(record, opts.at, 'writer');
  if (failure) return Object.assign({ ok: false }, failure);

  return {
    ok: true,
    code: 'OK',
    message: 'writer key is listed and active',
  };
}

// A revocation is a write: it must be signed by an admin under the committed
// policy, with a status source the write path can read. Revocation records
// revoke writer authority only; an admin who is also a writer keeps the admin
// role until the policy itself changes (which needs a successor ledger).
function authorizeAdmin(policy, keyId, opts) {
  opts = opts || {};
  if (!policy || !Array.isArray(policy.admin_keys) || policy.admin_keys.indexOf(keyId) === -1) {
    return {
      ok: false,
      code: 'LEDGER_POLICY_MISMATCH',
      message: 'key is not an admin under the policy committed by genesis: ' + keyId,
    };
  }

  const record = opts.records ? opts.records.get(keyId) : null;
  if (!record) {
    if (opts.requireStatus) {
      return {
        ok: false,
        code: 'LEDGER_KEY_NOT_ACTIVE',
        message: 'admin key status could not be established for ' + keyId
          + '; the write path needs the keyring that holds it',
      };
    }
    return { ok: true, code: 'OK', message: 'listed admin key; key status was not available' };
  }

  const failure = keyStatusFailure(record, opts.at, 'admin');
  if (failure) return Object.assign({ ok: false }, failure);
  return { ok: true, code: 'OK', message: 'admin key is listed and active' };
}

// --- revocation records --------------------------------------------------
//
// `<ledger>.revocations.jsonl` is append-only and every record is verified
// before it is used: scheme and fields, the signer's admin membership, the
// signature, the signer's status at its own recorded_at, the head it names, and
// that revoked_at does not reach behind that head. A file that exists but
// cannot be authenticated is an error, never an empty set: ignoring it would
// silently restore the authority it was meant to remove. The file is also
// matched against the ledger's commitment entries in both directions, so a
// missing, truncated or uncommitted record is a named failure.

function adminKeyOf(opts, keyId) {
  if (opts && opts.keyring) {
    const found = Signing.listKeys({ dir: opts.keyring }).find(k => k.key_id === keyId);
    if (found) return found;
  }
  const trusted = opts && opts.trustedKeys;
  if (trusted instanceof Map && trusted.has(keyId)) {
    return { key_id: keyId, public_key_pem: trusted.get(keyId), status: null };
  }
  if (trusted && typeof trusted === 'object' && typeof trusted[keyId] === 'string') {
    return { key_id: keyId, public_key_pem: trusted[keyId], status: null };
  }
  return null;
}

function readRevocations(pathsOf, read, io, opts) {
  opts = opts || {};
  // A supplied file is an alternate source, never a bypass: every record is
  // still held to the ledger's commitment digests below. This is the repair
  // path for a lost sidecar and the operational path when the sidecar is gone
  // but a backup exists. It cannot forge authority, only restore what the
  // ledger already committed to.
  const supplied = opts.revocations ? opts.revocations : null;
  const file = supplied || (pathsOf && pathsOf.revocations) || revocationPathFor(pathsOf.ledger);

  // Every entry the ledger dedicated to a revocation is a commitment. The file
  // is a rendering of those commitments, not their authority: a commitment
  // with no record is 'cannot tell', never 'no revocation'.
  const committed = new Map();
  for (const entry of read.entries) {
    if (typeof entry.receipt_id === 'string'
        && entry.receipt_id.indexOf(REVOCATION_COMMITMENT_PREFIX) === 0) {
      committed.set(entry.payload_digest, entry);
    }
  }

  let buf;
  try {
    buf = io.readFileSync(file);
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') {
      // A supplied file that does not exist is a caller error about the input,
      // not evidence that the ledger lost its sidecar. Those two conditions
      // used to share LEDGER_REVOCATION_MISSING; they must not, because one is
      // repaired by naming a file and the other by restoring one.
      if (supplied) {
        throw fail('LEDGER_IO',
          'the supplied revocation file does not exist: ' + file);
      }
      if (committed.size) {
        const first = committed.values().next().value;
        throw fail('LEDGER_REVOCATION_MISSING',
          'entry ' + first.seq + ' commits to a revocation record, but no revocation file exists at '
          + file + '; an absent file cannot mean no revocation');
      }
      return new Map();
    }
    throw fail('LEDGER_IO', 'cannot read revocation log ' + file + ': ' + (e.code || e.message));
  }

  const text = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf);
  // An empty backup holds no record to authenticate. It is malformed input,
  // not a commitment whose record the ledger lost.
  if (supplied && !text.trim().length) {
    throw fail('LEDGER_REVOCATION_MALFORMED',
      'the supplied revocation file holds no records: ' + file);
  }
  if (text.length && !text.endsWith('\n')) {
    throw fail('LEDGER_REVOCATION_MALFORMED',
      'the revocation log ends in an unterminated line: ' + file);
  }

  const policy = opts.policy;
  const revocations = new Map();
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;

    let record;
    try {
      record = JSON.parse(line);
    } catch (e) {
      throw fail('LEDGER_REVOCATION_MALFORMED',
        'revocation line ' + (i + 1) + ' is not valid JSON: ' + e.message);
    }

    let body;
    try {
      body = revocationBody(record);
    } catch (e) {
      throw fail('LEDGER_REVOCATION_MALFORMED',
        'revocation line ' + (i + 1) + ' is not a valid record: ' + e.message);
    }

    if (body.ledger_id !== read.ledgerId) {
      throw fail('LEDGER_REVOCATION_MALFORMED',
        'revocation line ' + (i + 1) + ' belongs to ledger ' + body.ledger_id + ', not ' + read.ledgerId);
    }

    const signature = record.signature;
    if (!signature || typeof signature.key_id !== 'string') {
      throw fail('LEDGER_REVOCATION_UNAUTHORIZED',
        'revocation line ' + (i + 1) + ' carries no signature');
    }
    if (!Array.isArray(policy.admin_keys) || policy.admin_keys.indexOf(signature.key_id) === -1) {
      throw fail('LEDGER_REVOCATION_UNAUTHORIZED',
        'revocation line ' + (i + 1) + ' is signed by a key that is not an admin under the committed policy: '
        + signature.key_id);
    }

    const key = adminKeyOf(opts, signature.key_id);
    if (!key || !key.public_key_pem) {
      throw fail('LEDGER_REVOCATION_UNAUTHORIZED',
        'no trusted public key for the admin that signed revocation line ' + (i + 1) + ': ' + signature.key_id);
    }
    if (signature.public_key && normalizePem(signature.public_key) !== normalizePem(key.public_key_pem)) {
      throw fail('LEDGER_REVOCATION_UNAUTHORIZED',
        'revocation line ' + (i + 1) + ' embeds a public key that does not match the trusted admin key');
    }
    if (!verifySignatureOf('revocation', record, key.public_key_pem)) {
      throw fail('LEDGER_REVOCATION_UNAUTHORIZED',
        'revocation line ' + (i + 1) + ' signature does not match its bytes');
    }

    if (key.status) {
      const failure = keyStatusFailure(key, body.recorded_at, 'admin');
      if (failure) {
        throw fail('LEDGER_REVOCATION_UNAUTHORIZED',
          'revocation line ' + (i + 1) + ' was signed by an admin key that was not usable: ' + failure.message);
      }
    }

    const head = read.checkpoints.find(c => c.tree_size === body.head_tree_size
      && c.checkpoint_hash === body.head_checkpoint_hash);
    if (!head) {
      throw fail('LEDGER_REVOCATION_MALFORMED',
        'revocation line ' + (i + 1) + ' names a head this ledger does not retain (tree size '
        + body.head_tree_size + ')');
    }
    // The latest record that existed when this revocation was issued, judged
    // against the head the record names: a revocation may end authority from
    // here on, never before a record it could already see. Entries written
    // after that head are the ones the boundary is meant to refuse.
    const latest = read.entries.slice(0, head.tree_size).reduce(
      (max, entry) => Math.max(max, Date.parse(entry.recorded_at)), Date.parse(head.created_at));
    if (Date.parse(body.revoked_at) <= latest) {
      throw fail('LEDGER_REVOCATION_BACKDATED',
        'revocation line ' + (i + 1) + ' takes effect at ' + body.revoked_at
        + ', at or before records the ledger already holds (' + new Date(latest).toISOString() + ')');
    }

    if (!Array.isArray(policy.writer_keys) || policy.writer_keys.indexOf(body.key_id) === -1) {
      throw fail('LEDGER_REVOCATION_UNKNOWN_WRITER',
        'revocation line ' + (i + 1) + ' names a key that is not a writer under the committed policy: '
        + body.key_id);
    }
    if (revocations.has(body.key_id)) {
      throw fail('LEDGER_REVOCATION_DUPLICATE',
        'a second revocation for ' + body.key_id + ' appears on line ' + (i + 1));
    }

    // Authenticated above, then matched to the ledger's own commitment. A
    // record the ledger never committed is not evidence, and a record the
    // ledger committed to but the file no longer holds fails below.
    const digest = revocationCommitmentDigest(record);
    if (!committed.has(digest)) {
      throw fail('LEDGER_REVOCATION_UNCOMMITTED',
        'revocation line ' + (i + 1) + ' for ' + body.key_id
        + ' is not committed by any ledger entry');
    }
    committed.delete(digest);

    revocations.set(body.key_id, {
      revoked_at: body.revoked_at,
      recorded_at: body.recorded_at,
      head_tree_size: body.head_tree_size,
      digest,
      record,
    });
  }

  if (committed.size) {
    const first = committed.values().next().value;
    throw fail('LEDGER_REVOCATION_MISSING',
      'entry ' + first.seq + ' commits to a revocation record that the file does not hold: '
      + file);
  }

  return revocations;
}

// --- one authorization owner ---------------------------------------------
//
// Every consumer resolves the committed policy, checks one or more signers,
// and then maps a verdict into its own vocabulary. That first half lives here
// so it cannot drift between append, verification, membership and recovery.
// The final mapping stays with each caller because it is genuinely different:
// a write throws, membership prints NOT IN CHAIN, the local walk names a code.
//
// The two scopes are explicit. `whole-ledger` covers every signed record in the
// read model, in record order. `single-record` covers one signer at one signed
// timestamp: the checkpoint a receipt proof lands in, or the signer of a write.

const SCOPE = Object.freeze({
  LEDGER: 'whole-ledger',
  RECORD: 'single-record',
});

const SCOPES = new Set([SCOPE.LEDGER, SCOPE.RECORD]);

function authorizationFailure(code, message, resolved) {
  return {
    ok: false,
    code,
    message,
    source: resolved ? resolved.source : null,
    policy_hash: resolved ? resolved.hash : null,
    writers: resolved ? resolved.policy.writer_keys.length : 0,
  };
}

// Resolution shared by the whole-ledger, single-record and repair checks:
// resolve the policy committed by genesis, then authenticate the revocation
// log once. Both failures come back as verdicts so each caller keeps its own
// error mapping.
function authorityContext(pathsOf, read, io, opts) {
  let resolved;
  try {
    resolved = resolvePolicy(pathsOf, read.genesis, io, opts);
  } catch (e) {
    return { failure: authorizationFailure(e.code || 'LEDGER_POLICY_MISSING', e.message, null) };
  }

  // A present-but-unauthenticated revocation log is a failure, never an empty
  // set: treating it as empty would restore authority the ledger removed.
  let revocations;
  try {
    revocations = readRevocations(pathsOf, read, io, Object.assign({}, opts, { policy: resolved.policy }));
  } catch (e) {
    return { failure: authorizationFailure(e.code || 'LEDGER_REVOCATION_MALFORMED', e.message, resolved) };
  }
  return { resolved, revocations };
}

// A policy or authority failure is a verdict, never a thrown error: the caller
// decides what it means. Errors raised while reading the key source are left to
// propagate exactly as each caller handled them before.
function authorize(pathsOf, read, io, opts) {
  opts = opts || {};
  if (!SCOPES.has(opts.scope)) {
    throw fail('LEDGER_MALFORMED', 'authorization scope must be ' + SCOPE.LEDGER + ' or ' + SCOPE.RECORD);
  }

  const context = authorityContext(pathsOf, read, io, opts);
  if (context.failure) return context.failure;
  const { resolved, revocations } = context;

  const records = opts.records !== undefined ? opts.records : keyRecordsOf(opts);
  // The whole-ledger scope walks the read model; a single-record scope names one
  // subject. Subjects are built here so the commitment mark can be derived from
  // the revocation records this pass authenticated, not from the caller.
  const subjects = opts.scope === SCOPE.LEDGER ? ledgerSubjects(read, revocations) : (opts.subjects || []);
  for (const subject of subjects) {
    // The commitment exemption is derived from the ledger walk, never from a
    // caller-supplied flag: a single-record scope therefore gets none of it.
    // Within the walk it is scoped to the two cases the revocation design
    // actually needs. An admin may seal only the record it signed itself; a
    // writer may skip the position rule only for the revocation that ends its
    // own authority. Every other commitment is an ordinary writer record: it
    // is admitted by the writer that made it, at its own position, and a
    // revoked writer is refused there.
    const derivedCommitment = opts.scope === SCOPE.LEDGER && subject.commitment === true
      && subject.commitment_sealer === subject.key;
    const adminCommitment = derivedCommitment
      && subject.commitment_signer === subject.key
      && Array.isArray(resolved.policy.admin_keys)
      && resolved.policy.admin_keys.indexOf(subject.key) !== -1;
    const selfCommitment = derivedCommitment
      && subject.commitment_key_id === subject.key;
    const verdict = adminCommitment
      ? authorizeAdmin(resolved.policy, subject.key, {
        at: subject.at,
        records,
        requireStatus: !!opts.requireStatus,
      })
      : authorizeWriter(resolved.policy, subject.key, {
        at: subject.at,
        seq: subject.seq,
        commitment: selfCommitment,
        records,
        revocations,
        requireStatus: !!opts.requireStatus,
      });
    if (!verdict.ok) {
      return authorizationFailure(verdict.code,
        subject.what ? verdict.message + ' (' + subject.what + ')' : verdict.message,
        resolved);
    }
  }

  return {
    ok: true,
    code: 'OK',
    message: null,
    source: resolved.source,
    policy_hash: resolved.hash,
    writers: resolved.policy.writer_keys.length,
  };
}

// `commitment` marks the entry that carries a revocation record: it is written
// after the head that record binds, by design, so the position rule must not
// refuse it. The mark is only granted when the entry's digest is one of the
// authenticated records, so a revoked writer cannot borrow the exemption for a
// new payload.
function ledgerSubjects(read, revocations) {
  const revocations2 = revocations || new Map();
  // The authenticated record behind each commitment digest. The record's
  // target and signer, plus the signer of the entry that carries it, are the
  // only facts the exemption is allowed to use: the target may seal its own
  // revocation, the admin that signed the record may seal the record itself,
  // and a checkpoint inherits only the authority of the entry it covers.
  const committedByDigest = new Map();
  for (const revocation of revocations2.values()) {
    committedByDigest.set(revocation.digest, {
      key_id: revocation.record.key_id,
      signer: revocation.record.signature.key_id,
    });
  }

  // Only the first entry carrying a committed digest is the commitment; a
  // hand-written duplicate leaf does not inherit the exemption.
  const firstSeq = new Map();
  for (const entry of read.entries) {
    if (!firstSeq.has(entry.payload_digest)) firstSeq.set(entry.payload_digest, entry.seq);
  }

  const commitmentSeqs = new Set();
  for (const entry of read.entries) {
    if (typeof entry.receipt_id === 'string'
        && entry.receipt_id.indexOf(REVOCATION_COMMITMENT_PREFIX) === 0
        && committedByDigest.has(entry.payload_digest)
        && firstSeq.get(entry.payload_digest) === entry.seq) {
      commitmentSeqs.add(entry.seq);
    }
  }

  const commitmentMeta = seq => {
    if (!commitmentSeqs.has(seq)) return null;
    const entry = read.entries[seq - 1];
    const record = committedByDigest.get(entry.payload_digest);
    if (!record) return null;
    // The entry's own signer is the only key whose checkpoint can ride on the
    // exemption. An entry signed by one key and a checkpoint at the same tree
    // size signed by another is not the same seal.
    return Object.assign({}, record, { sealer: entry.signature.key_id });
  };

  const subjects = [{
    what: 'the genesis checkpoint',
    key: read.genesis.signature.key_id,
    at: read.genesis.created_at,
  }];
  for (let i = 1; i < read.checkpoints.length; i++) {
    const checkpoint = read.checkpoints[i];
    // A checkpoint at the commitment's tree size is the seal of that entry.
    // It carries the same record metadata as the entry, so the exemption is
    // exactly as wide as the entry it accompanies.
    const meta = commitmentMeta(checkpoint.tree_size);
    subjects.push({
      what: 'checkpoint ' + checkpoint.tree_size,
      key: checkpoint.signature.key_id,
      at: checkpoint.created_at,
      commitment: !!meta,
      commitment_key_id: meta ? meta.key_id : null,
      commitment_signer: meta ? meta.signer : null,
      commitment_sealer: meta ? meta.sealer : null,
    });
  }
  for (const entry of read.entries) {
    const meta = commitmentMeta(entry.seq);
    subjects.push({
      what: 'entry ' + entry.seq,
      key: entry.signature.key_id,
      at: entry.recorded_at,
      seq: entry.seq,
      commitment: !!meta,
      commitment_key_id: meta ? meta.key_id : null,
      commitment_signer: meta ? meta.signer : null,
      commitment_sealer: meta ? meta.sealer : null,
    });
  }
  return subjects;
}

function authorizeLedger(pathsOf, read, io, opts) {
  return authorize(pathsOf, read, io, Object.assign({}, opts, {
    scope: SCOPE.LEDGER,
  }));
}

function authorizeRecord(pathsOf, read, io, subject, opts) {
  return authorize(pathsOf, read, io, Object.assign({}, opts, {
    scope: SCOPE.RECORD,
    subjects: [subject],
  }));
}

// Authority to write the checkpoints that cover entries `seqs` during repair.
// Ordinary entries take writer authority. The one exception is the commitment
// seal an admin made: verification already accepts a checkpoint at that tree
// size only when the same admin signed the entry and the record, so repair
// accepts exactly that pair and nothing wider. The facts are derived from the
// ledger walk, never from a caller flag, so a caller cannot request the
// exemption for an append. Every size is checked before the caller writes.
function authorizeRepairSeals(pathsOf, read, io, seqs, keyId, opts) {
  opts = opts || {};
  const context = authorityContext(pathsOf, read, io, opts);
  if (context.failure) return context.failure;
  const { resolved, revocations } = context;

  const records = opts.records !== undefined ? opts.records : keyRecordsOf(opts);
  const at = opts.at || new Date().toISOString();
  const subjects = ledgerSubjects(read, revocations);
  for (const seq of seqs) {
    const subject = subjects.find(s => s.seq === seq && s.key === keyId);
    const adminCommitment = !!subject && subject.commitment === true
      && subject.commitment_sealer === subject.key
      && subject.commitment_signer === subject.key
      && Array.isArray(resolved.policy.admin_keys)
      && resolved.policy.admin_keys.indexOf(subject.key) !== -1;

    const verdict = adminCommitment
      ? authorizeAdmin(resolved.policy, keyId, {
        at,
        records,
        requireStatus: !!opts.requireStatus,
      })
      : authorizeWriter(resolved.policy, keyId, {
        at,
        records,
        revocations,
        requireStatus: !!opts.requireStatus,
      });
    if (!verdict.ok) {
      return authorizationFailure(verdict.code,
        verdict.message + ' (checkpoint ' + seq + ')', resolved);
    }
  }

  return {
    ok: true,
    code: 'OK',
    message: null,
    source: resolved.source,
    policy_hash: resolved.hash,
    writers: resolved.policy.writer_keys.length,
  };
}

module.exports = {
  POLICY_SUFFIX,
  SCOPE,
  policyPathFor,
  revocationPathFor,
  resolvePolicy,
  writePolicy,
  keyRecordsOf,
  authorizeWriter,
  authorizeAdmin,
  readRevocations,
  authorizeLedger,
  authorizeRecord,
  authorizeRepairSeals,
};

// Verifyd receipt ledger - public entry point.
//
// The ledger is four layers in four files; this module is the only one callers
// outside engine/ should need. It re-exports the public surface, so a helper
// that a lower layer needs internally cannot quietly become part of the
// contract, and composes the one operation that needs both layers: a restore
// is verified by the walk and written by the store, in that order.
//
//   ledger-format.cjs   frozen shapes, tags, hashes, signing preimages (no I/O)
//   ledger-store.cjs    lock, durable append, state cache, one read model
//   ledger-recovery.cjs fsck: findings in, repairs and a verdict out
//   ledger-verify.cjs   the local walk: inspection plus signature checks
//
// The layers depend downward on ledger-format.cjs only; none of them requires
// this file, so there is no cycle to reason about.

'use strict';

const fs = require('fs');
const path = require('path');

const Format = require('./ledger-format.cjs');
const Store = require('./ledger-store.cjs');
const Recovery = require('./ledger-recovery.cjs');
const Verify = require('./ledger-verify.cjs');
const Signing = require('./signing.cjs');

// A restore is a repair, so it is all-or-nothing and its success means the
// ledger verifies. The supplied file is authenticated by the store, but a
// store-level check alone cannot see authority: a ledger can hold a structurally
// valid, correctly committed, badly authorized chain. So verify the ledger with
// the backup in place first and write nothing when that fails; write atomically;
// then verify again and put the previous sidecar back if the result does not
// stand. Only then is "Restored" an honest report.
function restoreRevocations(ledgerPath, opts) {
  opts = opts || {};
  if (typeof opts.file !== 'string' || !opts.file.length) {
    // The store raises the caller error for a missing argument and writes
    // nothing, so there is no partial state to guard here.
    return Store.restoreRevocations(ledgerPath, opts);
  }

  const io = opts.fs || fs;
  const pathsOf = Store.ledgerPaths(ledgerPath);
  const file = path.resolve(opts.file);

  const pre = Verify.verifyLocal(ledgerPath, Object.assign({}, opts, { revocations: file }));
  if (!pre.ok) throw Format.fail(pre.code, pre.message);

  // Read the rollback copy before the write. If the existing sidecar cannot be
  // read, refuse rather than overwrite something we could not put back.
  let previous = null;
  try {
    previous = io.readFileSync(pathsOf.revocations);
  } catch (e) {
    if (e.code !== 'ENOENT') {
      throw Format.fail('LEDGER_IO',
        'cannot read the existing revocation file ' + pathsOf.revocations
        + '; refusing to overwrite it without a rollback copy: ' + (e.code || e.message));
    }
  }

  const out = Store.restoreRevocations(ledgerPath, opts);

  const postOpts = Object.assign({}, opts);
  delete postOpts.revocations;
  const post = Verify.verifyLocal(ledgerPath, postOpts);
  if (post.ok) return out;

  try {
    if (previous === null) io.unlinkSync(pathsOf.revocations);
    else Signing.writeAtomic(pathsOf.revocations, previous, { fs: io, fsync: true });
    Store.fsyncDir(pathsOf.dir, io);
  } catch (rollback) {
    throw Format.fail(post.code, post.message
      + '; the previous revocation file could not be restored ('
      + (rollback.code || rollback.message) + ')');
  }
  throw Format.fail(post.code, post.message);
}

module.exports = {
  // Formats and hashing.
  SCHEME: Format.SCHEME,
  PUBLICATION_SCHEME: Format.PUBLICATION_SCHEME,
  CHECKPOINT_TYPE: Format.CHECKPOINT_TYPE,
  GENESIS: Format.GENESIS,
  TAG: Format.TAG,
  TAG_REGISTRY: Format.TAG_REGISTRY,
  canonical: Format.canonical,
  sha256Hex: Format.sha256Hex,
  emptyRoot: Format.emptyRoot,
  entryBody: Format.entryBody,
  buildEntry: Format.buildEntry,
  entryHash: Format.entryHash,
  entryHashPreimage: Format.entryHashPreimage,
  entrySigningPayload: Format.entrySigningPayload,
  checkpointBody: Format.checkpointBody,
  genesisBody: Format.genesisBody,
  buildCheckpoint: Format.buildCheckpoint,
  buildGenesis: Format.buildGenesis,
  signEntry: Format.signEntry,
  signCheckpoint: Format.signCheckpoint,
  checkpointHash: Format.checkpointHash,
  checkpointHashPreimage: Format.checkpointHashPreimage,
  checkpointSigningPayload: Format.checkpointSigningPayload,
  ledgerIdFromGenesis: Format.ledgerIdFromGenesis,
  keyringSigner: Format.keyringSigner,
  verifySignatureOf: Format.verifySignatureOf,
  policyBody: Format.policyBody,
  policyBytes: Format.policyBytes,
  policyHash: Format.policyHash,
  REVOCATION_COMMITMENT_PREFIX: Format.REVOCATION_COMMITMENT_PREFIX,
  revocationBody: Format.revocationBody,
  buildRevocation: Format.buildRevocation,
  signRevocation: Format.signRevocation,
  revocationSigningPayload: Format.revocationSigningPayload,
  revocationCommitmentDigest: Format.revocationCommitmentDigest,
  cosignStatement: Format.cosignStatement,
  cosignSigningPayload: Format.cosignSigningPayload,
  cosignDigest: Format.cosignDigest,
  publicationStatement: Format.publicationStatement,
  publicationStatementBytes: Format.publicationStatementBytes,
  publicationStatementDigest: Format.publicationStatementDigest,
  assertScheme: Format.assertScheme,
  assertPublicationScheme: Format.assertPublicationScheme,

  // The store.
  ledgerPaths: Store.ledgerPaths,
  acquireLock: Store.acquireLock,
  releaseLock: Store.releaseLock,
  initLedger: Store.initLedger,
  append: Store.append,
  revokeWriter: Store.revokeWriter,
  restoreRevocations,
  readRepairEvents: Store.readRepairEvents,

  // Recovery and verification.
  fsck: Recovery.fsck,
  verifyLocal: Verify.verifyLocal,
  verifyReceipt: Verify.verifyReceipt,
  verifyChain: Verify.verifyChain,
};

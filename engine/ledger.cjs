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

const path = require('path');

const Format = require('./ledger-format.cjs');
const Store = require('./ledger-store.cjs');
const Recovery = require('./ledger-recovery.cjs');
const Verify = require('./ledger-verify.cjs');

// A restore is a repair, so it is all-or-nothing and its success means the
// ledger verifies. The supplied file is authenticated by the store, but a
// store-level check alone cannot see authority: a ledger can hold a structurally
// valid, correctly committed, badly authorized chain. The store therefore calls
// back for a whole-ledger verification before it writes and again after; both
// run while it holds the lock, and a failure in either leaves the previous
// sidecar in place. Only then is "Restored" an honest report.
function restoreRevocations(ledgerPath, opts) {
  opts = opts || {};
  if (typeof opts.file !== 'string' || !opts.file.length) {
    // The store raises the caller error for a missing argument and writes
    // nothing, so there is no partial state to guard here.
    return Store.restoreRevocations(ledgerPath, opts);
  }

  const file = path.resolve(opts.file);
  const before = Object.assign({}, opts, { revocations: file });
  const after = Object.assign({}, opts);
  delete after.revocations;

  return Store.restoreRevocations(ledgerPath, Object.assign({}, opts, {
    verify(phase) {
      const result = Verify.verifyLocal(ledgerPath, phase === 'pre' ? before : after);
      if (!result.ok) throw Format.fail(result.code, result.message);
    },
  }));
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

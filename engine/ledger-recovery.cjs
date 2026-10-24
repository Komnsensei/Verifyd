// Verifyd receipt ledger - fsck (Phase B, section 5).
//
// Repairs exactly one condition automatically: a final unterminated fragment
// whose complete prefix matches the state cache. Everything else is reported
// and left byte-for-byte alone, because a repair that cannot be justified from
// the surviving bytes is how evidence quietly disappears.
//
// The walk itself is ledger-store.cjs's inspectLedger; this file only decides
// what a finding means, in the order fsck has always used: structural damage,
// then the counts, then roots, then re-sealing an entry log that is ahead of
// the checkpoint log. Re-inspecting after a repair is deliberate. It is the
// same walk, reading the bytes that are actually on disk now.

'use strict';

const fs = require('fs');

const {
  SCHEME,
  GENESIS,
  requireHex,
  buildCheckpoint,
  signCheckpoint,
  normalizeSigner,
} = require('./ledger-format.cjs');
const Policy = require('./ledger-policy.cjs');
const {
  ledgerPaths,
  inspectLedger,
  readState,
  writeState,
  armTornGuard,
  fileExistsAt,
  truncateTo,
  logRepair,
  appendLineDurable,
  withLock,
  assertLockOwned,
  readRepairEvents,
  fsyncDir,
} = require('./ledger-store.cjs');

function fsckBody(pathsOf, io, opts, dryRun, lock) {
  const actions = [];
  const requirements = [];
  // A repair is a write, so it gets the same fencing check as an append.
  const guard = () => { if (lock) assertLockOwned(lock, io); };
  const finish = (ok, code, message, head) => ({
    ok, code, message, actions, requirements, head: head || null, paths: pathsOf,
  });
  const summary = (report) => {
    if (!report || !report.head) return null;
    return {
      seq: report.entries.length,
      tree_size: report.head.tree_size,
      checkpoint_hash: report.head.checkpoint_hash,
      root_hash: report.head.root_hash,
    };
  };

  const repairs = readRepairEvents(io, pathsOf.repairs);
  // Either kind of evidence blocks a second automatic truncation: the marker
  // (authoritative, contents ignored) or a parseable log record from a ledger
  // written before the marker existed.
  const guardArmed = fileExistsAt(io, pathsOf.torn);
  const priorTruncations = repairs.filter(r => r.event === 'TORN_TAIL_TRUNCATED').length;
  const priorRepairEvidence = guardArmed || priorTruncations > 0;
  let state = readState(io, pathsOf.state);

  let report = inspectLedger(pathsOf, io);
  let findings = report.findings;

  if (findings.checkpoints) {
    return finish(false, findings.checkpoints.code || 'LEDGER_CORRUPT', findings.checkpoints.message, null);
  }
  if (findings.not_initialized) {
    return finish(false, 'LEDGER_NOT_INITIALIZED', 'no checkpoints in ' + pathsOf.checkpoints, null);
  }

  if (findings.checkpoint_tail) {
    const tail = findings.checkpoint_tail;
    if (!opts.repairTail) {
      requirements.push('repair-tail');
      return finish(false, 'LEDGER_TORN_CHECKPOINT_TAIL',
        'the final checkpoint line is unterminated (' + tail.bytes + ' bytes); pass repairTail to discard it',
        null);
    }
    if (dryRun) {
      actions.push({ event: 'CHECKPOINT_TAIL_TRUNCATED', discarded_bytes: tail.bytes, dry_run: true });
      return finish(false, 'LEDGER_REPAIR_PENDING', 'dry run: would discard ' + tail.bytes + ' bytes of checkpoint tail', null);
    }
    guard();
    logRepair(io, pathsOf.repairs, {
      event: 'CHECKPOINT_TAIL_TRUNCATED',
      discarded_hex: report.checkpointRead.fragment_buf.slice(0, 4096).toString('hex'),
      discarded_bytes: tail.bytes,
    });
    try {
      truncateTo(io, pathsOf.checkpoints, report.checkpointRead.complete_bytes);
    } catch (e) {
      return finish(false, 'LEDGER_CORRUPT', 'could not truncate the torn checkpoint tail: ' + (e.code || e.message), null);
    }
    actions.push({ event: 'CHECKPOINT_TAIL_TRUNCATED', discarded_bytes: tail.bytes });

    report = inspectLedger(pathsOf, io);
    findings = report.findings;
    if (findings.checkpoint_tail) {
      return finish(false, 'LEDGER_CORRUPT', 'the checkpoint log still ends in an unterminated line', null);
    }
    if (findings.checkpoints) {
      return finish(false, findings.checkpoints.code || 'LEDGER_CORRUPT', findings.checkpoints.message, null);
    }
    if (findings.not_initialized) {
      return finish(false, 'LEDGER_NOT_INITIALIZED', 'no checkpoints in ' + pathsOf.checkpoints, null);
    }
  }

  if (findings.checkpoint_chain) {
    return finish(false, findings.checkpoint_chain.code || 'LEDGER_CORRUPT', findings.checkpoint_chain.message, null);
  }

  if (findings.entries) {
    // A complete line that does not parse or does not hash to its own digest is
    // corruption. It is reported, never truncated: only an unterminated tail is
    // a crash artifact.
    return finish(false, findings.entries.code || 'LEDGER_CORRUPT', findings.entries.message, summary(report));
  }

  if (findings.entry_tail) {
    const tail = findings.entry_tail;
    if (findings.entry_chain) {
      return finish(false, 'LEDGER_CORRUPT', 'the torn tail sits over a prefix that does not link: '
        + findings.entry_chain.message, summary(report));
    }
    const matchesState = !!state && state.seq === report.entries.length;
    const autoSafe = matchesState && !priorRepairEvidence;
    if (!opts.repairTail && !autoSafe) {
      requirements.push('repair-tail');
      const why = priorRepairEvidence
        ? 'a torn tail has already been truncated once'
        : 'the complete prefix does not match the state cache';
      return finish(false, 'LEDGER_TORN_TAIL_REQUIRES_FLAG',
        why + '; pass repairTail to discard ' + tail.bytes + ' bytes', summary(report));
    }
    if (dryRun) {
      actions.push({ event: 'TORN_TAIL_TRUNCATED', discarded_bytes: tail.bytes, dry_run: true });
      return finish(false, 'LEDGER_REPAIR_PENDING', 'dry run: would discard ' + tail.bytes + ' bytes of entry tail', summary(report));
    }
    guard();
    try {
      armTornGuard(pathsOf, io, { discarded_bytes: tail.bytes, entries_kept: report.entries.length });
    } catch (e) {
      return finish(false, 'LEDGER_IO', 'cannot record the truncation guard: ' + (e.code || e.message), summary(report));
    }
    logRepair(io, pathsOf.repairs, {
      event: 'TORN_TAIL_TRUNCATED',
      discarded_hex: report.entryRead.fragment_buf.slice(0, 4096).toString('hex'),
      discarded_bytes: tail.bytes,
      entries_kept: report.entries.length,
      state_seq: state ? state.seq : null,
    });
    try {
      truncateTo(io, pathsOf.entries, report.entryRead.complete_bytes);
    } catch (e) {
      return finish(false, 'LEDGER_CORRUPT', 'could not truncate the torn entry tail: ' + (e.code || e.message), summary(report));
    }
    actions.push({ event: 'TORN_TAIL_TRUNCATED', discarded_bytes: tail.bytes });

    report = inspectLedger(pathsOf, io);
    findings = report.findings;
    if (findings.entries) {
      return finish(false, findings.entries.code || 'LEDGER_CORRUPT',
        'the truncated log still does not parse: ' + findings.entries.message, summary(report));
    }
  }

  if (findings.entry_chain) {
    return finish(false, findings.entry_chain.code || 'LEDGER_CORRUPT', findings.entry_chain.message, summary(report));
  }

  if (findings.short) {
    return finish(false, 'LEDGER_TRUNCATED',
      'the entry log holds ' + report.entries.length + ' entries but the head checkpoint covers ' + report.head.tree_size,
      summary(report));
  }

  // Roots are checked before any re-sealing: a checkpoint that does not cover
  // the entries it claims is not repaired by adding more checkpoints.
  if (findings.roots) {
    const message = findings.roots.code === 'LEDGER_ENTRY_MISMATCH'
      ? 'the root at tree size ' + findings.roots.tree_size + ' does not match the entry log'
      : findings.roots.message;
    return finish(false, findings.roots.code || 'LEDGER_CORRUPT', message, summary(report));
  }

  if (findings.ahead) {
    const head = report.head;
    const missing = [];
    for (let size = head.tree_size + 1; size <= report.entries.length; size++) missing.push(size);
    if (!opts.signer) {
      requirements.push('signer');
      return finish(false, 'LEDGER_CHECKPOINT_MISSING',
        'the entry log is ' + missing.length + ' ahead of the checkpoint log; a signing key is required to re-seal',
        summary(report));
    }
    // Re-sealing writes checkpoints under the writer policy too, so the repair
    // signer is authorized for every checkpoint before any byte is written.
    // Authority is derived per entry: ordinary entries take writer authority,
    // and the commitment seal keeps the narrow admin exemption verification
    // grants it, so a sole-writer ledger can be repaired without the admin
    // gaining append authority. A repair is a write: the status source is
    // mandatory, named by opts.keyring or by the signer's own keyring
    // reference.
    try {
      const keyring = opts.keyring || (opts.signer && opts.signer.keyring) || null;
      const authorized = Policy.authorizeRepairSeals(pathsOf, report, io, missing,
        opts.signer.key_id,
        { policy: opts.policy, keyring, revocations: opts.revocations, requireStatus: true,
          at: new Date().toISOString() });
      if (!authorized.ok) {
        return finish(false, authorized.code, authorized.message, summary(report));
      }
    } catch (e) {
      return finish(false, e.code || 'LEDGER_POLICY_MISSING', e.message, summary(report));
    }
    if (dryRun) {
      actions.push({ event: 'CHECKPOINT_RESEALED', sizes: missing, dry_run: true });
      return finish(false, 'LEDGER_REPAIR_PENDING', 'dry run: would re-seal ' + missing.length + ' checkpoint(s)', summary(report));
    }
    const signer = normalizeSigner(opts.signer);
    guard();
    // The report's frontier stops at the verified head; push the entries the
    // head does not cover and take each missing root from that one pass. No
    // per-size tree rebuild and no second tree implementation.
    const frontier = report.frontier;
    let prevHash = head.checkpoint_hash;
    for (const size of missing) {
      frontier.push(Buffer.from(requireHex(report.entries[size - 1].payload_digest, 'payload_digest'), 'hex'));
      const resealed = signCheckpoint(buildCheckpoint({
        ledger_id: report.ledgerId,
        tree_size: size,
        root_hash: frontier.root().toString('hex'),
        created_at: new Date().toISOString(),
        prev_checkpoint_hash: prevHash,
        policy_hash: report.checkpoints[0].policy_hash,
      }), signer);
      appendLineDurable(pathsOf.checkpoints, JSON.stringify(resealed) + '\n', io);
      prevHash = resealed.checkpoint_hash;
    }
    fsyncDir(pathsOf.dir, io);
    actions.push({ event: 'CHECKPOINT_RESEALED', sizes: missing });

    report = inspectLedger(pathsOf, io);
    findings = report.findings;
    if (findings.checkpoint_chain) {
      return finish(false, findings.checkpoint_chain.code || 'LEDGER_CORRUPT',
        're-sealed checkpoints do not chain: ' + findings.checkpoint_chain.message, null);
    }
  }

  const entries = report.entries;
  const head = report.head;
  const headEntryHash = entries.length ? entries[entries.length - 1].entry_hash : GENESIS;
  if (state && state.seq > entries.length) {
    return finish(false, 'LEDGER_TRUNCATED',
      'the state cache claims seq ' + state.seq + ' but the entry log holds ' + entries.length,
      summary(report));
  }

  const stateStale = !state
    || state.seq !== entries.length
    || state.checkpoint_hash !== head.checkpoint_hash
    || state.head_hash !== headEntryHash;
  if (stateStale) {
    if (dryRun) {
      actions.push({ event: 'STATE_REBUILT', from: state ? state.seq : null, to: entries.length, dry_run: true });
      return finish(false, 'LEDGER_REPAIR_PENDING', 'dry run: would rebuild the state cache', summary(report));
    }
    guard();
    const doc = {
      scheme: SCHEME,
      ledger_id: report.ledgerId,
      seq: entries.length,
      head_hash: headEntryHash,
      tree_size: head.tree_size,
      checkpoint_hash: head.checkpoint_hash,
      root_hash: head.root_hash,
      updated_at: new Date().toISOString(),
    };
    writeState(pathsOf, doc, io);
    state = doc;
    actions.push({ event: 'STATE_REBUILT', to: entries.length });
  }

  return finish(true, 'OK', 'the ledger is consistent', summary(report));
}

function fsck(ledgerPath, opts) {
  opts = opts || {};
  const io = opts.fs || fs;
  const pathsOf = ledgerPaths(ledgerPath);
  const dryRun = !!opts.dryRun;
  // Read-only fsck must not create or touch any file, including the lock.
  if (dryRun) return fsckBody(pathsOf, io, opts, true, null);
  return withLock(pathsOf.ledger, opts, (lock) => fsckBody(pathsOf, io, opts, false, lock));
}

module.exports = { fsck };

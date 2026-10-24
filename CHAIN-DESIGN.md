# CHAIN-DESIGN.md - Trust anchor for the receipt ledger

Status: **phases A and B implemented, nothing anchored.** The ledger formats, the
persistent entry and checkpoint logs, the lock, the fsync ordering, the local
verification walk and `fsck` exist in the four ledger layers behind the
`engine/ledger.cjs` facade and are covered by tests. No receipt carries a `ledger` block, no CLI command exposes the ledger,
and no checkpoint has been anchored. Baseline commit
`56e1ca0258ab5309b85b40f19991a908227bfc9b` (`target/main` matches).

Revision 2 resolves the anchor and ledger-scope decisions, promotes the protocol
rules to a normative specification, and replaces the old four-phase sketch with
phases A-F. It also records two code facts that change the earlier draft: entries
must be signed because several authorized writer keys may append, and
`receipt.prev_hash` cannot be used as ledger linkage because it is sealed inside
the signed receipt before an append can happen. See the amendment log at the end.

Current state, verified by running the shipped CLI on this baseline (not
inferred from docs):

```
$ node bin/verifyd.cjs audit a.txt   # exit 0
$ node bin/verifyd.cjs audit b.txt   # exit 0
a.verifyd-receipt.json  prev_hash=GENESIS  has ledger block=false  has inclusion=false
b.verifyd-receipt.json  prev_hash=GENESIS  has ledger block=false  has inclusion=false

files written beside the receipts: a.txt, a.verifyd-receipt.json, b.txt,
b.verifyd-receipt.json (plus the keyring). No ledger, chain, seq or checkpoint
file is created. this_hash values differ per run because receipt_id and
timestamps are random; the structural output above is what is deterministic.
```

`grep -rn "new v.AuditChain("` shows every caller constructs it with no file
path (`bin/verifyd.cjs:448`, `examples/audit-paper.cjs:143`,
`examples/run-example.cjs:52`, plus the staged copy under
`artifacts/bundle-stage/bin/verifyd.cjs:235`), so `AuditChain.lastHash()` always
returns `GENESIS`, every receipt claims to be first, and each audit leaves only
its own receipt file. `AuditChain` itself appends with `appendFileSync` and no `fsync`,
no lock, and no read-back, so it is not a durable writer either.

Receipt-level signature verification therefore proves *this receipt is
internally consistent*, not *this receipt is a member of an authentic,
un-rewritten sequence*. That distinction is the whole subject of this file.

---

## 1. What a ledger can and cannot prove

Stated first, because everything below is only useful if the limits are clear.

A ledger of receipt digests, anchored as described here, can establish:

- **Ordering.** Entry *n+1* was recorded after entry *n*, by the holder of the
  ledger signing key, with no gaps and no duplicate digests.
- **Non-repudiation of recording.** The ledger operator signed a root that
  commits to this receipt's exact signed bytes at a specific tree size.
- **Detectability of alteration.** Any change to a recorded entry, any removal,
  reordering, insertion or truncation, changes a root that has been signed and
  (with an anchor) retained elsewhere.
- **Inclusion.** A receipt holder can prove to a third party that their receipt
  is in a specific checkpoint, without handing over the ledger.

It cannot establish:

- **That the ledger is complete.** A writer can refuse to record a receipt, or
  record it and later present a different head. Only the holder's own inclusion
  proof, or an auditor who counted appends against an independent source of
  truth, detects omission. A ledger is not a source of truth about events.
- **That recorded content is true or compliant.** Inclusion is a position in a
  set, exactly as `engine/merkle.cjs` says of batches.
- **That the operator's clock is right.** Without an RFC 3161 token, timestamps
  are the writer's clock.
- **Anything at all against a writer who controls every retained copy and can
  re-sign.** See section 7. This is the reason the anchor is mandatory for the
  strong claim.
- **Prevention of deletion.** Every control here is detection. A writer can
  delete the ledger; the guarantee is that a verifier holding an older anchored
  head finds out.

The honest one-line summary: **an anchored ledger turns silent rewriting into
detected rewriting.** It does not make rewriting impossible, and it does not
make the engine a system of record.

---

## 2. Adversary model

Two adversaries, because they need different controls.

**A1 - the outsider.** Can read and modify files in the ledger directory but
does not hold the ledger signing key. Goals: alter a receipt after the fact,
delete an inconvenient receipt, splice in a forged one, present a truncated
ledger.

**A2 - the insider writer.** Holds the ledger signing key and full write access
to the ledger directory, and can re-sign anything. Goals: rewrite history so
that a receipt never existed, or existed with different contents; present a
forked ledger to different verifiers; roll the ledger back to before an
incident.

A1 is handled by signatures and linkage. A2 is handled **only** by an anchor
copy that the writer cannot rewrite, or by witnesses who will not cosign a fork.
A design that does not name its anchor has not addressed A2, which is the case
that matters for an evidentiary ledger.

Out of scope: an adversary who can rewrite every anchor copy *and* collude with
the witness quorum *and* forge TSA tokens. That is not a software problem.

---

## 3. Objects

All canonicalization uses `engine/canonicalize.cjs` (RFC 8785). All hashes are
lowercase SHA-256 hex. All timestamps are ISO 8601 UTC. Nothing here introduces
a new hash function or a new serialization.

### 3.1 Entry

One JSON object per line in `<ledger>.jsonl`.

```
{
  "scheme": "verifyd-ledger-v1",
  "ledger_id": "<checkpoint_hash of genesis, section 12.2>",
  "seq": 41,
  "payload_digest": "<sha256 of Signing.signingPayload(receipt)>",
  "receipt_id": "<receipt.receipt_id, for operator lookup only>",
  "recorded_at": "2026-10-23T12:00:00.000Z",
  "writer_key_id": "ed25519:...",
  "prev_entry_hash": "<entry_hash of seq 40, or GENESIS>",
  "entry_hash": "<sha256('verifyd-ledger-entry-v1\\nhash\\n' + JCS(entry without entry_hash, signature))>",
  "signature": "<Ed25519 over 'verifyd-ledger-entry-v1\\nsig\\n' + JCS(entry without signature)>"
}
```

In this JSON block the domain separators are escaped per JSON; the bytes that
are hashed are the tag text followed by a single LF.

- `payload_digest` is the **same** digest the batch code already uses
  (`v.TSA.sha256(v.Signing.signingPayload(data))`), so a ledger leaf and a batch
  leaf commit to identical bytes. It is excluded from the signed payload, so
  attaching ledger data later cannot invalidate a receipt signature or token.
- `receipt_id` is not trusted for linkage. It exists so an operator can find the
  receipt for an entry; every security check uses `payload_digest`.
- The domain prefixes mirror the signing domains already in use and keep an
  entry hash from being replayable as a receipt digest. The `hash` and `sig`
  sub-tags keep the two preimages under one scheme from being confused.
- **Entries are individually signed** by the appending writer key. Revision 1
  argued the checkpoint alone was enough, which held only for a single-key
  writer. Section 12 allows several authorized keyrings to append to one ledger,
  and the checkpoint signature names one key, so without a per-entry signature
the other writers' appends would be attributable only to the checkpoint signer.
  The cost is one Ed25519 sign per audit.
- The genesis checkpoint is the empty tree (`tree_size` 0), whose root is
  `SHA-256(0x02 || uint64be(0) || SHA-256(""))`. `Merkle.buildTree` rejects an
  empty leaf list today, so genesis must be constructed explicitly, not by
  calling it with `[]`.

### 3.2 Tree

Leaves are `payload_digest` values, in `seq` order, hashed with the existing
`engine/merkle.cjs` rules verbatim:

```
leaf_hash = SHA-256(0x00 || payload_digest)
node_hash = SHA-256(0x01 || left || right)
root      = SHA-256(0x02 || uint64be(tree_size) || MTH(leaves))
```

Reusing the leaf rule means `Merkle.inclusion(index, payloadDigests)` already
produces valid paths for ledger checkpoints. `Merkle.consistency(m, digests)`
and `Merkle.verifyConsistency(...)` supply the consistency proof (6.4,
normative in 13.4). Because a root here commits to the tree size, the proof
also carries `prefix_mth` = MTH(D[0:m]); without it a verifier holding only
`root_m` cannot fold the first m leaves, since the size prefix cannot be
stripped by hashing. That hash is public subtree data, not a secret, and adds
one 32-byte value to a proof.

### 3.3 Checkpoint

The ledger's signed tree head. Written to `<ledger>.checkpoints.jsonl`, one per
line, each signed with an authorized writer key under its own domain. In v1
exactly one checkpoint follows each entry, so `tree_size` increases by one per
checkpoint and a gap is itself a defect.

```
{
  "scheme": "verifyd-ledger-v1",
  "checkpoint_type": "ledger",
  "ledger_id": "<genesis checkpoint_hash, section 12.2>",
  "tree_size": 128,
  "root_hash": "<hex>",
  "created_at": "...",
  "prev_checkpoint_hash": "<checkpoint_hash at tree_size 127, or GENESIS>",
  "policy_hash": "<sha256 of the genesis writer/witness policy body>",
  "signature": { "algorithm": "ed25519", "key_id": "ed25519:...", "public_key": "...", "value": "..." }
}
```

- Signed over `Signing.signingPayload(checkpoint, { domain: 'verifyd-chain-checkpoint-v1\nsig\n' })`.
  A new domain tag is required: `verifyd-merkle-root-v1\n` is already taken by
  batch roots, and a checkpoint must not be replayable as a batch root.
- `checkpoint_hash = sha256('verifyd-chain-checkpoint-v1\nhash\n' + JCS(checkpoint without signature))`.
- A checkpoint line is written once and never edited. A token, a witness
  cosignature or a publication proof is **not** attached to it afterwards; those
  live in anchor records keyed by `checkpoint_hash` (13.8). Editing a written
  checkpoint to add evidence would turn an append-only log into a mutable one,
  and would make "the checkpoint that was signed" and "the checkpoint on disk"
  two different objects.
- Chaining checkpoints by `prev_checkpoint_hash` makes the checkpoint log
  append-only in the same sense the entry log is, so a rollback of the entry
  file alone leaves a checkpoint log that points past it.
- Different signature domain from receipts means a checkpoint cannot be
  replayed as a receipt, and vice versa.

### 3.4 Receipt attachment

After appending, the receipt gets a `ledger` member, excluded from the signed
payload exactly as `inclusion` and `attestations` already are:

```
"ledger": {
  "scheme": "verifyd-ledger-v1",
  "ledger_id": "<genesis checkpoint_hash>",
  "seq": 41,
  "checkpoint": { "tree_size": 128, "root_hash": "<hex>" },
  "path": ["<hex>", "<hex>", ...]
}
```

Adding `ledger` to the `omitKeys` list in `Signing.signingPayload` keeps a
receipt verifiable after its ledger block is attached, and lets a receipt be
appended later without re-sealing.

Consequence, stated because it is the same trap as batches: the block is
**outside** the signature, so it can be stripped or forged. A `ledger` block is
evidence only against a checkpoint the verifier already trusts; on its own it is
arithmetic. `verify` must print the same two-state distinction it already prints
for inclusion ("PROOF VALID, ROOT UNVERIFIED" vs "VALID").

---

## 4. Writer and concurrency model

One process appends at a time; over the life of a ledger, several authorized
writer keys may append (section 12). Not a distributed log, not multi-master.

### 4.1 Lock

`<ledger>.lock`, created with `fs.openSync(lockPath, 'wx')` - `O_CREAT|O_EXCL`,
atomic on POSIX and NTFS. Contents: writer PID, hostname, random nonce,
`created_at`, and the ledger path.

This is the same *property* the keyring relies on - exactly one creator wins a
race - reached by a different mechanism. The keyring builds a directory and
renames it into place (`createFreshKeyring` in `engine/signing.cjs`); a lock
cannot be renamed into a path that must stay absent, so it uses exclusive
create. Do not replace it with read-then-write, for the reason AGENTS.md gives
about the keyring rename.

Lock is a **mutex only**. It is never the record of truth; the entry log is.

### 4.2 Append sequence, in order

1. Acquire lock. On `EEXIST`, read the lock record and decide staleness (4.3).
2. Read the tail: last complete entry and the last checkpoint. Verify the last
   two entries link (`entry_hash`, `prev_entry_hash`, `seq`) before extending.
   A ledger with a broken tail is not extended - `LEDGER_CORRUPT`, exit non-zero.
   Fail closed at write time, not only at verify time.
3. Reject a duplicate `payload_digest` (`LEDGER_DUPLICATE`). The ledger has a
   `(digest -> seq)` index rebuilt at startup from the log.
4. Build the entry with `seq = tail.seq + 1`, then sign it with the appending
   writer key (3.1).
5. Append one line: `fs.openSync(file, 'a')`, single `fs.writeSync(fd, line)`,
   `fs.fsyncSync(fd)`, close. One line is far below any atomic-write limit, and
   `O_APPEND` keeps concurrent appends from interleaving - but concurrency is
   already excluded by the lock, so this is defence in depth.
6. `fsync` the containing directory on POSIX (new-file creation durability;
   no-op on Windows).
7. Build and sign the checkpoint covering the new tree size, append it to the
   checkpoint log with the same write+fsync discipline.
8. Update `<ledger>.state.json` (`seq`, `head_hash`, `checkpoint_hash`,
   `max_tree_size`) via temp file + rename + directory fsync, using the same
   temp-then-rename pattern as the unexported `writeAtomic` in
   `engine/signing.cjs` (either export that helper or move it to a shared
   module; do not add a second implementation).
9. Attach the inclusion path to the receipt, write the receipt, releasing the
   lock last.

If step 9 fails after step 7 succeeded, the ledger holds a correct entry and the
receipt lacks its block. That is recoverable, not corrupt: `chain proof`
regenerates the attachment from the ledger at any time. The command must say so
and exit non-zero rather than report a clean run - an operator who believes a
receipt is recorded when it is not is the failure mode this avoids.

`state.json` is a **cache of the newest observed position**, not an authority.
After a crash it may lag; it must never lead the log (4.4).

### 4.3 Staleness and reclaim

A lock is stale only if all of:

- `created_at` is older than `lock_ttl` (default 10 minutes; one append is
  milliseconds, so a 10-minute lock means a dead or hung writer), **and**
- the recorded host equals this host and the recorded PID is not alive
  (`process.kill(pid, 0)` throwing `ESRCH`).

Nothing else is auto-reclaimed. A live PID is never treated as dead, because
PIDs are reused; a foreign or unknown host is never treated as dead either.
Both cases exit `LEDGER_LOCKED` and require `--force-unlock` (13.9). The failure
direction is a stuck lock, not two writers.

Reclaim is itself serialized by renaming the stale lock to `<ledger>.lock.stale-<nonce>`
and re-attempting the exclusive create; if that create loses, another process
won. Reclaim writes a line to `<ledger>.repairs.log` with the old record.

Release unlinks the lock only after re-reading it and confirming the nonce
matches, so a process whose lock was reclaimed cannot delete its successor's.

`--force-unlock` exists, requires an explicit flag, prints the record it is
discarding, and is logged. It must never be a default.

### 4.4 Durability order and the crash window

Order is entry-fsync, then checkpoint-fsync, then state rename. Therefore the
only possible post-crash positions are:

- log ahead of state (crash between 7 and 8),
- log ahead of checkpoint log (crash between 6 and 7),
- a torn final line (crash during 5).

In every case the **log is the more advanced artifact**, which is why recovery
can adopt it after verifying the tail, while a state or checkpoint log that is
*ahead of* the entry log means data loss or truncation and must not be repaired
automatically.

---

## 5. Recovery matrix

`chain fsck` implements this. It repairs only the one case marked safe.

| Observed | Meaning | Action |
| --- | --- | --- |
| Final line is an unterminated fragment, and the last complete entry matches `state.seq` | crash during append | truncate to the last newline; log `TORN_TAIL_TRUNCATED`; safe |
| Final line parses and links, but `state.seq` is one behind | crash between append and state update | adopt the entry, rewrite `state.json`; no data change |
| Final line parses, `entry_hash` or `prev_entry_hash` wrong | tampering or bit rot in a complete record | `LEDGER_CORRUPT`; **no repair** |
| Bad line anywhere except the final fragment | tampering | `LEDGER_CORRUPT`; no repair |
| Entry file shorter than the newest checkpoint's `tree_size` | truncation or loss | `LEDGER_TRUNCATED`; no repair |
| Entry file longer than the newest checkpoint, with a valid link | normal unanchored append (checkpoint is per-append, so this means a crash in 7) | re-sign the missing checkpoint after verifying the tail |
| Entry file longer than the newest checkpoint, and the uncovered entry is a commitment seal | the checkpoint that sealed a revocation was lost | re-sign it with the admin that signed the entry and the record; the same narrow exemption verification grants, with no append authority |
| `state.seq` ahead of the entry log | data loss | `LEDGER_TRUNCATED`; no repair; report the missing range |
| Recompute root at a checkpoint size != signed root | history rewritten | `LEDGER_ENTRY_MISMATCH`; no repair |
| Two checkpoints at the same `tree_size` with different `root_hash`, or whose `prev_checkpoint_hash` does not extend the retained head | fork | `LEDGER_FORK`; no repair |
| Newest checkpoint older than the newest anchor | rollback of the whole ledger directory | `LEDGER_ROLLBACK`; no repair |

A second truncation of a torn tail requires `--repair-tail` explicitly and still
logs the bytes it discarded (hex, capped at 4 KiB) to `repairs.log`. Automatic
truncation on an already-truncated ledger is how evidence quietly disappears.

The "already truncated once" fact is kept in `<ledger>.torn-tail.json`,
written and fsynced before the bytes are discarded, and only its **existence**
is consulted. `repairs.log` is the audit trail of the action, not the guard: a
torn or damaged line in it must not be able to permit a second un-flagged
truncation, and an unreadable marker still blocks.

---

## 6. Verification

Three levels, with different inputs.

### 6.1 Local full verification

`chain verify --ledger <path> [--keyring <dir>]`

1. Parse every line strictly; a non-final malformed line is fatal.
2. Recompute each `entry_hash`; check `seq` is `1..n` with no gaps and that
   `GENESIS` is named only by seq 1; check `prev_entry_hash` linkage; reject a
   duplicate `payload_digest`; require `writer_key_id` to equal the key that
   signed the entry.
3. Rebuild the tree; for every checkpoint, recompute the root at its
   `tree_size` and compare.
4. Verify each checkpoint's Ed25519 signature against the trusted keyring, and
   judge authorization at signing time: a key removed from the writer policy by
   a later revocation still verifies signatures it made earlier (12.4).
5. Verify `prev_checkpoint_hash` chaining and that `tree_size` strictly
   increases.
6. For the checkpoint's anchor record: if a token is present, verify imprint and
   (with `--tsa-ca`) the chain.
7. If cosignatures are present, verify each against `--witness-keys`; count only
   distinct verified keys, exactly as the witness quorum code does. A missing
   anchor record is `UNANCHORED`, not a pass.

Prints one line per check and a final `Ledger: VALID` / `REJECTED`, exit 1 on
failure. Same presentation discipline as `verify`: each failure appears as its
own `Reason:` line.

### 6.2 Receipt membership

`verify <receipt> --ledger <path> [--anchor <checkpoint.json>]`

- Receipt has no `ledger` block: `Ledger: NOT RECORDED`, status unchanged.
  Absence is not a failure - receipts legitimately predate the ledger.
- Block present, recomputed root matches a checkpoint whose signature verifies
  and whose `ledger_id` matches: `Ledger: IN CHAIN (seq 41, tree 128, checkpoint VALID; anchor <state>)`.
- Block present, checkpoint signature valid but no anchor supplied:
  `Ledger: IN CHAIN (UNANCHORED)` - and the assurance model scores it as
  inclusion-without-an-authenticated-root, i.e. no credit.
- Block present, proof fails or the digest is absent: `Ledger: NOT IN CHAIN`,
  and the verdict is REJECTED **only if** the receipt claims ledger membership.
  A receipt that claims membership and cannot prove it is lying about its own
  evidence, which is the same rule already applied to `RATIFIED`.

### 6.3 Anchored verification (incremental)

`chain verify --ledger <path> --anchor <checkpoint.json>`

Verifies only entries `[anchor.tree_size, n)`, plus a consistency proof from the
anchor root to the current root (6.4). This is the check a third party runs
without holding the whole ledger, and the one that catches a fork or rollback.

### 6.4 Consistency proofs

Implemented in `engine/merkle.cjs` as RFC 6962 section 2.1.2 over the existing
tree rules:

- `Merkle.consistency(m, digests)` -> `{ scheme, m, n, root_m, root_n,
  prefix_mth, path }`, the path proving the tree of size `m` is a prefix of the
  tree of size `n`. `path` is SUBPROOF's list. `prefix_mth` is MTH(D[0:m]) and
  exists because roots here are size-prefixed (3.2): a verifier holding only
  `root_m` cannot fold the prefix, and the prefix hash cannot be recovered from
  a hashed size commitment.
- `Merkle.verifyConsistency({ m, n, rootM, rootN, prefixMth, path })` ->
  `{ ok, reason, computed_root }`. It checks `root_m` against `prefix_mth`,
  folds both roots from the path, and refuses a short, long, reordered or
  foreign path. `m = 0` is a prefix of everything and proves nothing about
  `root_n`, which the result states rather than implies.

The header no longer says consistency proofs are excluded; it names the
batch/ledger distinction instead: a batch is a set, and the append-only claim
belongs to the ledger's chained checkpoints.

---

## 7. The anchor

This is the part the current build does not have, and the part that decides
whether any of the above matters.

### 7.1 What each anchor actually buys

| Anchor | Kept where | Detects A1 | Detects A2 | Cost |
| --- | --- | --- | --- | --- |
| None (local log + local checkpoints) | same directory | yes | **no** | zero |
| RFC 3161 token per checkpoint | token file; only useful if a copy leaves the directory | yes | partially: backdating and checkpoint substitution, **not** a fresh forked history signed after the fact | one TSA call per checkpoint |
| Witness cosignature, n-of-m | each witness keyring, separately administered | yes | yes, unless the writer also controls a quorum | key ceremony per witness |
| Public append-only publication | sink the writer cannot rewrite | yes | yes: any retained older head exposes a fork | credential + sink choice |

The RFC 3161 row deserves precision, because it is often oversold: a token
proves *this root existed at time T*. It does not prove *no other root existed
at T*, and it cannot stop a writer from producing a second history later and
getting that one timestamped too. Tokens detect backdating; only retention by
someone else and comparison across retained heads detect forking.

### 7.2 Recommended configuration

Baseline, and what phases D-E implement:

- one signed checkpoint per append (cheap, local, pins the position);
- an RFC 3161 token and a witness cosignature on checkpoints at an **anchor
  interval** (default every 64 entries, or 24 h, or on `chain seal`);
- anchor records in `<ledger>.anchors.jsonl`, one per checkpoint, holding the
  token, cosignatures and publication proof for that `checkpoint_hash`; the
  newest is mirrored to `<ledger>.anchor.json`, which is the file an operator
  escrows or publishes. Checkpoints are never edited to add this evidence;
- verification calls a checkpoint `ANCHORED` only when a witness quorum or a
  publication record verifies. A token alone yields `ANCHORED-TIME`, which is
  not a fork control and does not satisfy `--require-anchor`. A local checkpoint
  is never described as anchored.

Witness cosignature reuses the existing keyring-per-witness model and quorum
counting, but checkpoints are a different statement type, so it is a
`checkpoint cosign` operation, not an overload of receipt attestation.
Separation of duties: the ledger signing key must not be a cosigning witness
key, and the quorum should be administered by people who do not operate the
ledger.

### 7.3 Publication sink

Decided in section 11: an independently operated public transparency log is the
primary anchor, with an operator-controlled append-only endpoint retained as an
availability fallback rather than as an independence claim. The adapter contract
and its verification rules are normative in section 13.8. A sink the operator
can rewrite is never counted as an anchor, and the README must say so.

---

## 8. Attack -> control

| Attack | Detected by | Result |
| --- | --- | --- |
| Edit a receipt file | signature check | `SIGNATURE_INVALID` |
| Edit a receipt and re-sign with another key | untrusted key / digest mismatch | `UNTRUSTED_KEY`, `LEDGER_ENTRY_MISMATCH` |
| Edit a receipt and re-sign with the ledger key | entry digest no longer matches its leaf | `LEDGER_ENTRY_MISMATCH` |
| Delete the last k entries | file shorter than the newest checkpoint `tree_size` | `LEDGER_TRUNCATED` |
| Delete a middle entry | `seq` gap plus root mismatch | `LEDGER_CORRUPT` |
| Reorder entries | root mismatch at every affected checkpoint | `LEDGER_ENTRY_MISMATCH` |
| Insert a forged entry | linkage or root mismatch; duplicate digest rejected | `LEDGER_CORRUPT` / `LEDGER_DUPLICATE` |
| Truncate mid-file | only a final unterminated fragment is repairable | `LEDGER_CORRUPT` |
| Rebuild the ledger and re-sign everything | consistency with a retained anchored checkpoint | `LEDGER_FORK` |
| Roll the directory back to an older copy | anchor newer than newest local checkpoint | `LEDGER_ROLLBACK` |
| Splice a real receipt's digest to a different receipt | digest is over signed bytes | `LEDGER_ENTRY_MISMATCH` |
| Strip a ledger block to hide membership | verifier with `--ledger` sees no block | `NOT RECORDED` (cannot be proven either way; documented) |
| Omit a receipt entirely | holder's own inclusion proof, or an auditor's count | outside the ledger's power; documented |

---

## 9. CLI surface (proposed)

```
node bin/verifyd.cjs chain init         [--ledger <path>] [--policy <policy.json>]
node bin/verifyd.cjs chain append       <receipt.json> [--ledger <path>] [--allow-multi-ledger]
                                        [--policy <policy.json>]
node bin/verifyd.cjs chain seal         [--ledger <path>] [--tsa] [--cosign]
node bin/verifyd.cjs chain verify       [--ledger <path>] [--anchor <anchor.json>] [--offline]
                                        [--policy <policy.json>]
                                        [--heads <file>] [--record-head]
                                        [--keyring <dir>] [--witness-keys <dir>] [--tsa-ca <pem>]
node bin/verifyd.cjs chain proof        <receipt.json> [--ledger <path>] [--out <proof.json>]
node bin/verifyd.cjs chain fsck         [--ledger <path>] [--repair-tail] [--dry-run] [--force-unlock]
                                        [--policy <policy.json>]
node bin/verifyd.cjs chain authorize    <pub.json> --role writer|admin
node bin/verifyd.cjs chain revoke-writer <key_id> [--revoked-at <iso>] [--reason <text>]
                                       [--policy <policy.json>]
node bin/verifyd.cjs chain publish      --sink <adapter> --anchor <anchor.json>
```

Plus:

- `audit <file> --ledger <path>`: append and attach after sealing. If the append
  fails, the receipt is still written and the command exits non-zero having
  printed `Ledger: NOT RECORDED (<reason>)`. A receipt that exists but was not
  recorded must not be reported as a success.
- `verify <receipt> --ledger <path> [--anchor <checkpoint.json>]`: section 6.2.

Default ledger path: `$VERIFYD_LEDGER` or `<keyring>/ledger.jsonl`. Keeping it
beside the keyring makes the custody boundary explicit: whoever holds that
directory holds the ledger *and* the signing key, which is exactly the A2 case
the anchor exists for.

---

## 10. Integration points

| File | Change |
| --- | --- |
| `engine/ledger-format.cjs` (new) | entry/checkpoint objects, domain tags, hashes, signing preimages. No I/O. |
| `engine/ledger-store.cjs` (new) | exclusive lock, durable append, state cache, and `inspectLedger`, the one read model every consumer uses. |
| `engine/ledger-recovery.cjs` (new) | `fsck`: findings in, the one automatic repair and a verdict out. |
| `engine/ledger-verify.cjs` (new) | `verifyLocal`: the shared inspection plus signature checks against trusted keys. |
| `engine/ledger.cjs` (new) | public facade; re-exports the four layers and keeps internal helpers off the contract. |
| `engine/ledger-anchor.cjs` (new, Phase E) | publication records, sink adapters, offline publication verification. |
| `artifacts/bundle-stage/` | tracked copy of `bin/verifyd.cjs`; must be regenerated with any CLI change or it becomes a stale second CLI. |
| `engine/merkle.cjs` | add `consistency()` and `verifyConsistency()`; correct the header that says consistency proofs are excluded. |
| `engine/signing.cjs` | add `ledger` to `signingPayload`'s `omitKeys`; checkpoint signing uses the existing `domain` option. No new crypto. |
| `engine/audit-chain.cjs` | retire or reduce to a compatibility shim. The current class has no lock, no fsync, no read-back, and nothing calls it with a path; keeping it as a second ledger implementation invites drift. |
| `engine/evidence.cjs` | new `ledger` evidence member and a `ledgerVerdict()`; `verdict()` rejects a claimed-but-unprovable membership. No second verdict path. |
| `bin/verifyd.cjs` | `chain` command group, `--ledger` on `audit` and `verify`, `Ledger:` output line mirroring the `Inclusion:` wording. |
| `bin/certify.cjs` | shows ledger position in the Subject section from the same evidence pass; never its own check. |
| `engine/trust-score.cjs` + calibration | add "ledger inclusion with authenticated checkpoint" as a scored dimension; refit, do not hand-tune. |
| `AGENTS.md`, `README.md` | document the guarantee and its limits verbatim from section 1 and 7.1. |

---

## 11. Decision: the trust anchor

Requirement: a copy of the ledger head that the ledger operator cannot alter, so
that an A2 rewrite is detectable by whoever retained the earlier head.

### 11.1 Options evaluated

**Option A - independently operated public transparency log (recommended).**

A CT-style append-only log (RFC 6962 / RFC 9162 shape): the publisher submits a
leaf, the log returns an inclusion proof and a signed tree head, and any third
party can fetch a head and compare it with one it retained. Concrete current
candidate: Sigstore Rekor v2 (GA October 2025). Facts that matter here, from the
project's announcement (https://blog.sigstore.dev/rekor-v2-ga/, retrieved
2026-10-23):

- tile-backed log with a single upload endpoint, `/api/v2/log/entries`;
- inclusion proofs are returned on upload and are meant to be persisted with the
  artifact;
- log shards have unique URLs distributed via TUF and are rotated, with explicit
  guidance not to hardcode them;
- only the `hashedrekord` and `dsse` entry types remain in v2;
- the log no longer returns signed timestamps; a TSA is a separate dependency;
- uploads are batched, so a publish takes seconds rather than milliseconds;
- log-integrated witnessing is announced as in progress, not as a shipped
  guarantee.

Guarantees: an independent operator enforces append-only; any verifier can
compare heads; a fork requires log misbehaviour (publicly monitorable) or the
publisher failing to publish. Availability: outside the org's control. Cost: low
or free on a public instance; a private instance stops being independent.
Privacy: permanent public metadata (13.14). Recovery: the log pins heads, it is
not a backup of the ledger.

**Option B - operator-controlled append-only endpoint.**

Self-hosted Rekor v2 or a Trillian-backed log, or object storage with
provider-enforced WORM retention plus independent mirrors. Same API shape, so
one adapter contract covers both.

Guarantees: detects deletion of the live ledger **if** a copy survives elsewhere;
does not detect an operator who rewrites the ledger and its own endpoint
together. Independence has to come from a mirror or escrow held by someone else
(auditor, regulator, customer). Availability and cost: under the operator's
control, cheap, no public metadata. Recovery: works offline; the right fallback
when the public log is unreachable.

| Dimension | Option A: independent log | Option B: operator endpoint |
| --- | --- | --- |
| Security against the operator | fork visible to anyone retaining a head; operator cannot rewrite the log | detects only if a copy survives elsewhere; operator can rewrite both |
| Availability | third-party outage, shard rotation, rate limits | operator-controlled, usable when offline |
| Cost | free or low on a public instance; a private one costs infrastructure and is no longer independent | storage plus mirror custody; cheap |
| Operational complexity | client must pin the log key (TUF), handle rotating URLs, and queue retries | run a log or WORM bucket and keep a second copy with someone else |
| Privacy | permanent public metadata: head size and cadence | metadata stays private |
| Recovery | pins heads, is not a backup; old shards must stay readable for old proofs | under operator control; verification works without a network |

**Option C - rejected.**

| Rejected | Why |
| --- | --- |
| Commit to the operator's own git branch | force-push rewrites it; no append-only enforcement |
| Local anchor file only | same directory, no independence |
| RFC 3161 only | proves a head existed, not that no competing head did |
| Per-checkpoint blockchain write | cost, latency, permanent public metadata |
| Manual notarization or email | not machine-verifiable, does not scale |

### 11.2 Recommendation

1. **Primary:** publish anchored checkpoints to an independent CT-style log. The
   first adapter targets the Rekor v2 API; the instance and its TUF-distributed
   URL are chosen at Phase E and never hardcoded.
2. **Secondary:** an operator-controlled append-only endpoint (WORM storage or a
   self-hosted log) so verification survives a public-log outage. Labelled as
   *not independent* everywhere it appears.
3. **Tertiary:** RFC 3161 token and witness cosignatures on anchored checkpoints.

A checkpoint is `ANCHORED` only when a publication record or a witness quorum
verifies. Local signatures alone, however many, produce `UNANCHORED`.

### 11.3 What a verifier can prove, per deployment mode

| Deployment | Proves | Does not prove |
| --- | --- | --- |
| local ledger only | internal consistency; outsider tampering detected | anything against the operator |
| + org endpoint or mirror | operator deletion detected if a copy survived elsewhere | against an operator controlling both copies |
| + RFC 3161 | this head existed by time T | no competing history |
| + witness quorum | a fork needs m colluding witnesses | that witnesses are actually independent |
| + independent log | a fork contradicts a published head; any retained head exposes it | the log's own honesty; ledger completeness |

### 11.4 Failure behavior

- Sink unreachable at append: append succeeds locally, checkpoint stays
  `UNANCHORED`, a durable retry record is written, `anchor_overdue` is reported
  after the cadence deadline. The ledger never blocks on an external service.
- Sink unreachable at verification: `ANCHOR_UNCHECKED`, printed distinctly;
  `--require-anchor` makes it a rejection.
- Log shard rotated or retired: each publication record keeps the URL and log key
  it was made under. Verification of an old record uses the pinned key, not
  today's URL.
- Publication accepted but never retrievable again: treated as unanchored. A
  publication record with no verifiable proof earns nothing.

---

## 12. Decision: ledger scope and authorization

### 12.1 Scope

One ledger per organization. Departmental or project partitions are separate
ledgers created explicitly, never a side effect of pointing at a different
keyring.

### 12.2 Identity

`ledger_id = checkpoint_hash(genesis)`, where genesis is the tree_size-0
checkpoint. It is self-certifying: two ledgers cannot share an id unless their
genesis bodies and signatures collide, and a verifier that pins genesis pins the
ledger.

The genesis body carries the literal `"ledger_id": "GENESIS"` as a placeholder.
It cannot carry the derived value: that value is the hash of the body, so
putting it inside the body would be circular. Every later checkpoint and every
entry records the derived id, and verification checks that genesis says
`GENESIS` and that everything after it agrees on the derived value.

The implemented genesis body carries `created_at` and `policy_hash` only. The
full policy body (`writer_keys`, `admin_keys`, `witness_policy`) is committed by
that hash and is carried beside the ledger as `<ledger>.policy.json`; append and
verification read it, recompute `policyHash`, and refuse a body that does not
hash to `policy_hash` (`LEDGER_POLICY_MISMATCH`) or that is absent
(`LEDGER_POLICY_MISSING`). `--policy <file>` supplies the same body to
`chain verify`, `chain append` and `chain fsck` when the sidecar is lost; it
passes the same check, so an explicitly supplied file is never trusted on its
face. The file is transport, not trust: swapping it for a
different policy changes the hash and fails closed.

Earlier drafts of this section also listed `org_id`, `ledger_name`,
`partition_of` and the key lists inside the body. None of those are in the v1
bytes, and adding them now would change every `ledger_id`; they stay Phase D4
(`successor_of`) or operator metadata rather than v1 genesis fields.

### 12.3 Who may append

- Every entry names `writer_key_id` and carries that key's signature (3.1).
- `chain append` requires the key to appear in `writer_keys`, be active, and be
  unrevoked.
- Implemented in D1 (`engine/ledger-policy.cjs`): the policy body is resolved
  from the sidecar (or `opts.policy`), checked against the genesis commitment,
  and `signature.key_id` is authorized for every entry and checkpoint at that
  record's own signed timestamp. A keyring record that is revoked or expired at
  that timestamp fails `LEDGER_KEY_NOT_ACTIVE`; a `retired` key does not, so
  rotation leaves past records valid. For a write the status source is
  mandatory: the keyring named by `opts.keyring` or by the `keyringSigner` that
  built the signer, re-read at append time so a revocation made after the
  signer was built still refuses. A signer whose record cannot be read is
  refused `LEDGER_KEY_NOT_ACTIVE`; policy membership alone never authorizes a
  write. A verifier that supplies only a trusted key map has no status to
  consult and authorizes on membership alone.
- Several keyrings may hold authorized writers; the lock serializes them. A
  writer cannot attribute an entry to another key because the entry signature
  would fail.
- Genesis is immutable in v1. Changing writers, admins or the witness policy
  creates a successor ledger with a cross-signed `successor_of` record;
  historical checkpoints keep the policy they were made under. Restrictive by
  design: in-place policy amendments invite ambiguity about which policy applied
  at which tree size.

### 12.4 Revocation and rotation

- `chain revoke-writer <key_id>` records an admin-signed statement and seals it
  into the ledger. The record is `{scheme, ledger_id, key_id, revoked_at,
  recorded_at, head_tree_size, head_checkpoint_hash, reason, signature}` signed
  under `verifyd-ledger-revocation-v1\n` and canonicalized by JCS like every
  other ledger record; it is written to `<ledger>.revocations.jsonl`.
- The record is evidence only once the ledger holds its commitment: an ordinary
  entry whose `payload_digest` is the digest of the signed record and whose
  `receipt_id` is `verifyd-revocation:v1:<key_id>`, sealed by an active writer
  through the normal entry/checkpoint path or, when the admin is not a writer
  and no writer is named, by the admin under the narrow exemption below. The
  file is a rendering of those
  commitments. A commitment with no record is `LEDGER_REVOCATION_MISSING`
  (including an absent file); a record with no commitment is
  `LEDGER_REVOCATION_UNCOMMITTED`. Neither is ever read as "no revocation".
  The sealing key may differ from the admin who signs the revocation
  (`--writer-keyring`). When the admin is not a writer and no writer is named,
  the admin seals the commitment itself: `admin_keys` authorises that one entry
  and the checkpoint at its tree size, because the alternatives are to let the
  revoked key make the seal (the one append it would still be allowed) or to
  make a single-writer ledger impossible to revoke. Either branch is scoped to
  the record it seals: the exemption is personal, so a writer may use it only
  for the revocation of its own key and an admin only for a record that admin
  signed. A different listed writer seals the same entry as an ordinary append
  at its own position, where the target's boundary does not reach it. The
  exemption covers the entry
  whose payload digest is that committed record (its first occurrence) and the
  checkpoint that covers it; neither sealer gains ordinary append authority,
  and the admin's next receipt append still fails `LEDGER_POLICY_MISMATCH`.
  The marker sits outside the receipt-id vocabulary: `append` and `chain append` refuse any receipt id beginning
  `verifyd-revocation:v1:` (`LEDGER_RECEIPT_ID_RESERVED`) before taking the
  lock, and the store's write helper accepts the marker only from the sealing
  path. A receipt therefore cannot claim the marker deliberately or by accident,
  and cannot turn a normal append into an apparent revocation commitment.
- The signer must appear in `admin_keys`, and its key status must be readable at
  `recorded_at` (the same write-path rule as append). Revoking a key outside
  `writer_keys` is `LEDGER_REVOCATION_UNKNOWN_WRITER`; a second record for one
  key is `LEDGER_REVOCATION_DUPLICATE`, because two effective dates for one key
  would make the boundary depend on line order.
- Authority is decided by position. The signed `head_tree_size` and
  `head_checkpoint_hash` name the head the admin saw, so every entry past that
  head lies outside that history and is refused `LEDGER_WRITER_REVOKED`
  whatever its `recorded_at` claims: a writer that turns its clock back cannot
  place a new entry before the boundary. Entries up to the bound head stay
  valid, because `revoked_at` is required to postdate all of them. The
  commitment entry is exempt by digest, never by label, and only for the key
  the digest revokes: a writer may place the seal of its own revocation past
  its boundary, and nothing else. An admin seal is bound the same way, to the
  record that admin signed.
- `revoked_at` must be strictly after every record up to the head the record
  names, and after the record's own `recorded_at`
  (`LEDGER_REVOCATION_BACKDATED`). `revoke-writer` always binds the current
  head, so a record it writes can never invalidate an entry that already
  exists; the write verb cannot backdate. A hand-written record is bounded
  only by the head it names: if that is an older retained checkpoint, entries
  already written past it are refused by position, even though they existed
  when the record was written. That takes an admin signature and a committed
  entry, and it is the deliberate cost of deciding authority by position. The
  guarantee is that a revocation cannot predate the head it binds, not that it
  can never reach back past entries the ledger already holds.
- `revoked_at` is the admin's clock. It dates the statement and orders records
  inside the bound head; it is not evidence of when a key was actually
  compromised, and it is not what refuses new entries - position is.
- A lost sidecar has a repair path. `chain verify --revocations <file>` reads a
  supplied file as an alternate source and writes nothing; `chain
  restore-revocations <file>` runs the same authentication and then rewrites
  `<ledger>.revocations.jsonl` only if every record matches a commitment digest
  and every commitment has a record. A supplied file is not trusted because it
  was supplied: signature, admin membership, bound head and boundary are all
  rechecked, so restoration can reproduce authority the ledger already
  committed to but cannot mint new authority. Rebuilding a record from a
  commitment digest alone is not accepted and is not offered. The repair is
  all-or-nothing: the whole ledger is verified with the backup in place before
  the write, and verified again after it, with the previous sidecar restored if
  the result does not stand. A supplied path that is missing or unreadable is
  `LEDGER_IO`, and a supplied file that holds no records is
  `LEDGER_REVOCATION_MALFORMED`; `LEDGER_REVOCATION_MISSING` is only the
  ledger's own verdict that a committed record has no sidecar.
- Every record is verified before it is used: scheme and shape, the signer's
  admin membership, the signature, the signer's status at its own
  `recorded_at`, the bound head, the boundary and its commitment. A file that
  exists but cannot be authenticated is `LEDGER_REVOCATION_UNAUTHORIZED` or
  `LEDGER_REVOCATION_MALFORMED`, never treated as an empty set. The trust store
  (keyring records, or the trusted key map a programmatic verifier supplies)
  must therefore hold the public keys of the admins that signed the records;
  the embedded `public_key` is checked against it, never trusted on its own.
- Revocation ends writer authority only. An admin who is also a writer keeps the
  admin role; changing `admin_keys` still requires a successor ledger.
- Rotation is a new writer key in a successor ledger, not an in-place mutation.

### 12.5 Which ledger is authoritative

A receipt cannot appoint its own authority. The verifier supplies the trusted
genesis checkpoint or anchor path; a receipt's `ledger_id` is only a claim to
match against it. A block naming an unknown ledger is `LEDGER_UNKNOWN`, not
"valid in some other ledger".

### 12.6 Cross-ledger references, mergers, migration

- v1 permits at most one ledger entry per receipt. `--ledger` refuses a receipt
  that already carries a block for a different ledger
  (`LEDGER_ALREADY_RECORDED`) unless `--allow-multi-ledger` is passed.
- No tree merging. A successor ledger starts empty and points at its
  predecessor; verifiers check both independently.
- Backup and restore are a rollback problem (13.10), not a migration.

---

## 13. Normative specification

Where this section and the descriptive text above differ, this section governs.

### 13.1 Canonical data format

- Versioned scheme strings: `verifyd-ledger-v1` for entries and checkpoints.
  A verifier that does not recognise the scheme or version refuses
  (`LEDGER_UNSUPPORTED`); it never best-effort parses.
- Serialization is RFC 8785 JCS from `engine/canonicalize.cjs`. No new
  canonicalizer.
- Numeric fields are integers within the safe range. Floats, `NaN` and
  `Infinity` are rejected at parse time, not rounded: JCS on floats is a
  cross-runtime hazard, and there is no field here that needs one.
- Hashes are lowercase hex SHA-256. Signatures are base64 Ed25519. Timestamps
  are ISO 8601 UTC strings.
- Domain separation registry. Every preimage carries exactly one tag:

| Tag | Use | Preimage |
| --- | --- | --- |
| `verifyd-receipt-v1\n` | receipt envelope signature (existing) | canonical envelope sans `signature`, `timestamp`, `inclusion`, `attestations`, `ledger` |
| `verifyd-merkle-root-v1\n` | batch root signature (existing) | canonical batch root object |
| `verifyd-chain-checkpoint-v1\nsig\n` | checkpoint signature | canonical checkpoint sans `signature` |
| `verifyd-chain-checkpoint-v1\nhash\n` | checkpoint hash | same body as above |
| `verifyd-ledger-entry-v1\nhash\n` | entry hash | canonical entry sans `entry_hash`, `signature` |
| `verifyd-ledger-entry-v1\nsig\n` | entry signature | canonical entry sans `signature` |
| `verifyd-ledger-policy-v1\n` | policy hash | canonical `{writer_keys, admin_keys, witness_policy}` |
| `verifyd-chain-cosign-v1\n` | witness cosignature | canonical cosign statement (13.6) |
| `verifyd-chain-publication-v1\n` | publication statement | canonical statement (13.8) |
| `verifyd-ledger-revocation-v1\n` | admin revocation record | canonical revocation body sans `signature` |

- Phase A commits fixed test vectors: for each domain, the exact bytes and the
  expected hash for one canonical sample, asserted byte-for-byte. A vector that
  changes between Node versions is a defect, not a test update.

### 13.2 Checkpoint structure

```
{
  "scheme": "verifyd-ledger-v1",
  "checkpoint_type": "ledger",
  "ledger_id": "<genesis checkpoint_hash>",
  "tree_size": 128,
  "root_hash": "<hex>",
  "created_at": "2026-10-23T12:00:00.000Z",
  "prev_checkpoint_hash": "<checkpoint_hash at size 127, or GENESIS>",
  "policy_hash": "<sha256 of the genesis writer/witness policy body>",
  "signature": { "algorithm": "ed25519", "key_id": "ed25519:...", "public_key": "...", "value": "..." }
}
```

- `tree_size` is both the tree size and the sequence number in v1: each entry is
  followed by exactly one checkpoint, so a checkpoint whose size is not
  `previous + 1` is a defect.
- Genesis is the only checkpoint with `tree_size` 0 and `ledger_id: "GENESIS"`.
  Its `checkpoint_hash` defines the `ledger_id` that every later checkpoint and
  entry must carry. A later checkpoint carrying a different id is treated as a
  different ledger, not as a defect in this one.
- `policy_hash = sha256('verifyd-ledger-policy-v1\n' + JCS({writer_keys,
  admin_keys, witness_policy}))`. Key lists are sorted ascending and must be
  duplicate-free before hashing, so one policy written in two orders is one
  ledger rather than two; the witness policy object is hashed as given. It
  binds the checkpoint to the genesis policy,
  prevents a mid-log policy swap without a new ledger, and is why 12.3 forbids
  in-place amendments.
- Tokens, cosignatures and publication proofs are **not** checkpoint fields and
  are never written into a checkpoint line. They live in anchor records bound to
  `checkpoint_hash` (13.8), because they cannot exist at signing time and because
  editing a written checkpoint would break the append-only property.
- Their absence is reported, never assumed: a checkpoint without an anchor record
  is `UNANCHORED`, not "anchored by default".

### 13.3 Receipt binding

- `payload_digest = SHA-256(Signing.signingPayload(receipt))`, the same digest
  the batch code computes, so a batch leaf and a ledger leaf commit to identical
  bytes.
- The entry signature covers `payload_digest` (it is inside the signed body), and
  the checkpoint covers the leaf, so binding a receipt to a checkpoint is: entry
  signature -> leaf -> inclusion path -> checkpoint root -> checkpoint signature
  -> publication record.
- `Signing.signingPayload` must add `ledger` to `omitKeys`. For receipts that do
  not contain a `ledger` member the canonical bytes are unchanged, so every
  existing signature still verifies; this is a compatibility requirement, not a
  convenience.
- The `ledger` block is unsigned. It is a claim until checked against a pinned
  checkpoint, exactly like `inclusion`. `verify` must never print it as proof on
  its own.
- **`receipt.prev_hash` is not ledger linkage.** It is sealed inside the signed
  receipt, so it cannot be set to the previous entry at append time; in every
  shipped receipt it is `GENESIS`. It stays as a legacy field, is never used for
  ordering, and the ledger's own `prev_entry_hash` is authoritative. Do not
  "fix" it by pre-allocating an entry before sealing: that would create a
  reserved-but-unwritten sequence and a new crash-recovery problem.

### 13.4 Merkle verification

Rules are those in 3.2, unchanged from `engine/merkle.cjs`.

| Proof | Proves | Does not prove |
| --- | --- | --- |
| inclusion (index, size, path) | this leaf is at that position in a tree of that size with that root | that the tree is the whole ledger, or that the receipt is honest |
| consistency (m, n) | the tree of size m is a prefix of the tree of size n | that nothing was omitted before m, or that either head is published |
| checkpoint signature | a trusted key signed this exact root and size | that the key holder was authorised beyond the keyring, or that time passed |
| publication record | a log included this statement by a stated tree size | that the log is honest, or that no other head was published |

A batch root is not a checkpoint: batch roots are signed under
`verifyd-merkle-root-v1\n` over a root object, checkpoints under
`verifyd-chain-checkpoint-v1\n` over a checkpoint body. Neither verifies as the
other.

### 13.5 Fork detection

Verifier rules, applied in order. `retained` means heads the verifier kept
(`--heads <file>`, append-only) or an anchor it was given.

| Rule | Condition | Result |
| --- | --- | --- |
| F1 | same `ledger_id`, same `tree_size`, different `root_hash` | `FORK` |
| F2 | larger head whose consistency proof from a retained head fails | `FORK` |
| F3 | two different `checkpoint_hash` values at one size for one ledger | `FORK_EQUIVOCATION` |
| F4 | observed head smaller than a retained head | `ROLLBACK` |
| F5 | `prev_checkpoint_hash` not equal to the checkpoint at `size - 1` | `FORK` |
| F6 | publication proof does not include the checkpoint leaf it names | `ANCHOR_WITHHELD` (unanchored, incident) |

On F1-F3 the verifier emits both heads and exits non-zero. It never chooses the
newer or the longer one: choosing is how a fork becomes a silent rewrite. Both
heads are retained as evidence, and an incident line is appended to
`<ledger>.incidents.jsonl`.

### 13.6 Witness protocol

- Cosign statement: `{scheme, ledger_id, checkpoint_hash, tree_size, root_hash,
  witness_key_id, identity, cosigned_at}` signed under
  `verifyd-chain-cosign-v1\n`. Binding `ledger_id` and `checkpoint_hash` makes a
  cosignature unusable on another checkpoint or ledger, which is the replay
  defence.
- Threshold `m of n` is fixed in the genesis `witness_policy`. Counted by
  distinct verified keys, never by labels, reusing `engine/witness.cjs` identity
  binding.
- Recusal: a witness whose key is also a `writer_key` for this ledger does not
  count; the audited party's key does not count. This mirrors the existing
  self-witness rule rather than inventing a second one.
- Revocation: cosignatures from a revoked key do not count for checkpoints whose
  `created_at` is after `revoked_at`. Since `created_at` is the writer's clock,
  this detects carelessness, not a determined backdater; only a TSA makes the
  ordering of revocation and cosignature evidence.
- Rotation: new witness keys require a successor ledger (12.3).
- Quorum unavailable: checkpoints stay `UNANCHORED`, appends continue, and
  `anchor_overdue` is reported after the cadence deadline. Availability is not
  sacrificed for a label, and the label is not granted for availability.
- Collusion limit: `m` witnesses can always fabricate a consistent alternative
  history. The control is independence of administration, which is an
  organizational property this design cannot enforce.

### 13.7 Timestamp semantics

- Stamped object: the checkpoint signature payload (domain tag plus canonical
  body). `messageImprint` must equal `SHA-256` of exactly those bytes, so a token
  cannot be moved to another checkpoint. The token is stored in that checkpoint's
  anchor record, never appended to the checkpoint line.
- Proves: the checkpoint existed, with that content, no later than `genTime`.
- Does not prove: that no other checkpoint existed at that time; that the ledger
  is complete; that the writer's local clock was right.
- States mirror the receipt path: `ATTESTED` only when a configured CA chain
  verifies; `UNVERIFIED` when the token is structurally valid and no root is
  configured (exit stays 0); `INVALID` for imprint, signature or chain failure
  (exit non-zero). A missing token is `UNATTESTED`, never assumed.

### 13.8 Publication protocol

Publication statement, minimal by design:

```
{ "scheme": "verifyd-chain-publication-v1",
  "ledger_id": "<hash>",
  "tree_size": 128,
  "root_hash": "<hex>",
  "checkpoint_hash": "<hex>" }
```

It contains no receipt ids, no document names and no `org_id`.

Anchor record, appended to `<ledger>.anchors.jsonl` and mirrored in
`<ledger>.anchor.json` for the newest head. Records are additive: a later record
for the same checkpoint may add evidence (a token obtained after the sink came
back), and may never contradict an earlier one. `<ledger>.anchors.jsonl` is
append-only, so no record is edited after it is written.

```
{ "scheme": "verifyd-ledger-v1",
  "checkpoint_hash": "<hex>",
  "ledger_id": "<hex>",
  "tree_size": 128,
  "recorded_at": "2026-10-23T12:00:00.000Z",
  "timestamp": { "type": "rfc3161", ... },        // optional, 13.7
  "cosignatures": [ { "key_id": "...", "identity": "...", "signature": "..." } ],
  "publication": { ... } }
```

Its `publication` member is the publication record:

```
{ "scheme": "verifyd-ledger-v1",
  "checkpoint_hash": "<hex>",
  "statement_digest": "<sha256 of the statement bytes>",
  "sink": { "kind": "ct-log|worm-object|local-mirror", "url": "<as used>",
            "log_key_id": "<pinned>", "trust_root": "<TUF snapshot or key ref>" },
  "proof": { "leaf_index": 12, "tree_size": 9001, "path": ["<hex>"],
             "signed_tree_head": { ... }, "sth_signature": "..." },
  "published_at": "...", "sink_entry_id": "..." }
```

Adapter contract (one interface, several sinks):

1. Append-only. The adapter must never offer overwrite or delete; if the sink
   does, the adapter is rejected in review.
2. Returns an inclusion proof at a signed tree head under a key the operator
   pins out of band (TUF or a committed key), not a key fetched on the same
   connection that served the proof.
3. Idempotent on retry, keyed by `checkpoint_hash`, so a retry after a timeout
   cannot publish a second leaf for the same head.
4. No hardcoded URLs. The Rekor v2 shard URL rotates; the adapter reads its URL
   and trust root from configuration recorded in the publication record.
5. Failure leaves the checkpoint `UNANCHORED`; it never fabricates a proof.

Two anchor records for one checkpoint that disagree on `ledger_id`, `tree_size`
or the publication statement are `ANCHOR_CONFLICT`, never "the better of the
two".

Verification of a record, offline where possible:

1. The statement's `checkpoint_hash` matches a checkpoint the verifier trusts.
2. `statement_digest` equals the hash actually submitted.
3. The inclusion path recomputes to the signed tree head's root at the stated
   size, and the head's signature verifies under the pinned log key.
4. When online, the current head is fetched and a consistency proof from the
   publish-time head to it verifies; failure is a split-view signal.
5. Where two independent retrieval paths exist, their heads are compared and any
   mismatch is `FORK_VIEW`.

`ANCHOR_UNCHECKED` is the state when a record exists but cannot be checked now
(sink down, no network, malformed proof). It is not `ANCHORED`.

### 13.9 Single-writer safety

- Lock record: `{pid, host, boot_id (when available), nonce, created_at,
  ledger_path, tool_version}`. `boot_id` is read from the platform where it
  exists and omitted where it does not; an absent `boot_id` never makes a lock
  reclaimable on its own.
- Acquisition writes the record to a private temporary file, fsyncs it, then
  hard-links it to `<ledger>.lock`; the shared path never holds a half-written
  record, and a crash leaves only an orphan temporary file. Where hard links are
  unavailable, `O_CREAT|O_EXCL` is used and a partial file is removed on failure.
- A live PID is **never** auto-reclaimed, even past the TTL, because PIDs are
  reused: a recycled PID would otherwise turn a stale lock into two writers. A
  live-but-stale lock exits `LEDGER_LOCKED` and requires `--force-unlock`, which
  prints the record and logs the override. The failure direction is a stuck
  lock, not a double append.
- A record that cannot be read or attributed (empty, malformed, or missing
  `pid`/`host`/`nonce`/`created_at`) is never auto-reclaimed and is reported as
  unreadable, not as an unknown pid. `--force-unlock` does discard it, recording
  the raw bytes it discarded, so a lock broken by a crash cannot wedge the
  ledger permanently.
- A foreign host is never auto-reclaimed; TTL expiry alone is not proof of death.
- Release re-reads the lock and unlinks only on nonce match, so a reclaimed
  owner cannot delete its successor's lock.
- The lock is held only across file operations, never across a prompt, a network
  call, or a publication attempt.
- Network filesystems: `O_EXCL` and `O_APPEND` are not reliable on all NFS/SMB
  servers. A ledger on a UNC path is refused by default; `--allow-network-fs`
  prints the caveat and is documented as unsupported.

### 13.10 Durability and recovery

Additions to sections 4.4 and 5.

| Condition | Behavior |
| --- | --- |
| short write or `ENOSPC` during entry append | capture pre-append size, `ftruncate` back, fsync, fail `LEDGER_WRITE_FAILED`; if the truncate fails, `LEDGER_CORRUPT` |
| `EACCES`/`EPERM` on any write | same rollback rule; no partial state accepted |
| checkpoint write fails after entry fsync | entry is durable, checkpoint absent; fsck re-signs it from the log (deterministic, same key) |
| `state.json` rename fails | benign lag; next append recomputes from the log |
| state or checkpoint log ahead of entries | `LEDGER_TRUNCATED`; never repaired automatically |
| final fragment contains NUL padding | still a torn tail if unterminated; a NUL inside a complete line is corruption |
| disk full during fsck repair | stop, leave the ledger byte-identical |
| read-only verification | `verify`, `chain verify`, `chain fsck --dry-run` open read-only and must not create or touch any file |

Platform notes: directory `fsync` is available on POSIX and not on Windows, so
power-loss durability is weaker there and the docs must say so. Rename is atomic
only within one filesystem; state and ledger must share a directory. A backup
restore is a rollback: restore the full ledger where possible, compare against
the retained anchor, record an incident, and never re-anchor a shorter history
under the same `ledger_id` - a shorter history with the same id is exactly the
fork 13.5 is built to detect. If the full ledger is unrecoverable, the surviving
history becomes a successor ledger.

### 13.11 Verification modes

| Mode | Command | Prerequisites | Proves | Does not prove |
| --- | --- | --- | --- | --- |
| receipt only (today) | `verify <receipt>` | keyring, artifact | signature, hash, artifact, witnesses, determination | any ledger membership |
| full local | `chain verify --ledger` | ledger, keyring | every entry links, every checkpoint matches, signatures valid | that any head was published |
| membership | `verify --ledger [--anchor]` | receipt, ledger, checkpoint | this receipt is in this checkpoint | that the checkpoint is anchored |
| anchored incremental | `chain verify --ledger --anchor` | anchor, ledger tail | prefix consistency with a published/retained head | completeness before the anchor |
| publication replay | `chain verify --anchor --offline` | anchor file, pinned log key | the head was included by that log at that size | freshness after the last publication |

A verifier must state which mode it ran. "Verified" without a mode is not a
result.

### 13.12 Failure semantics

Ledger labels, printed on their own line, never folded into `Status: VALID`:

```
Ledger: NOT RECORDED
Ledger: IN CHAIN (UNANCHORED)
Ledger: IN CHAIN (ANCHORED-TIME: no fork detection)
Ledger: IN CHAIN (ANCHORED-WITNESS: 2 of 3)
Ledger: IN CHAIN (ANCHORED-PUBLISHED: ct-log)
Ledger: NOT IN CHAIN
Ledger: INCONSISTENT (<code>)
Ledger: FORK (<detail>)
Ledger: ROLLBACK (<detail>)
Ledger: TRUNCATED (<detail>)
Ledger: UNKNOWN LEDGER
```

| Ledger state | Default exit | `--require-anchor` |
| --- | --- | --- |
| `NOT RECORDED` | 0 | 1 |
| `IN CHAIN (UNANCHORED)` | 0 | 1 |
| `IN CHAIN (ANCHORED-TIME)` | 0 | 1 (time alone is not a fork control) |
| `IN CHAIN (ANCHORED-WITNESS)` / `(ANCHORED-PUBLISHED)` | 0 | 0 |
| `NOT IN CHAIN` on a receipt that claims membership | 1 | 1 |
| `INCONSISTENT`, `FORK`, `ROLLBACK`, `TRUNCATED` | 1 | 1 |
| `UNKNOWN LEDGER`, `UNSUPPORTED` | 1 | 1 |

Rules: no corrupted, missing, untrusted or unverifiable evidence may become
`VALID`. A missing ledger supplied by the caller is an error, not an absence. A
receipt with no claim is not penalised for predating the ledger. `certify` reads
the same evidence object; it never grows its own ledger check.

### 13.13 Compatibility

- Existing receipts: unchanged. Adding `ledger` to `omitKeys` does not alter the
  canonical bytes of a receipt that lacks the member, so old signatures verify
  exactly as before.
- Shipped `examples/` receipts are not regenerated and stay `NOT RECORDED`.
- `receipt.prev_hash` stays `GENESIS`; it is never retroactively reinterpreted as
  a ledger link (13.3).
- Batches are unaffected. A receipt may carry both `inclusion` and `ledger`; the
  two prove different things and both blocks are unsigned.
- `artifacts/bundle-stage/` contains a tracked copy of `bin/verifyd.cjs`
  (verified with `git ls-files`). A ledger change must regenerate or remove that
  copy in the same commit; a stale CLI that reports `NOT RECORDED` for a
  recorded receipt is worse than no CLI.
- `package.json` ships `engine/` and `bin/` wholesale, so new modules need no
  `files` change; no new `bin` entry is required.
- The assurance model has no ledger dimension today. Adding one requires
  `scripts/calibrate-trust.cjs --write` and the README numbers, which a test
  asserts; it is never hand-tuned.

### 13.14 Privacy and retention

- Published: root, size, `ledger_id` (a hash), statement digest, times. Not
  published: receipt ids, document names, `org_id`, entry digests.
- Public-log entries are permanent. A mistaken publication cannot be retracted,
  which is a reason to publish only at cadence and to rehearse on a throwaway
  ledger before Phase E.
- Tree size and cadence leak activity volume. If that is unacceptable, the
  operator chooses Option B and accepts the weaker guarantee; both cannot be had.
- Retention: the ledger is retained indefinitely. v1 has no pruning, because a
  pruned ledger with the same id is indistinguishable from a truncation.
- Erasure requests conflict with append-only. The only supported response is a
  tombstone entry referencing the erasure, plus a legal decision about whether a
  hash is personal data in the relevant jurisdiction. This design does not
  resolve that; it records that it must be resolved before production use.
- Access to the ledger is not audit-logged by this design. That is a gap, not a
  control.

---

## 14. Implementation phases

Dependency-ordered. No phase may be described as delivering more than its
acceptance criteria show.

### Phase A - formats, hashing, test vectors

**Delivered** (revision 2a). 11 tests, all passing; `npm test` 187/187.

Files: `engine/ledger.cjs` (objects and hashing only), `engine/test/ledger-format.test.cjs`.
Depends on: nothing.
Migration risk: none; no existing code path changes.
Test: `node --test engine/test/ledger-format.test.cjs`.
Acceptance:
- fixed byte-and-hash vectors for all nine domain tags, committed and stable;
- JCS numbers restricted to integers, floats rejected with a named error;
- genesis (size 0) root reproducible without calling `Merkle.buildTree([])`;
- unknown scheme/version refused;
- `git status` shows no artifact or receipt change.

### Phase B - persistent single-writer ledger and crash recovery

Files: `engine/ledger.cjs`, `engine/audit-chain.cjs` (thin deprecation shim or removal),
`engine/test/ledger-writer.test.cjs`, `engine/test/ledger-recovery.test.cjs`.
Depends on: A.
Migration risk: `AuditChain` callers in `bin/verifyd.cjs`, `examples/audit-paper.cjs`,
`examples/run-example.cjs`, and the tracked `artifacts/bundle-stage` copy.
Test: `node --test engine/test/ledger-writer.test.cjs engine/test/ledger-recovery.test.cjs`.
Acceptance:
- 8 concurrent appenders: contiguous `seq`, one winner per seq, no interleaving;
- crash injected at each of the five durability boundaries, fsck outcome matches
the section 5 matrix, and no case repairs silently twice;
- short write and `ENOSPC` roll back to the pre-append size;
- a live-PID stale lock blocks and requires `--force-unlock`;
- a reclaimed former owner cannot unlink the successor's lock;
- failed append leaves the receipt file and ledger byte-identical apart from the
intended failure notice.

Delivered: the log (entries, `.checkpoints.jsonl`, `.state.json`, `.lock`,
`.repairs.log`), `initLedger`, `append`, `verifyLocal` (section 6.1 steps 1-5)
and `fsck` (section 5) are split across `engine/ledger-format.cjs`,
`engine/ledger-store.cjs`, `engine/ledger-recovery.cjs` and
`engine/ledger-verify.cjs` behind the `engine/ledger.cjs` facade. One inspection
result (`inspectLedger`) serves `readLedger`, `fsck` and `verifyLocal`; none of
them walks the log itself. `engine/signing.cjs` exports its
single `writeAtomic` helper with optional fsync and an injectable filesystem, so
the state cache reuses that one atomic-replace implementation instead of a
second copy. Receipts are untouched: `signingPayload` still omits only
`signature`, `timestamp`, `inclusion` and `attestations`, so no receipt gains a
`ledger` block this phase and no signature changes.

Three details the earlier sections left open, now fixed:

- `checkpoint_hash` is excluded from its own hash preimage, as `entry_hash`
already was. The frozen Phase A vectors do not carry the field, so their bytes
and digests are unchanged; without this, a checkpoint read back from disk could
not be re-hashed.
- Only the entry tail is repaired automatically. An unterminated final
*checkpoint* line is reported as `LEDGER_TORN_CHECKPOINT_TAIL` and discarded only
with `repairTail`, then re-sealed from the entry log, so exactly one rule runs
without an explicit flag.
- The section 5 row that compares the newest checkpoint with an anchor
(`LEDGER_ROLLBACK`) is not implemented here: it needs an anchor record, which is
Phase E. `fsck` implements every row decidable from the ledger directory alone,
and says nothing about rollback of the whole directory.
- `state.json` is rebuilt silently in the sense that it is a cache, but the
rebuild is listed as a `STATE_REBUILT` action, as are `CHECKPOINT_RESEALED` and
`TORN_TAIL_TRUNCATED`, so a caller can never mistake a repair for a clean run.

### Phase C - verification, membership, consistency proofs

**Delivered** (revision 2j). 248 tests pass. `npm test` exit 0.

Files: `engine/merkle.cjs`, `engine/ledger.cjs`,
`engine/evidence.cjs`, `bin/verifyd.cjs`, `bin/certify.cjs`,
`engine/test/merkle-consistency.test.cjs`, `engine/test/ledger-verify.test.cjs`.
Depends on: A, B.
Migration risk: `signingPayload` gains `ledger` in `omitKeys`; existing
signatures must be re-checked by the full suite before merge.
Test: `node --test engine/test/merkle-consistency.test.cjs engine/test/ledger-verify.test.cjs`
then `npm test`.
Acceptance:
- consistency vectors at sizes 1..64 against a reference implementation;
- fork, rollback, reorder, deletion and truncation each produce their named code;
- a valid signature with a false membership claim is REJECTED, and the same
receipt without a claim is `NOT RECORDED`, exit 0;
- `certify` and `verify` agree on every ledger scenario;
- read-only verification writes nothing (directory snapshot unchanged).

### Phase D - checkpoints, witnesses, key lifecycle

Files: `engine/ledger.cjs`, `engine/witness.cjs` (reuse, not fork),
`engine/test/ledger-witness.test.cjs`.
Depends on: C.
Migration risk: none to receipts; new key types are additive.
Test: `node --test engine/test/ledger-witness.test.cjs`.
Acceptance:
- threshold met, unmet, colluding and recused cases each produce the right label;
- cosignature replay onto a different checkpoint or ledger fails;
- revoked and expired writer and witness keys are excluded with their own codes;
- quorum outage leaves `UNANCHORED` plus `anchor_overdue`, and never blocks appends;
- rotation via a successor ledger verifies both generations independently.

### Phase E - external anchoring and publication

Files: `engine/ledger-anchor.cjs`, `engine/test/ledger-anchor.test.cjs`,
`engine/test/support/fake-ct-log.cjs` (local sink implementing the adapter contract).
Depends on: D.
Migration risk: new optional sidecar files; no change to ledger or receipts.
Test: `node --test engine/test/ledger-anchor.test.cjs`.
Acceptance:
- publish, then verify offline from the anchor record alone;
- sink down, sink returning malformed proof, sink returning a forged STH: each is
  `UNANCHORED` / `ANCHOR_UNCHECKED`, never `ANCHORED`;
- split view across two retrieval paths is `FORK_VIEW`;
- a rotated shard URL is recorded and an old record still verifies under its
  pinned key;
- published statement bytes contain no receipt id, document name or `org_id`;
- retry publishes one leaf, not two.

### Phase F - CLI, migration, docs, release validation

Files: `bin/verifyd.cjs`, `bin/certify.cjs`, `AGENTS.md`, `README.md`,
`BUILD.md`, `engine/test/end-to-end-cli.test.cjs`, `engine/test/example-receipts.test.cjs`.
Depends on: E.
Migration risk: none if `--ledger` stays opt-in; shipped receipts must not be
regenerated.
Test: `npm test && npm run test:sentinel && npm run calibrate`.
Acceptance:
- full lifecycle on Windows and Linux (the uncommitted workflow covers the
  latter once enabled);
- pre-ledger receipts and examples unchanged, `NOT RECORDED`, suites green;
- README states the guarantee, the anchor dependency and the modes verbatim
  from 1 and 11.3;
- `audit --ledger` failure exits non-zero with `NOT RECORDED`;
- no command claims `ANCHORED` without a verifying publication or quorum.

---

## 15. Acceptance test matrix

Every row must assert both the expected outcome and the absence of unintended
mutation (directory listing, sizes and mtimes compared before and after).

| # | Scenario | Phase | Expected |
| --- | --- | --- | --- |
| 1 | source artifact edited after sealing | C | receipt `REJECTED`, ledger unaffected |
| 2 | receipt fields altered and `this_hash` recomputed | C | signature fails; membership fails |
| 3 | valid signature, false membership claim | C | `NOT IN CHAIN`, exit 1 |
| 4 | entry removed or reordered | B/C | `INCONSISTENT`/`FORK`, exit 1 |
| 5 | complete trailing entry truncated | B | `TRUNCATED` |
| 6 | torn final write | B | one safe truncation, logged |
| 7 | state ahead of / behind log | B | ahead: `TRUNCATED`; behind: adopted |
| 8 | old ledger snapshot restored | C | `ROLLBACK` vs retained head |
| 9 | two simultaneous writers | B | one winner per seq, no interleave |
| 10 | stale-lock reclaim, former owner release | B | successor lock survives |
| 11 | crash at each durability boundary | B | section 5 matrix |
| 12 | disk full, permission denied | B | rollback, `LEDGER_WRITE_FAILED` |
| 13 | publication sink broken or unavailable | E | `UNANCHORED`/`ANCHOR_UNCHECKED` |
| 14 | conflicting checkpoints, same ledger and size | C | `FORK`, both heads emitted |
| 15 | inconsistent tree heads / failed consistency proof | C | `FORK` |
| 16 | expired, revoked or untrusted signing key | D | named code, excluded from quorum |
| 17 | insufficient or colluding witnesses | D | `UNANCHORED`; collusion not detected, documented |
| 18 | replayed timestamp token or cosignature | D/E | imprint or checkpoint mismatch |
| 19 | historical receipts migrated | F | `NOT RECORDED`, trust not upgraded |
| 20 | no unintended mutation on failure | B/C/E | byte-identical directory |

---

## 16. Operator decisions still open

1. Which independent log instance, and who custodies the Option B mirror.
2. Witness identities and threshold, and whether they may be the same people as
   the Oversight Board (separation of duties says no).
3. Anchor cadence: every 64 entries, 24 h, or manual.
4. Whether `--require-anchor` becomes the default in CI and in `certify`.
5. Retention and erasure policy (13.14), including the legal question about
   hashes as personal data.
6. Whether original-PDF byte hashing lands before Phase A, so the first anchored
   ledger commits to the stronger digest.

---

## 17. Claims this design does not establish

- Phases A and B exist. The byte contracts (pinned in
  `engine/test/ledger-format.test.cjs`), the persistent entry and checkpoint
  logs, the exclusive lock, the fsync ordering, the state cache, the local
  verification walk and `fsck` live in `engine/ledger-format.cjs`,
  `engine/ledger-store.cjs`, `engine/ledger-recovery.cjs` and
  `engine/ledger-verify.cjs`, behind the `engine/ledger.cjs` facade. Phase B tests cover eight concurrent appenders,
  the section 5 recovery matrix, short-write rollback and lock ownership.
  Missing: receipt membership and consistency proofs (C), witness cosignatures
  and writer authorization (D), anchoring (E), and every CLI verb (F). No
  receipt carries a `ledger` block, so no command in this document exists yet.
- Receipt hand-off has no retry path. If `writeReceipt` fails, the entry and its
  checkpoint are already durable, so the digest is recorded with no receipt and
  a second `append` of the same digest is refused as `LEDGER_DUPLICATE`. The
  error names that state, but nothing re-delivers the block; recovering it means
  reading the entry back, which is Phase C/F work, not a Phase B guarantee.
- Durability is shown against injected write, fsync and process faults on
  Windows, not against power loss: directory fsync is unavailable there, and no
  power-cut test was run on either platform.
- Every append re-verifies the whole tail before writing: it re-reads and
  re-hashes every entry and checkpoint, checks both chains and every checkpoint
  prefix root, and never treats the state cache as evidence for the decision to
  append. The cost has a fixed part and a growing part, measured by
  `npm run bench:ledger` (win32 x64, Node 22.22.3, one run; expect a few ms of
  variance). Fixed: the lock record and seven fsyncs (lock-record temp, entry,
  entry directory, checkpoint, checkpoint directory, state temp, state
  directory) plus the state rename, 23-30 ms in the tabulated run. Growing: the
  inspection of the whole log (re-read, parse, hash, both chains, every prefix
  root) measured 5, 6, 18, 25 and 45 ms at 50, 100, 200, 400 and 800 entries.
  Append adds no tree build of its own: it continues the frontier the inspection
  validated, so the inspection is the only growing term. Per-append work after
  the fixed part is therefore linear in ledger size, and a sequential load of
  `m` entries is quadratic in `m`. The raw per-append times (35, 35, 44, 50 and
  68 ms) look sublinear below about 1,000 entries because the ~25 ms floor
  dominates; 200 appends took 7.7 s and 800 took 40.8 s. That is deliberate: an
  O(1) append would mean building on a prefix the writer has not verified. The
  sanctioned mitigations for bulk loading are batched appends (verify once,
  append many under one lock) and a documented maximum entries per ledger;
  neither exists yet, and no later phase may add an append path that skips the
  tail check.
- Writer authorization is not enforced at append time. An entry records the
  signing key; whether that key was allowed to write is Phase D's judgement
  against the policy committed by `policy_hash`. Phase B proves bytes, order and
  durability, not authority.
- The Rekor v2 integration is unvalidated: entry-type construction, TUF pinning
  and shard handling are Phase E work, not established facts.
- No external security review has been performed on this design.
- Performance is measured on one machine (`npm run bench:ledger`) and not on
  other platforms, storage or production load; the numbers are not a service
  level guarantee.
- Witness independence, log honesty and mirror custody are organizational
  properties that no code in this file can guarantee.

---

## 18. Gate recommendation

Phases A-C are specified tightly enough to implement: formats are fixed, failure
semantics are named, and the adversarial cases have expected outcomes. Phases D
and E depend on the witness set and the sink instance, which are operator
decisions, not implementation details.

Recommendation: approve A-C for implementation, hold D until the witness policy
is chosen, and hold E until a log instance and mirror custodian are named. Do
not describe any result produced by A-C as an anchored ledger; A-C deliver a
local, durable, tamper-detecting ledger with no external anchor, which is
strictly weaker than the guarantee this document exists to define.

---

## 19. Relationship to the other outstanding items

Deliberately not covered here, and not to be folded in silently:

- **Original-PDF byte integrity.** The ledger commits to `payload_digest`, which
  covers the *extracted text*, so a ledger does not fix the PDF limitation. A
  separate `document.bytes_sha256` recorded at audit time is the fix, and it
  should land before or with Phase A so the first anchored ledger commits to the
  stronger digest.
- **Linux/CI validation.** The workflow is written but uncommitted, per
  instruction. Nothing here has run on Linux.
- **Assurance display.** The printed probability currently appears next to a
  REJECTED status; coupling it to the verdict's language (or withholding it when
  the receipt is rejected) is a display change independent of this design. The
  ledger adds a scored dimension only after a calibration refit (13.13).

Until Phases A-F land, this repository remains: a correctly signed,
artifact-bound receipt engine with **no** persistent, anchored receipt ledger.

---

## 20. Amendment log

**Revision 1** - first design: threat model, objects, writer model, recovery,
verification, anchor comparison, attack table, CLI sketch, four-phase plan.

**Revision 2** (2026-10-23, baseline `56e1ca0`) - after verifying every claim
against the code and completing the design gate:

- anchor decided (11): independent CT-style log primary, operator endpoint as an
  availability fallback, TSA and witnesses as secondary controls;
- ledger scope and authorization decided (12): one ledger per organization,
  self-certifying id, several authorized writer keys, immutable genesis;
- entries are now individually signed (3.1), because a single checkpoint
  signature cannot attribute appends made with several writer keys;
- `ledger_id` derived from the genesis checkpoint, and `policy_hash` added to
  bind each checkpoint to the policy it was made under;
- `receipt.prev_hash` identified as legacy and explicitly not ledger linkage
  (13.3), because it is sealed inside the signed receipt before appending;
- normative specification added (13) covering the 14 required areas: format and
  domain separation, checkpoint structure, receipt binding, Merkle guarantees,
  fork detection, witness protocol, timestamp semantics, publication protocol,
  single-writer safety, durability and recovery, verification modes, failure
  labels, compatibility, privacy and retention;
- phases replaced with dependency-ordered A-F (14) and the acceptance matrix
  expanded to 20 adversarial rows (15);
- gate recommendation recorded (18).

**Revision 2a** (2026-10-23, baseline `56e1ca0`) - Phase A implemented:

- `engine/ledger.cjs` added: the nine domain tags, integer-only JCS wrapper,
  entry and checkpoint bodies and hashes, genesis body and `emptyRoot()`,
  policy hash, cosign and publication statements. No I/O, no keys, no log;
- `engine/test/ledger-format.test.cjs` pins each domain's tag, canonical body
  and SHA-256, and refuses floats, unknown schemes and non-genesis ids;
- `engine/verifyd.cjs` and `engine/signing.cjs` are unchanged, so no existing
  code path or receipt format moved. Section 17 and the phase list are updated
  to say only Phase A exists.

**Revision 2b** (2026-10-23, baseline `56e1ca0`) - Phase B implemented:

- `engine/ledger.cjs` gains the persistent log: `initLedger`, `append`,
  `verifyLocal` and `fsck`, plus the lock, the state cache and the repairs
  record. Written order is entry append, entry fsync, checkpoint append,
  checkpoint fsync, state temp fsync, state rename, directory fsync.
- `engine/signing.cjs` exports `writeAtomic` with optional `fsync` and a
  filesystem facade, so the state cache shares the keyring's atomic-replace
  code. Signature verification, the signing payload and the receipt format are
  untouched, and `writeAtomic` behaves exactly as before when called without
  options.
- `checkpointHashPreimage` now omits `checkpoint_hash` as well as `signature`;
  the Phase A vectors are byte-identical under that change.
- Receipts deliberately gain nothing: `signingPayload` does not omit `ledger`
  yet, so attaching a block would break a signature. That integration is Phase
  C, and no code writes a `ledger` block before it lands.
- Tests: `engine/test/ledger-writer.test.cjs` (24) and
  `engine/test/ledger-recovery.test.cjs` (16). Full suite 227 pass, 0 fail.
  Sabotage runs (lock created with `w`, append fsync removed, auto-repair rule
  widened, writer binding removed) each fail the tests that claim to cover them.
- `engine/audit-chain.cjs` is marked superseded but left in place: its four
  call sites are in `bin/verifyd.cjs`, `examples/` and the tracked
  `artifacts/bundle-stage` copy, so retiral belongs with the Phase F CLI work.
- Not done in this phase: no CLI verb, no authorization, no anchor, no
  membership proof, and no power-loss test. Section 17 says so.

**Revision 2c** (2026-10-23, baseline `56e1ca0`) - Phase B reviewed and hardened:

An independent read-only review of the Phase B code found three real defects,
all in the parts that only matter under contention. They are fixed and covered:

- **Reclaim race (blocker).** Two processes that both judged the same dead lock
  could both rename it, the second moving the winner's *fresh* lock, and both
  then append at the same `seq`. Reclaim now renames the record to a name
  derived from its own nonce (`<lock>.stale-<nonce>`), so the loser of the
  atomic rename gets `ENOENT` and cannot touch the winner's lock; the record is
  re-read before the rename and the file actually moved is checked after it, so
  a lock that changed hands is put back with a hard link and the call fails
  `LEDGER_LOCKED`. No claim file is created, so a crash cannot leave one behind
  and wedge the only recovery path.
- **Release race (major).** Release read the lock, compared the nonce and then
  unlinked the shared path, so a reclaim or forced unlock between the read and
  the unlink let it delete its successor's lock. Release now renames the lock to
  a private name and inspects what it moved; only a matching record is deleted,
  and anything else is restored.
- **Unbound attribution (major).** `writer_key_id` was inside the signed body but
  was not required to equal the signing key's id, so any trusted writer could
  sign an entry that named a different writer. The parser and `signEntry` both
  reject the mismatch now, which is the binding Phase D authorization needs.
- Fencing added: a writer re-checks the lock nonce immediately before each
  durable write (entry, checkpoint, state cache, receipt hand-off) and fails
  `LEDGER_LOCK_LOST` without writing if it lost the lock. `fsck` applies the same
  check before each repair. The check is not atomic with the write, so an
  explicit `forceUnlock` racing a writer can still produce a conflicting append;
  `verifyLocal` reports the duplicate seq, so it is detected rather than silent.
- The read-only test now runs `verifyLocal` and `fsck --dry-run` through a
  recording filesystem and asserts no write operation at all, because byte
  comparison cannot see a file created and removed.
- Section 6.1 step 2 said `seq` was `0..n-1`; the code and the pinned Phase A
  vectors use `1..n` with `GENESIS` only at seq 1. The spec is corrected.
- The `LEDGER_ROLLBACK` row needs an anchor and is stated as Phase E work rather
  than implied to be implemented by `fsck`.

A second review pass checked the fix itself. It found a wedge: the claim file
introduced by the first fix would survive a crash and block `forceUnlock`, which
is why reclaim now uses the deterministic rename target instead. It also found
that restoring a moved lock had a rename fallback that could overwrite a live
lock; restore now uses only a hard link and reports the moved path when that
fails, and the fence was extended to the state cache and the receipt hand-off.

Tests are now 19 writer and 15 recovery, 34 together; the full suite is 221
pass. Sabotage runs removing the exclusive create, the append fsync, the
single-repair rule and the writer binding each fail the tests that name them.

**Revision 2d** (2026-10-23, baseline `56e1ca0`) - three defects from the
four-dimension audit fixed, each with a regression test that failed before the
change:

- **Lock wedge.** `create()` opened `<ledger>.lock` with `O_EXCL` and then wrote
  the record, so a crash, `ENOSPC` or short write in between left a 0-byte or
  malformed lock that `reclaim` could not judge; `forceUnlock` then retried and
  threw `LEDGER_LOCKED` forever, and both `append` and `fsck` were wedged until
  the file was removed by hand. The record is now written and fsynced in a
  private temporary file and hard-linked into place, and a failed write removes
  the temporary file, so the tool no longer creates that state. For a lock
  already damaged that way, `forceUnlock` discards it and logs `LOCK_FORCED`
  with `unreadable: true` and the raw bytes; without the flag the error now says
  the lock is unreadable rather than reporting `pid null`.
- **Double-truncation guard.** The guard counted `TORN_TAIL_TRUNCATED` lines in
  `repairs.log`, and a torn line there was skipped, so damage to the audit trail
  silently allowed a second un-flagged truncation. The fact now lives in
  `<ledger>.torn-tail.json`, armed and fsynced before the bytes are discarded;
  only its existence is read, so an unreadable marker still blocks. The log
  count is still consulted for ledgers written before the marker existed.
- **Wrong code for a missing directory.** `initLedger` in a non-existent
  directory reported `LEDGER_LOCKED`; it now reports `LEDGER_DIRECTORY_MISSING`
  with the directory path. The check lives in `acquireLock`, so every entry
  point names the same real cause.

Tests are 24 writer and 16 recovery, 40 together; the full suite is 227 pass.
The audit's other findings - quadratic append cost, the single 1,700-line
module, and seven unused exports - were deliberately left for a separate pass,
as was the omitted receipt integration.

**Revision 2e** (2026-10-23, baseline `56e1ca0`) - Phase B restructured along its
four layers, no behavior change:

- `engine/ledger-format.cjs` (572 lines) holds the frozen Phase A layer, moved
  out of `engine/ledger.cjs` unchanged. The pinned vectors still pass
  byte-for-byte.
- `engine/ledger-store.cjs` (1,115) owns paths and the durable write helpers,
  the lock, the state cache, `initLedger` and `append`, plus `inspectLedger`:
  one walk that reads both files, checks both chains and recomputes every
  checkpoint's prefix root. `readLedger` is the refusing wrapper over it, and
  it is the only path append and verify use.
- `engine/ledger-recovery.cjs` (282) is `fsck` only. It consumes the inspection
  findings, repairs the one crash-shaped condition, and re-inspects after a
  repair instead of carrying its own chain and root walk.
- `engine/ledger-verify.cjs` (116) is `verifyLocal`: the same inspection plus
  signature checks against trusted keys.
- `engine/ledger.cjs` (74) is the public facade. It re-exports 45 names and no
  longer exposes the seven names the audit found unused: `rootAt`, `withLock`
  and `appendLineDurable` remain module exports of the store because recovery
  needs them, while `verifyEntryChain`, `verifyCheckpointChain`, `TOOL_VERSION`
  and `DEFAULT_LOCK_TTL_MS` are now private to the store.
- Tests are unchanged: 227 pass, 51 of them across the three ledger test files
  (11 format, 24 writer, 16 recovery). No test assertion was edited.

**Revision 2f** (2026-10-23, baseline `56e1ca0`) - the remaining `forceUnlock`
wedge closed:

- A lock whose contents parse as a JSON object but carry no attributable process
  (`{"pid":null}`, a record missing `nonce`, or an interrupted external write)
  was unclearable. `reclaim(null)` read "the current text parses" as "another
  writer's record appeared" and threw `LEDGER_LOCKED: the lock became readable
  while it was being discarded`, so the documented escape hatch failed on exactly
  the incomplete records its own error text tells the operator to discard.
- The escape hatch now discards only the bytes it judged. `acquireLock` passes
  the judged text to `reclaim`, which moves the record aside when the text is
  unchanged and reports, without moving, a different record that appeared. For
  the unattributable path the moved record is re-checked by exact text (the
  attributed path still uses the nonce), so a lock that changed hands is
  restored rather than lost.
- Creation was already closed in revision 2d: the record is written and fsynced
  in a private temporary file and hard-linked into place. The `wx` fallback
  writes only a flat JSON object, every proper prefix of which is unparseable,
  and unlinks on failure. This version does not create the wedged state; it is
  reachable through an older writer's record shape or an external write, which
  is why the escape hatch must still handle it.
- Three regression tests in `engine/test/ledger-writer.test.cjs`: `append` with
  `forceUnlock` on a parseable unattributable record (fails before the change),
  `fsck` on an unattributable record missing `nonce`, and a swap test proving a
  different lock installed mid-discard survives. Full suite 230 pass.
- The section 17 claim that append cost is linear in ledger size is untouched by
  this pass and remains unqualified; the audit measured roughly quadratic total
  append cost.

**Revision 2g** (2026-10-23, baseline `56e1ca0`) - the accidental quadratic
factor in append removed; the fail-closed rule is unchanged:

- Measurement showed that tail re-verification was not what made an append
  superlinear. At 200 entries one append took 180 ms: 157 ms inside
  `inspectLedger`, of which 133 ms was the loop that rebuilt a Merkle tree for
  every checkpoint, O(n^2) hashing per append. Parsing and hashing every entry
  took 4 ms and building the new tree 9 ms, so the full-tail check was cheap
  and the root loop was the defect.
- `inspectLedger` now carries the RFC 6962 complete-subtree frontier across the
  entries and yields each checkpoint's prefix root after one leaf hash per
  entry and an O(log n) fold, comparing it with the checkpoint before moving on.
  Every checkpoint root is still checked, both chains are still verified, and
  the state cache is still never consulted for the decision to append. Disk
  formats and Phase A vectors are untouched, and no existing test was changed.
- Per append (win32 x64, Node 22.22.3, `npm run bench:ledger`): 34, 37, 48,
  67 and 105 ms at 50, 100, 200, 400 and 800 entries; 7.9 s for 200 appends and
  50.2 s for 800. Before the fix, on the same machine: 49, 74 and 184 ms at 50,
  100 and 200, 18.6 s for 200 appends. The floor is the lock and seven fsyncs
  (lock-record temp, entry, entry directory, checkpoint, checkpoint directory,
  state temp, state directory), about 30 ms in the tabulated run (29-46 ms
  across runs); an earlier note said five, which was a count that had not been
  taken. The rest of the growth is the
  inspection plus the two tree builds append still performs for its root and
  inclusion path, which is why the small-n curve looks flat.
- Section 17 now separates the fixed lock-and-fsync part from the growing
  inspection and tree-build part, states that per-append work after the floor
  is linear in ledger size, and keeps the sequential load quadratic, with
  batched appends or a documented ceiling as the sanctioned mitigation. No
  append path that skips the tail check is sanctioned.
- New test in `engine/test/ledger-writer.test.cjs`: a middle checkpoint re-signed
  with a wrong root and the tail re-linked is still rejected with
  `LEDGER_ENTRY_MISMATCH`, pinning that the incremental pass checks every
  checkpoint, not only the head. Full suite 231 pass.

**Revision 2h** (2026-10-23, baseline `56e1ca0`) - provenance for the cost claim:

- `engine/test/ledger-roots.test.cjs` proves the incremental frontier against
  `Merkle.buildTree` at every size 0..64 over three independent digest sets, and
  again across a non-contiguous size list (`0, 1, 2, 3, 5, 8, 13, 21, 34, 55,
  64`). 64 crosses the 8-entry ceiling the rest of the suite never reaches,
  covers many binary carries and every non-power-of-two size, and keeps the file
  under 100 ms, so it runs in the default suite rather than by hand.
- `scripts/ledger-bench.cjs` (`npm run bench:ledger`, optional
  `--sizes 50,100,200`, `--json`) regenerates the section 17 numbers. It reports
  the median of the last five appends, the full-load total, one inspection of
  the finished ledger, and append-minus-inspection so the fixed floor can be
  read separately from the growing term. Default sizes are 50, 100, 200, 400
  and 800, about a minute.
- Section 17 now states the measured decomposition and the complexity that
  follows: about 30 ms of lock and seven fsyncs, then linear inspection and
  tree-build work; per append linear after the floor, sequential load quadratic.
  Revision 2g's fsync count is corrected from five to seven, with the seven
  named, because the earlier number had not been counted.
- No behavior change: the frontier algorithm, append, fsck reseal, the split
  layout, receipt integration and the cryptographic paths are untouched. The
  only code change is that `prefixRoots` is exported by `engine/ledger-store.cjs`
  so the equivalence test can call it; the public facade does not expose it.

**Revision 2i** (2026-10-23, baseline `56e1ca0`) - the tree rules have one owner:

- `createFrontier()` now lives in `engine/merkle.cjs` beside `buildTree`,
  `inclusion`, `pathFor` and the leaf/node/root definitions, and is exported
  from there. `engine/ledger-store.cjs` no longer defines any tree shape: its
  `prefixRoots` is a thin adapter (validate the hex digest, push, yield the
  root) kept because the equivalence test imports it, and its inspection,
  append and `fsck` re-seal all consume the same frontier instance.
- Append no longer rebuilds the tree: the inspection leaves its frontier at the
  verified head, and `frontier.append(digest)` returns both the new root and the
  inclusion path from that one push. The `rootAt`-plus-`Merkle.inclusion` pair
  that hashed every leaf a second and third time is gone.
- `fsck`'s re-seal loop continues the inspection's frontier across the missing
  sizes instead of calling `buildTree` once per size, so re-sealing `k` missing
  checkpoints is `k` pushes plus `k` folds, not `k` full rebuilds.
  No behavior change: every root, inclusion path, refusal code and disk byte is
  identical, and `engine/test/ledger-roots.test.cjs` still passes unedited
  (its mtime predates every source file in this pass).
- New `engine/test/ledger-frontier.test.cjs` (2 tests) pins the frontier's root
  and inclusion path against `buildTree` and `inclusion` at every size 1..64
  for two digest sets, and pins `push()` against `append()`'s root sequence.
- Per append (win32 x64, Node 22.22.3, `npm run bench:ledger`): 35, 35, 44, 50
  and 68 ms at 50, 100, 200, 400 and 800 entries; 7.7 s for 200 appends and
  40.8 s for 800. Revision 2h's 67 and 105 ms, and its 50.2 s for 800, were
  measured with the two tree builds still in place; the floor is now 23-30 ms
  and the 800-entry append is 68 ms instead of 105 ms.
- Section 17's cost bullet is restated from this run, and its "performance is
  estimated from operation counts, not measured" line is retired because the
  claim is no longer true.
- Full suite 235 pass, 0 fail. Not touched: signature verification, artifact
  binding, witness quorum, governance rejection, receipt integration, batched
  appends. Not committed.

**Revision 2j** (2026-10-23, baseline `56e1ca0`) - Phase C delivered: membership,
consistency proofs, anchored verification, fork and rollback rules.

- **Consistency proofs** in `engine/merkle.cjs`: `consistency(m, digests)` and
  `verifyConsistency(...)`, exactly as 6.4 now specifies, including the
  `prefix_mth` element the size-prefixed roots require. `sizeBytes` and the
  size-committing root are unchanged, so every existing batch root and receipt
  inclusion proof is byte-identical.
- **Receipt binding.** `Signing.signingPayload` now omits `ledger` as it omits
  `inclusion`: a receipt that lacks the member canonicalizes exactly as before,
  which is why every shipped signature still verifies, and attaching the block
  after sealing cannot break the signature. `engine/test/ledger-verify.test.cjs`
  pins both directions.
- **Membership** (`engine/ledger-verify.cjs#verifyReceipt`): validates the block
  shape, recomputes the payload digest from the same signed bytes the ledger
  entry records, requires the entry at `seq` to hold that digest, finds the
  checkpoint at the claimed size whose root matches, verifies that checkpoint's
  signature under the trusted keys, verifies the inclusion path, and (with
  `--anchor`) requires the anchor's signature, ledger, size and checkpoint hash
  to match the ledger. Statuses are the 6.2 vocabulary: `NOT RECORDED`,
  `IN CHAIN`, `NOT IN CHAIN`, `UNKNOWN LEDGER`, `INCONSISTENT`.
- **Anchored verification** (`verifyChain`): the local walk plus an anchor
  checkpoint and/or retained heads. Rules: a newer anchor than the head is
  `ROLLBACK`; a root mismatch at the anchor size is `FORK`; a second checkpoint
  hash at one size is `FORK_EQUIVOCATION`; a retained head with no consistency
  proof to the observed head is `FORK`; a retained head larger than the observed
  head is `ROLLBACK`. Consistency is checked with `Merkle.verifyConsistency`
  over a proof derived from the ledger's own entries, so a rewritten prefix
  cannot reproduce the anchored root.
- **Evidence and verdict** (`engine/evidence.cjs`): `ledger` is a new evidence
  member and `ledgerVerdict` joins `verdict`. A claimed-but-unprovable
  membership is REJECTED; a receipt with no block is not penalised;
  `--require-anchor` makes `NOT RECORDED` and an unanchored membership failures.
  `certify` prints the same evidence object's line and cannot disagree.
- **Assurance model 1.4.0**: `ledger` is a scored feature (1 only when
  membership is proven against an anchored, trusted checkpoint), the corpus and
  model are regenerated with `--write`, and README's numbers are refit from the
  new artifact (Brier 0.178887, ECE 0.058479, AUC 0.807756). Labels remain
  synthetic; the method is wired, not validated.
- **CLI**: `audit --ledger` appends after sealing and attaches the block in
  place, printing `IN CHAIN` or `NOT RECORDED (<reason>)` with a non-zero exit;
  `verify --ledger [--anchor] [--require-anchor]` prints one `Ledger:` line;
  `chain init|append|proof|verify|fsck` are implemented. `chain seal`,
  `authorize`, `revoke-writer` and `publish` remain Phase D/E and are listed as
  such, not stubbed to look done.
- **Retained heads are opt-in writes.** `chain verify` is read-only unless
  `--record-head --heads <file>` is passed; the 13.5 incident append is therefore
  not performed on a plain verify, because the acceptance criterion that
  verification writes nothing wins over a line in that section that assumed
  otherwise.
- **Debt, named:** `artifacts/bundle-stage/` is a tracked pre-Phase-B snapshot
  (its `engine/` lacks the ledger modules entirely). 13.13 requires regenerating
  or removing that copy with a CLI change; copying only `bin/verifyd.cjs` would
  make it reference modules it does not ship, so it was left untouched rather
  than half-updated. It is not a verification path for the ledger and must be
  regenerated or removed before any release that ships it.
- Not touched: signature verification, artifact binding, witness quorum,
  governance rejection, batched appends, publication sinks. Nothing committed.

**Revision 2k** (2026-10-23, baseline `56e1ca0`) - adversarial review of 2j;
three defects fixed, one cross-check added.

- **Published vectors, not only our own reference.** `engine/test/merkle-consistency.test.cjs`
  now contains Google certificate-transparency's published tree
  (`cpp/merkletree/merkle_tree_test.cc`: `kInputs`, `kSHA256Roots`,
  `kSHA256Proofs`). Our leaf/node rules reproduce all eight published MTHs, and
  our verifier folds the published SUBPROOF paths for (1,8), (6,8), (2,5) and
  (1,1) to their published roots. Because this scheme's leaves are 32-byte
  payload digests, the published arbitrary-byte inputs cannot be fed to
  `consistency()`; the generator remains checked against the definition-based
  reference at every size, and the verifier is checked against the published
  proofs. `prefix_mth` is a stated contract, not a replacement for the proof:
  the verifier still folds both roots from the path.
- **Defect 1, fixed: a genesis checkpoint could anchor.** `--anchor` on a
  size-0 checkpoint was accepted, so a ledger with no anchored position could
  print `IN CHAIN (ANCHORED)`; a genesis record commits to an empty tree. Both
  `verifyReceipt` and `verifyChain` now reject `tree_size < 1` as
  `INCONSISTENT` / `LEDGER_INCONSISTENT`, with regression tests.
- **Defect 2, fixed: a replaced ledger escaped retained-head detection.** Heads
  whose `ledger_id` did not match the observed ledger were skipped, so replacing
  the ledger file with a different internally valid one produced a pass. A
  non-empty `--heads` file that contains no head for the observed ledger is now
  `LEDGER_UNKNOWN_LEDGER`; an empty file (first use) is unaffected. The test
  builds a second valid ledger and confirms it passes without the retained head
  and fails with it.
- **Defect 3, fixed: silence could be read as trust.** `verify` without
  `--ledger` printed no ledger line, so `Status: VALID` could be misread as
  ledger trust; `chain verify` without an anchor said only `full local`. The
  output is now explicit: `Ledger: NOT CHECKED (no --ledger)`,
  `IN CHAIN (UNANCHORED)`, `IN CHAIN (ANCHORED)`, or a failure state;
  `chain verify` appends `UNANCHORED` unless an anchor was checked; `certify`
  prints `NOT CHECKED` when no ledger was supplied. `Status` still means receipt
  and artifact integrity, and the ledger verdict sits on its own line.
- **Verified independently of 2j's suite:** 253 tests (was 248) exit 0;
  Sentinel 72/72; calibration reproduces model 1.4.0; the documented lifecycle
  runs 21/21; negative cases (tampered receipt, changed artifact, forged block
  with a still-valid signature, unanchored `--require-anchor`, missing ledger,
  genesis anchor, wrong retained head, replaced ledger) all fail with exit 1.
  Those runs were made from a copy of the working tree with no `.git` and no
  prior state, so nothing depended on this checkout.
- **Remaining trust boundary, stated:** the anchor's custody is the trust
  decision. A holder of a trusted signing key can rebuild a ledger with a new
  genesis and sign consistent checkpoints; detection then depends on a retained
  head or anchor the verifier kept independently, never on the ledger's own
  entries. `chain verify` without either proves internal consistency only, and
  says `UNANCHORED`. Publication and witness-anchored heads remain Phase E.
- **Still not done, unchanged from 2j:** `chain seal|authorize|revoke-writer|publish`
  (D/E), `artifacts/bundle-stage/` (stale tracked snapshot; regenerate or remove
  before release), batched appends, publication sinks. Nothing committed.

**Revision 2l** (2026-10-23) - Phase D1: writer authorization from the committed
policy.

- **The commitment, not a copy, decides.** `engine/ledger-policy.cjs` resolves
  the policy body from `<ledger>.policy.json` (or `opts.policy`), refuses a body
  whose `policyHash` is not the `policy_hash` in genesis (`LEDGER_POLICY_MISMATCH`),
  and refuses a ledger with no resolvable body (`LEDGER_POLICY_MISSING`). The
  sidecar is written under the init lock before the genesis line, so a ledger is
  never committed without the body its policy names. Genesis bytes and every
  Phase A/B/C artefact are unchanged.
- **Append refuses before writing.** `Store.append` resolves the policy and
  authorizes the signer after the duplicate check and before the first byte;
  a refusal leaves entries, checkpoints, state and the policy file identical.
  The signer's key status is read at that moment from `opts.keyring` or from
  the keyring its `keyringSigner` names; a signer whose status cannot be
  established is refused, because membership is not a status.
  `Recovery.fsck` applies the same rule to a repair signer before re-sealing a
  missing checkpoint, including in dry runs: the status source is mandatory and
  a refused reseal writes nothing.
- **The commitment can be supplied, not trusted.** `chain verify`, `chain
  append` and `chain fsck` take `--policy <file>` for a ledger whose sidecar is
  gone. An unreadable explicit file is a named caller error; no file and no flag
  is `LEDGER_POLICY_MISSING`; a body that hashes differently is
  `LEDGER_POLICY_MISMATCH`. The same `resolvePolicy` check runs in every case.
- **Verification reaches the same verdict.** `Verify.verifyLocal` authorizes
  every entry and checkpoint signer at its own `recorded_at`/`created_at`;
  `Verify.verifyReceipt` authorizes the checkpoint its proof lands in. With
  valid signatures but an unlisted writer the walk fails
  `LEDGER_POLICY_MISMATCH` and membership is `NOT IN CHAIN`; a revoked or
  expired keyring record fails `LEDGER_KEY_NOT_ACTIVE` at the record's own
  timestamp, so an undated revocation fails closed while a `retired` key does
  not. `chain verify` prints this as a separate `writer_authorization` line,
  because a trusted key is not an authorized writer.
- **Scope held.** No revocation records (D2), checkpoint cosignatures (D3),
  successor ledgers (D4), anchor cadence or publication (E); no change to
  receipt signature verification, artefact binding, receipt witness quorum or
  governance rejection. `engine/test/ledger-policy.test.cjs` adds ten cases
  that build individually valid signatures and fail on authority alone,
  including a detached signer whose key status cannot be established on append
  and on an fsck reseal, and a revoked writer appending without one.

**Revision 2m** (2026-10-23) - Phase D2: admin-signed writer revocation.

- **The tenth domain tag.** `verifyd-ledger-revocation-v1\n` is added to
  `engine/ledger-format.cjs` with a pinned byte vector; the frozen registry and
  its count assertions move from nine to ten. A revocation record carries
  `ledger_id`, `key_id`, `revoked_at`, `recorded_at`, the head it was issued
  against (`head_tree_size`, `head_checkpoint_hash`) and an optional `reason`.
- **One authority path.** `engine/ledger-policy.cjs` reads the sidecar, verifies
  every record (admin membership, signature, admin status at `recorded_at`,
  bound head, boundary) and hands the resulting map to the existing
  `authorizeWriter`. Append, whole-ledger verification, membership verification
  and fsck resealing therefore enforce revocation without a second code path.
- **The boundary cannot move backwards.** `revoked_at` must be strictly after
  every record that existed when the revocation was issued. The signed bound
  head proves which records those were; a hand-crafted backdated record fails
  `LEDGER_REVOCATION_BACKDATED` at verification, and the write verb refuses it
  before appending. Records at or after `revoked_at` fail
  `LEDGER_WRITER_REVOKED` at append and at verification.
- **Conservative readings recorded:** one revocation per key (duplicates
  refused), only listed writers may be revoked, only `admin_keys` may sign, a
  present-but-unauthenticated file is a failure rather than an empty set, and a
  writer revocation does not strip an admin role. Admission is a separate
  successor-ledger question.
- **Tests:** `engine/test/ledger-revocation.test.cjs` adds nine cases, including
  a forged signature, a non-admin signer, a backdated record, a duplicate, an
  unknown writer and a garbage file. All nine fail against the pre-D2 behaviour
  (0/9) and pass here; the suite is 274 tests exit 0. D3, D4 and Phase E are
  untouched.

**Revision 2n** (2026-10-23) - Phase D2 hardening: position, not the writer's clock.

- **Why 2m was not enough.** Two evasions survived it. (1) `revoked_at` was
  compared against `entry.recorded_at`, a timestamp the writer signs, so a
  revoked writer could append after the revocation with a turned-back or frozen
  clock and be accepted as "before the boundary". (2) The revocation file was
  the one ledger artifact with no commitment anywhere, so deleting or truncating
  it read as an internally valid ledger with no revocations.
- **Position decides.** `authorizeWriter` now refuses any subject at a position
  past the revocation's signed `head_tree_size`, regardless of its timestamp:
  the head the admin saw proves the record came later. Append passes the seq it
  is about to occupy; the whole-ledger walk passes each entry's seq. The
  commitment entry is the single exemption, and it is granted by digest only
  after the record has been authenticated, so a revoked writer cannot borrow it
  for a new payload. Checkpoints keep the signed-time rule: a checkpoint adds no
  entry, and an entry it covers is refused on its own.
- **The file is derived, not authority.** `revoke-writer` now seals the record's
  digest as an ordinary entry (`payload_digest` = digest of the signed record,
  `receipt_id` = `verifyd-revocation:v1:<key_id>`) through the normal
  entry/checkpoint path, then writes the sidecar line. `readRevocations` matches
  both directions: a commitment with no record fails `LEDGER_REVOCATION_MISSING`
  (an absent file included) and a record with no commitment fails
  `LEDGER_REVOCATION_UNCOMMITTED`. Deleting or rolling back the file now fails
  closed instead of restoring authority.
- **Sealing needs a writer.** The admin who signs the revocation may be disjoint
  from `writer_keys`; the commitment is a write, so `revoke-writer` accepts a
  writer signer (`--writer-keyring`) or reuses the admin when it is also a
  writer, and refuses `LEDGER_REVOCATION_NEEDS_WRITER` otherwise. An unsealed
  revocation is a file, not evidence.
- **Boundary at the seal.** `revoked_at` must also postdate the record's own
  `recorded_at` (`LEDGER_REVOCATION_BACKDATED`), so the sealing checkpoint is
  never the first record the boundary invalidates.
- **Tests:** `engine/test/ledger-revocation.test.cjs` is 14 cases. The four that
  pin these fixes - a backdated append, a hand-written entry past the bound head,
  a deleted file and a rolled-back file - fail against the 2m logic (10/14) and
  pass here. `npm test` is 279 tests, exit 0. D3, D4 and Phase E untouched.

**Revision 2o** (2026-10-23) - Phase D2 hardening: the reserved id is not a receipt id.

- **The DoS.** `append` accepted any `receipt_id`, and the read path treats an
  entry whose `receipt_id` begins `verifyd-revocation:v1:` as a commitment. A
  signed receipt naming that prefix was therefore accepted, read back as a
  commitment, and the ledger failed `LEDGER_REVOCATION_MISSING` forever with no
  repair path.
- **The fix is at the write path, not the read path.** The marker has to remain
  readable from the entry alone, because that is what detects a deleted sidecar.
  What must change is who can mint it. `append` now refuses a receipt id with the
  prefix (`LEDGER_RECEIPT_ID_RESERVED`) before the lock and before any byte;
  `chain append` inherits the refusal. The internal write helper accepts the
  marker only with an explicit `commitment: true`, which only `revokeWriter`
  passes. The read path still recognises hand-written commitment entries, which
  is required for detection, but no supported append can produce one.
- **Why not a structural marker?** A dedicated entry field would be genuinely
  unforgeable, but it changes the frozen entry body and its Phase A vectors, and
  this pass is scoped to the write path. A UUID-only receipt-id grammar was also
  rejected: `append` has always accepted short labels, and existing callers and
  tests use them. Reserving the one prefix keeps every legitimate id working.
- **Tests:** `engine/test/ledger-revocation.test.cjs` adds the library refusal,
  the CLI refusal, and a normal-id append as a control. Both refusal tests fail
  against the unguarded code (14/16 pass), and pass here (16/16); the full suite
  is 281 tests, exit 0. No tag, vector, entry body, receipt bytes, inclusion
  block or verdict changed.

**Revision 2p** (2026-10-23) - Phase D2 close-out: a sole writer can be revoked, and a lost revocation file can be repaired.

- **Sole-writer revocation without a second keyring.** The commitment used to
  need a writer signer, so revoking the only writer either required an unrelated
  writer keyring or left the revoked key as the only key allowed to seal. The
  admin who signs the record now seals it when it is not a writer and no writer
  is named. Authorization for that entry and its checkpoint comes from
  `admin_keys`, not `writer_keys`, and only for the commitment digest; an
  ordinary append by the same admin still fails `LEDGER_POLICY_MISMATCH`, and
  the revoked writer is refused every later entry. `--writer-keyring` still
  names a writer when one exists.
- **Repair, not reconstruction.** `restoreRevocations` / `chain
  restore-revocations <file>` re-authenticates a supplied file with the same
  `readRevocations` pass used by verification, and writes it only when every
  record matches a commitment digest and every commitment is present. A file
  with an altered, added or missing record is refused and nothing is written.
  `chain verify --revocations <file>` is the read-only equivalent. Nothing
  rebuilds a record from its digest alone.
- **Doc correction.** Earlier text said a revocation can never retroactively
  invalidate written history. That holds for `revoke-writer`, which binds the
  current head; it does not hold for a hand-written record bound to an older
  retained head, which refuses entries already written past that head. The
  guarantee is now stated as what it is: the boundary must postdate the head the
  record names.
- **Tests:** `engine/test/ledger-revocation.test.cjs` is 20 cases. The
  admin-seal case, the two restore cases and the restore CLI case fail against
  the pre-2p code; the hand-bound-head case pins the corrected claim. The suite
  is 285 tests, exit 0. D3, D4 and Phase E untouched.

**Revision 2q** (2026-10-23) - The commitment exemption is scoped to the record it seals.

- **Defect.** 2p exempted every commitment entry by digest, whoever signed it.
  `authorizeWriter` skipped the position rule whenever `subject.commitment` was
  set, and `ledgerSubjects` set it from the marker, a committed digest and the
  first occurrence alone. A writer revoked at tree 2 could therefore seal the
  revocation of a different key at entry 4, and any listed admin could seal a
  record that another admin had signed. Neither gained ordinary append
  authority, but the first turned "a revoked key never writes again" into a
  false statement, and the second widened the admin seal past the act it was
  meant to permit.
- **Fix.** `ledgerSubjects` resolves each commitment entry to the key its
  payload digest revokes, read from the authenticated record, and the position
  exemption applies only when that key is the entry's signer. The admin branch
  is bound the same way: an admin seal is accepted only for a record that admin
  signed. Every other combination falls through to the ordinary writer rules
  and is refused with the existing `LEDGER_WRITER_REVOKED` or
  `LEDGER_POLICY_MISMATCH`; no new code was added.
- **Checkpoint.** The checkpoint authority the admin exemption grants is keyed
  to the entry it covers and to that entry's signer, so a checkpoint at the
  commitment's tree size is exempt only when the same key signed both. Any
  other checkpoint is judged as an ordinary one.
- **Tests:** six cases in `engine/test/ledger-revocation.test.cjs`. Two are
  attacks: a revoked writer sealing another key's revocation, and an admin
  sealing a record another admin signed. Four are controls: a non-listed key
  (refused by the writer rule in both states), the sole-writer admin path, the
  admin-who-is-a-writer path, and a disjoint admin/writer/target trio whose
  sealer writes as an ordinary entry. Both attacks fail against the unscoped
  rule and pass here. The suite is 291 tests, exit 0.

**Revision 2r** (2026-10-23) - Phase D2 close-out: an honest restore, and a repairable admin seal.

- **Restore reported repair before proving it.** `restoreRevocations`
  authenticated the supplied records and wrote the sidecar, while the CLI
  printed `Restored` before its own verification. A ledger that failed
  whole-ledger authority - structurally valid, correctly committed, signed by a
  key outside the policy - was therefore reported as repaired. The public
  `Ledger.restoreRevocations` now verifies the ledger with the backup in place,
  writes nothing when that fails, then verifies the restored ledger and puts
  the previous sidecar back if the post-check does not stand. The store keeps
  its record-level authentication; the facade adds the authority verdict the
  store cannot reach without depending upward.
- **One code carried two conditions.** A missing, unreadable or empty backup
  and a ledger that commits a record with no sidecar all raised
  `LEDGER_REVOCATION_MISSING`. The input cases are now `LEDGER_IO` (missing or
  unreadable) and `LEDGER_REVOCATION_MALFORMED` (holds no records);
  `LEDGER_REVOCATION_MISSING` is reserved for the ledger's own verdict.
- **The admin seal could not be repaired.** `fsck` authorized its re-seal as a
  writer, so a sole-writer ledger whose commitment checkpoint was lost had no
  key that could re-sign it: the admin is not a writer, and the revoked writer
  may not write. `Policy.authorizeRepairSeals` derives the same narrow facts
  verification uses, per missing size, and accepts the admin only for the entry
  it signed as the record's signer, with the same entry-signer binding for the
  checkpoint. Every missing size is authorized before any byte is written. The
  repair signs checkpoints, never entries, so no append authority is granted.
- **Tests:** three of the four new cases fail against 2q code: the
  unusable-backup taxonomy, the unverifiable-ledger restore, and the
  admin-sealed checkpoint repair. The failed-write case pins that an I/O failure
  leaves no sidecar and the commitment unpaired rather than reporting a repair.
  The suite is 295 tests, exit 0. No D3 cosignature, no D4 successor ledger, no
  Phase E.

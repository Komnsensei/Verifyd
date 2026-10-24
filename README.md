# Verifyd

**Tamper-evident audit receipts for AI decisions. Zero dependencies. 13KB of Node.js.**

Every policy check grounded in real regulation: NIST AI RMF, EU AI Act, ISO/IEC 42001, FIPS 180-4, RFC 8785, RFC 6962.

---

## What it does

```
verifyd audit your-document.pdf
```

Produces a forensic-grade JSON receipt + human-readable certificate. SHA-256 hashed, Ed25519-signed, optionally RFC 3161 timestamped,  citation-grounded. Survives offline. No vendor. No API. No login.

```
verifyd verify your-document.verifyd-receipt.json
```

Returns `VALID` (signature and hashes recompute) or `REJECTED` with the reason.

---

## Signatures and key management

Every receipt is signed with an Ed25519 key. The signature covers one canonical
payload: the whole envelope (document metadata plus receipt body) minus the
signature block, prefixed with `verifyd-receipt-v1`. There is no second,
unhashed copy of the audit data.

```
verifyd audit your-document.pdf          # signs with the active key
verifyd verify your-document.verifyd-receipt.json
verifyd keys list                        # key id, status, creation time
verifyd keys init                        # create the keyring and first key
verifyd keys rotate                      # new active key, old one retired
verifyd keys path                        # print the keyring directory
```

Keyring location: `$VERIFYD_KEYRING`, or `~/.verifyd/keys` by default. Override
per command with `--keyring <dir>`, and pick a signer with `--key <key_id>`.

- `<key-slug>.key` private key (PKCS#8 PEM), written 0600 with its directory at
  0700 on POSIX.
- `<key-slug>.pub.json` public record: key id, public key, creation time, status.
- `active` names the key used for new signatures.
- A key id is `ed25519:` plus the SHA-256 of the SPKI public key. Every receipt
  it signs records that same key id.
- Rotation retires the old key and keeps its public record, so receipts signed
  before the rotation still verify. Deleting a public record distrusts every
  receipt that key signed.

`verify` exits non-zero and names the reason when a receipt is unsigned, signed
by a key outside your keyring, signed over different bytes, internally
inconsistent, or carrying a timestamp token that fails verification.

It also rehashes the document the receipt names, looking beside the receipt
unless `--artifact <path>` says otherwise. A document changed after sealing, or
one that is missing or unreadable, makes the exit non-zero with `Status:
REJECTED`; `Signature: VALID` and `Receipt hash: VALID` can still be printed,
because those describe the receipt bytes and not the document on disk. `certify`
runs the same check and refuses to issue a valid-looking certificate.

Keyring creation is atomic: a first run builds the key in a sibling temporary
directory and renames it into place, so concurrent creators produce exactly one
key and a failed writer leaves no partial keyring behind. A process that loses
the race reuses the winner's key or fails with `KEYRING_RACE`.

`certify` runs the same verification pass as `verify` and prints a certificate
only with the same verdict: a receipt that `verify` would reject is stamped
`REJECTED` and exits non-zero, including a batch root that does not
authenticate, a `RATIFIED` claim without a met witness quorum, and a
non-compliant determination. A folder or light record has no signature to
verify, so its certificate says `SEAL STATUS UNVERIFIED` rather than `VALID`.

### What a signature proves, and what it does not

Proves: whoever held the private key for that key id signed these exact bytes,
and the bytes have not changed since.

Does not prove: that the signer was honest or authorized, that the audited
document is true, that `signed_at` is accurate (it is the signer's clock, not a
third-party timestamp), or that a receipt was never replayed. Your keyring
decides who you trust; it is not a certificate authority.

Windows: Node cannot apply POSIX modes, so the private key inherits the ACL of
the keyring directory. Keep the keyring inside your user profile and do not sync
it to shared storage.

---

## Timestamping (RFC 3161)

`audit` can ask a time-stamp authority to attest when the signed bytes existed:

```
verifyd audit doc.pdf --tsa https://freetsa.org/tsr
verifyd verify doc.verifyd-receipt.json --tsa-ca ./freetsa-cacert.pem
```

Configure once with `VERIFYD_TSA_URL`, `VERIFYD_TSA_CA` and
`VERIFYD_TSA_TIMEOUT_MS`, or per command with the flags above.

The token cannot live inside the signed payload -- that is circular -- so it is
attached beside it and bound by its message imprint: the token covers the
SHA-256 of exactly the bytes the signature covers. `verify` recomputes those
bytes and requires the imprint to match, which is what stops a token being
lifted from another receipt.

`verify` keeps three values apart and never merges them:

- `Signed at`: the signer's clock, self-asserted.
- `Attested`: the TSA's genTime, printed only when the token signature, its
  message imprint, the signer certificate at that time and the chain to your
  configured root all check out.
- `Time status`: `ATTESTED`, `UNVERIFIED` (token signature fine, no root
  configured), `INVALID` (imprint, signature or chain failed) or `UNATTESTED`
  (no token).

An unreachable TSA does not fail the audit. The receipt is still signed and
verifiable; time is reported `UNATTESTED` alongside the recorded error.

### What a timestamp proves, and what it does not

Proves: the authority signed an imprint equal to the hash of these bytes, and
asserts those bytes existed at or before genTime. That is what makes backdating
falsifiable.

Does not prove: that the content is true, that the audit ran at that moment (a
receipt can be timestamped long after it was signed), that the authority is
honest, or anything about revocation -- CRLs and OCSP are not checked.

---

## Batching (Merkle inclusion)

`audit` seals one receipt. `batch` commits a set of receipts to one Merkle root,
so the set can be signed (and timestamped) once and any single member can later
prove it was in that set:

```
verifyd batch receipts/
verifyd batch receipts/ --tsa https://freetsa.org/tsr
verifyd verify receipts/doc.verifyd-receipt.json --artifact doc.pdf
verifyd verify receipts/doc.verifyd-receipt.json --artifact doc.pdf --batch receipts/verifyd-batch.json
```

`batch` seals the root with the active key of the keyring that signed the
receipts, so it needs that private key. The bundled `examples/keyring` is
verify-only: pointing `batch` at it fails with `PRIVATE_KEY_MISSING` by design.

`batch` writes `verifyd-batch.json` in the folder and stores a proof inside each
receipt under `inclusion`. Leaves are the SHA-256 of each receipt's signed
payload -- the same bytes the signature and any timestamp cover -- not the raw
file bytes. The chain therefore composes: leaf digest -> inclusion path -> root
-> root signature -> optional attestation of the root.

Scheme `verifyd-merkle-v1`, specified in [engine/merkle.cjs](engine/merkle.cjs):

- Leaves are `SHA-256(0x00 || payload)` and internal nodes are
  `SHA-256(0x01 || left || right)`. The domain bytes stop a node being passed
  off as a leaf, or a leaf as a node.
- Position is fixed, not inferred: the path lists sibling hashes bottom-up and
  the proof carries the leaf index, so left/right comes from the index bits and
  no other ordering verifies.
- The proof commits to tree size, so a shortened path cannot verify against a
  larger tree, and a size that disagrees with the path is rejected.
- The root hash is deterministic for a given ordered receipt set. Batching the
  same set twice gives the same root with a fresh batch id.

`verify` reports `Inclusion: VALID (leaf i of n)` once a root is authenticated,
and `Inclusion: PROOF VALID, ROOT UNVERIFIED` otherwise. The proof sits outside
the signed payload -- it is computed over those bytes -- so on its own it is
only arithmetic: without the root there is nothing to compare against, and
anyone can build a one-leaf tree over their own digest. `verify` therefore does
not call that line fully valid, and the score withholds inclusion credit, unless
you supply the root file. With
`--batch` it checks the root's own signature and batch id, and with `--tsa-ca`
the root's attestation, at which point inclusion is anchored rather than merely
self-consistent. A receipt with no proof verifies exactly as before and prints
`Inclusion: NOT PRESENT`.

Exit 1 with the reason on: an altered leaf, a tampered or reordered path, a
wrong leaf index, a tree size that disagrees with the path, a proof lifted from
another batch, and a root whose signature does not cover the root hash it
presents.

### What inclusion proves, and what it does not

Proves (when checked with `--batch`): these signed bytes are a leaf at that
position in a tree whose root hash is the one signed, and (if attested)
timestamped. Together with the receipt's own signature, an auditor holding one
receipt and the root can check membership without seeing the other receipts.

Does not prove: that the other leaves are what they claim, that the batch is
complete, that the content is true, or that history was not rewritten. A batch
publishes no consistency proof between successive roots, so whoever holds the
signing key can publish a new root over a different set and each old receipt
still verifies on its own. Treat a batch root as a commitment to one set at one
time, not as an append-only log.

The Merkle primitive itself exists (`Merkle.consistency` / `verifyConsistency`),
and the receipt ledger below uses it to connect two signed heads. A consistency
proof here also carries `prefix_mth` (the subtree hash of the first m leaves),
because these roots commit to the tree size and the prefix hash cannot be
recovered from a size-prefixed commitment. It is public tree data, not a secret.

---

## Receipt ledger: membership and append-only evidence

A receipt can carry an unsigned `ledger` block: which ledger, which sequence
number, which signed checkpoint, and the inclusion path into its root. The
block is excluded from the signed payload for the same reason `inclusion` and
`attestations` are, so attaching it never invalidates the receipt signature --
and for the same reason it proves nothing on its own. It is a claim until a
checkpoint the verifier trusts is the one the proof lands in.

```
verifyd chain init --ledger audit.ledger.jsonl
verifyd audit paper.pdf --ledger audit.ledger.jsonl
verifyd verify paper.verifyd-receipt.json --ledger audit.ledger.jsonl
verifyd chain revoke-writer <key_id> --ledger audit.ledger.jsonl --reason "left the team"
verifyd chain verify --ledger audit.ledger.jsonl
verifyd chain restore-revocations revocations.backup.jsonl --ledger audit.ledger.jsonl
verifyd chain verify --ledger audit.ledger.jsonl --anchor head.json --heads retained-heads.jsonl
verifyd chain fsck --ledger audit.ledger.jsonl --dry-run
```

`chain init` writes the committed policy body beside the ledger as
`<ledger>.policy.json`. Append and verification recompute its hash and refuse a
body that does not match the `policy_hash` in genesis. If that file is lost,
`--policy <file>` supplies the same body to `chain verify`, `chain append` and
`chain fsck`, and is held to the same hash check. A trusted key is not
enough: the signer must be a writer under the policy the ledger committed to,
and its key status must be readable from the keyring the signer names. An
append whose signer cannot be tied to a keyring record is refused rather than
assumed authorized. `chain verify` prints the authority verdict as a separate
`writer_authorization` line.

A revocation is an admin-signed record in `<ledger>.revocations.jsonl`, and it
counts only once the ledger commits to it: `revoke-writer` seals the record's
digest as a normal entry before writing the file. A writer seals it, or the
admin itself when the admin does not write and no `--writer-keyring` is given;
that one seal grants no append authority and keeps the revoked key from
writing anything but that seal. The exemption is personal: a writer may skip
the position rule only for the seal of its own revocation, and an admin may
seal only a record it signed; a different listed writer seals at its own
position. The record binds the head it was issued against, so `revoke-writer`
can never reach back behind entries that already exist. Everything past that
head is refused `LEDGER_WRITER_REVOKED` by position, whatever timestamp the
writer claims; within the head, `revoked_at` orders the records. A hand-written
record bound to an older retained head can therefore refuse entries already
written past it: the guarantee is against a backdated seal, not against an
admin moving the boundary. Deleting or truncating the revocation file leaves
the commitment behind and fails `LEDGER_REVOCATION_MISSING` rather than reading
as "no revocation". `chain verify --revocations <file>` reads a backup without
writing, and `chain restore-revocations <file>` re-authenticates it against the
commitments and restores the sidecar; neither can add a record the ledger never
committed to. A supplied backup that is missing or unreadable is `LEDGER_IO`,
and one that holds no records is `LEDGER_REVOCATION_MALFORMED`;
`LEDGER_REVOCATION_MISSING` is reserved for a ledger that commits a record with
no sidecar. Restore verifies the whole ledger with the backup in place before
writing, and rolls the sidecar back if the restored ledger does not verify. Both
checks and the rollback run under the ledger lock, so no writer can append
inside the repair window, and "Restored" is never printed for a repair that did
not hold. The marker is
reserved: an ordinary append naming a receipt id that begins
`verifyd-revocation:v1:` is refused with `LEDGER_RECEIPT_ID_RESERVED` before any
byte is written, so a receipt cannot claim to be a commitment. Revoking a key
ends its authority, it does not rewrite what it signed.

`chain fsck` re-seals a lost checkpoint tail; for a sole-writer ledger the
admin that sealed the commitment may re-sign that checkpoint under the same
narrow act, and gains no append authority.

`verify --ledger` prints one line and the exit code follows it:

```
Ledger:       NOT CHECKED (no --ledger)       exit 0   (receipt integrity only; no ledger claim)
Ledger:       NOT RECORDED                    exit 0   (a receipt may predate the ledger)
Ledger:       IN CHAIN (UNANCHORED)           exit 0   (proof valid, no trusted head supplied)
Ledger:       IN CHAIN (ANCHORED)             exit 0   (the proof lands in the supplied checkpoint)
Ledger:       NOT IN CHAIN (...reason...)     exit 1   (a claim that cannot be proven)
Ledger:       INCONSISTENT (...reason...)     exit 1
Ledger:       UNKNOWN LEDGER (...reason...)   exit 1
```

`--require-anchor` turns `NOT RECORDED` and unanchored membership into failures.
`chain verify --anchor` checks that the ledger's prefix at the anchor's tree
size still hashes to the anchored root, and refuses a rollback (the observed
head is smaller than the anchor) or an equivocation (two checkpoint hashes at
one size). `--heads` applies the same rules against retained heads; recording a
new head is opt-in (`--record-head`) because verification otherwise writes
nothing.

What this proves: these signed receipt bytes are at that position in that
checkpoint, signed by a trusted key, and (with an anchor) extend a head the
verifier already trusted -- nothing was removed or reordered before it.

What it does not prove: that the checkpoint was published anywhere (Phase E),
that the ledger is complete after the anchor, that the signer held an admin or
witness role rather than writer membership (Phases D2-D4), or that the
receipt's contents are true.
A ledger held entirely by one party can be rebuilt with a fresh key; the anchor
is what makes rewriting detectable, and only if somebody else kept it.

---

## Witness identity proofing (quorum)

The Oversight Board quorum is counted over verified witness keys and identities,
never over labels. A witness contributes only through an attestation signed by
its own key, over a payload that includes the SHA-256 of the receipt's signed
bytes, so an attestation cannot be moved to another receipt or replayed.

```
verifyd witness init --keyring witnesses/alice
verifyd witness prove alice@example.org --proof-out alice.witness-proof.txt --keyring witnesses/alice
# publish alice.witness-proof.txt at a stable URI, then:
verifyd witness attest receipt.json --identity alice@example.org \
  --proof alice.witness-proof.txt --proof-uri https://example.org/alice.txt \
  --keyring witnesses/alice
verifyd witness vouch receipt.json --witness-key <alice key id> \
  --identity alice@example.org --keyring vouchers/board
verifyd witness register witnesses/alice --into trusted-witnesses \
  --expires 2027-01-01T00:00:00Z
verifyd verify receipt.json --keyring keys --witness-keys trusted-witnesses
```

Three tiers are recorded and displayed, never collapsed into a boolean:

| Tier | How it is reached | What it proves | What it does not prove |
|---|---|---|---|
| `label` | Signed, but no proof material | Only that some key holder typed this label | That the label names a real, distinct person. Rejected as `label_only`; counted as nothing |
| `key` | Signed, plus a resource whose bytes are committed in the attestation and which publishes `verifyd-witness: <key_id> <identity>` | The holder of that key can write to that resource, and the key id and label appear there together | That the resource owner is the person the label names, or that the resource will never change |
| `vouched` | `key`, plus a voucher signed by a second trusted key that is neither the witness nor the audited party | A second key asserts the key-to-identity binding | Anything about the voucher's authority; your witness keyring decides that |

`verify` prints the count and every decision behind it:

```
Witnesses:    2 counted of 4 required (QUORUM NOT MET)
  counted     alice@example.org             ed25519:e8741f756c20...   tier=vouched, voucher ed25519:7543c4626f14...
  counted     bob@example.org               ed25519:9a21c0dd4e77...   tier=key
  rejected    carol@example.org             ed25519:33ac91b07f02...   label_only: signed, but carries no identity proof material
  conflict    shared@example.org            2 keys claim this identity (counted once)
```

The accounting is deliberately unhelpful to anyone trying to inflate a board:

- The same key under two labels counts once; the extra label is listed as an alias.
- Two keys claiming one identity are surfaced as a conflict and the identity counts once.
- The audited party's own signing key is rejected as `self_witness`.
- An attestation bound to a different receipt is rejected as `wrong_receipt`.
- A revoked key is rejected as `key_revoked`; a key whose `expires_at` predates the receipt is `key_expired`.
- An unregistered key is `unknown_witness_key`; an unreachable proof is `proof_unavailable`;
  with no witness keyring the summary says `NOT ASSESSED`.
- Every rejected attestation is reported with its reason. Nothing is silently dropped,
  and nothing unverified is counted.
- Attestations sit outside the receipt signature (they sign those bytes themselves), so
  one can be stripped without breaking the signature. That lowers the count, and a
  `RATIFIED` claim that drops below quorum is rejected; one cannot be added without the
  witness key.

A receipt whose lattice status is `RATIFIED` but whose witness claim is missing,
unassessable or short of quorum prints `Signature: VALID` and still exits 1: the
signature proves who sealed the bytes, not that the board existed.

### What an attestation proves, and what it does not

Proves: the holder of that witness key signed a statement bound to these exact
receipt bytes, and (at tier `key`) could write the key-to-label binding to the
named resource at verification time.

Does not prove: that the witness is independent in interest, read the document,
was honest or competent, that the resource will keep serving those bytes, or
that the receipt is true. Ratification records who attested; it does not make
the content correct.

---

## Compliance determinations (not legal advice)

**This is an engineering record of evidence and review status. It is not legal
advice, it does not decide whether a regulation applies, and it does not
establish compliance. That takes a qualified reviewer in the relevant
jurisdiction, working from material Verifyd does not hold.**

A determination is a separate artifact, signed by a named reviewer with a role
and bound to one receipt's signed bytes:

```
verifyd determination create receipt.json --keyring keys \
  --jurisdiction EU --regime EU_AI_ACT_2024 \
  --reviewer "Jane Doe" --role "Head of Compliance" \
  --conclusion compliant --fact actor_role=provider --fact high_risk=no \
  --expires 2027-01-01T00:00:00Z
verifyd determination verify det.json --receipt receipt.json --keyring keys
verifyd verify receipt.json --keyring keys --determination det.json
verifyd determination show det.json
verifyd determination regimes
```

It records what was assessed (the machine checks and their evidence), under
which jurisdiction and regime (with the repo-cited basis), against which
requirements, what applicability facts the reviewer supplied, what remains
outstanding, who concluded what, when it expires, and the notice above. The
signature covers a domain-separated payload containing the receipt digest, so
the determination cannot be edited or moved to another receipt.

### Two judgements, never merged

- `machine`: for each requirement, the predicate, the evidence paths and values
  inspected, and `satisfied` / `partial` / `not_satisfied` / `no_evidence`. These
  are tool checks over the receipt bytes only.
- `review`: the reviewer's name, role, conclusion, rationale and time, signed by
  their key. A reviewer may disagree with the machine; both are kept.

`compliant` requires all of: a trusted signature, a binding match, no expiry,
an indexed jurisdiction and regime, no missing/unresolved/invalid applicability
fact, every citation traceable to `engine/citations.json`, every machine
requirement satisfied, a named reviewer with a role, and that reviewer's
conclusion of `compliant`. Everything else is a named failure, never compliant:

| Condition | Status |
|---|---|
| No jurisdiction declared (there is no default) | `undetermined` |
| Jurisdiction or regime not indexed | `undetermined` |
| Regime indexed under a different jurisdiction | `undetermined` |
| Required applicability fact missing, invalid, or "unknown" | `incomplete` |
| Requirement has no evidence or only partial evidence | `incomplete` |
| Requirement evidence fails | `non_compliant` |
| Citation not present in the repo | `incomplete` (`source_unverified`) |
| Reviewer name, role or review time missing | `incomplete` |
| Reviewer concluded `insufficient_evidence` | `incomplete` |
| Reviewer concluded `non_compliant` | `non_compliant` |
| No signature, edited bytes, untrusted reviewer key | `unsigned` / `tampered` / `untrusted_reviewer_key` |
| Bound to a different receipt | `wrong_receipt` |
| Past its `expires_at` | `expired` |
| Stored machine evidence differs from a fresh recheck | `evidence_mismatch` |

`verifyd verify --determination det.json` prints the reviewer, machine result,
signature, binding, expiry and status, and makes the receipt `REJECTED` unless
the determination is `compliant` — the receipt signature may still print
`VALID`, because sealing bytes is not the same claim as compliance.

### What the regime registry is, and is not

[engine/legal-regimes.json](engine/legal-regimes.json) indexes two
jurisdictions and two regimes, and every requirement's source ref and locator
must already exist in [engine/citations.json](engine/citations.json); the module
refuses to load otherwise. The checklists are therefore partial by construction:
they cover only obligations the repo already cites, and each carries a coverage
note saying so. There is no applicability engine and no invented statute, article
or case. A requirement supplied by a reviewer whose ref is not in the repo is
recorded as `source_unverified` and forces `incomplete`. Add one with
`--requirement 'id|statement|ref|locator'`; the same tracing rule applies.

It does not decide whether the EU AI Act or Reg. B applies, does not interpret
any text, does not know your facts, and does not replace counsel. It records
what a tool checked and what a named human signed.

---

## Assurance score (a probability, fitted on synthetic labels)

Every verification reports a probability between 0 and 1 that the receipt's
assurance claim holds: signed by a trusted key, time attested, inclusion proven,
witness quorum real, every policy result checked and traced to its citation,
every external anchor resolved, determination standing. It is the output of a
logistic model with committed parameters, not a weighted sum of hand-picked
numbers.

```
Assurance:    0.247 (probability; model 1.4.0)
Model:        verifyd-trust-assurance-v1 1.4.0, synthetic labels, data deebd9994e62
```

### What it is, and is not

- **It is** an estimate that the evidence attached to these bytes is what it
  claims to be. The features are exactly that evidence: `signature`, `time`,
  `inclusion`, `witness_count`, `witness_tier`, `policy`, `ratification`,
  `anchors`, `determination`, `ledger`, and `missing`.
- **It is not** a probability that the document's contents are true. Verifyd
  cannot see truth; it sees sealed bytes and the evidence attached to them.
- **It is not calibrated against real audit outcomes.** The committed corpus is
  **synthetic**: labels are drawn from a documented latent rule with a seeded
  PRNG. Held-out metrics below show the machinery is wired and stable. They do
  not show that the probability matches the world. That requires labelled
  outcomes from real audits, which this repo does not have.
- **It is not a target.** Deleting a timestamp lowers the number because the
  evidence is genuinely absent, and the output names the absence.
- **A failed check never pays.** Each verification dimension is binary: it
  contributes only when it was checked and passed. A signature under an
  untrusted key scores what no signature scores; a timestamp token whose chain
  was not checked scores what no timestamp scores; inclusion without an
  authenticated root scores what no proof scores; three witnesses score what no
  witnesses score; an adverse or unverifiable determination scores what no
  determination scores. Policy results pay only when every recorded result was
  evaluated, passed, and traced to a registered citation; a warning, a skipped
  result, or an untraceable citation scores what no policy result scores.
  Anchors pay only when every external anchor records a resolution that matches
  its resolver; an unresolved or unverifiable anchor scores what no anchor
  scores. Receipt membership pays only when the proof lands in a checkpoint
  under a trusted key that is also anchored; a verified signature on the block
  is not enough, because the block sits outside the signed receipt. Failures are
  named in `absent` and counted by the same `missing` term as absence. This is per dimension: a failed check scores the same as that
  evidence being absent, not the same as a receipt with no evidence at all; the
  dimensions that did pass still count. Policy and anchor evidence is recorded
  in the signed receipt at audit time: verification checks that the record is
  complete, passed, cited, and resolver-consistent, not that a policy check
  would run the same way today or that the remote source still resolves.

### Missing evidence degrades, it does not disappear

The bundled example receipt is signed by a trusted key and carries a fully
traced policy result, but it has no timestamp, no witnesses, no determination
and no external anchor a known resolver recognizes. It cannot reach a high
probability, and the result says which evidence would move it:

```
Assurance:    0.247 (probability; model 1.4.0); absent: attested_time, proven_inclusion, witness_quorum, compliant_determination, resolved_anchor
```

`absent` names each failed or missing dimension, and the model's fitted
`missing` term carries the cost of the five verification dimensions. An
unverified timestamp token, a root without `--batch`, and attestations without
`--witness-keys` are reported as notes, never silently counted as good evidence.
An untraceable policy result or an unresolved anchor is named the same way.
`RATIFIED` with no met quorum scores as unbacked.

### Reproducing the numbers

The corpus, the fit and the metrics are committed. One command checks that the
model file still reproduces from the corpus, and fails if either the parameters
or the metrics drift:

```
node scripts/calibrate-trust.cjs          # verify (exit 1 on drift)
node scripts/calibrate-trust.cjs --write  # regenerate corpus + model
```

`npm test` runs the same check twice: once by wiring the script, once by
rescoring the held-out rows directly through the model and comparing against
the committed metrics and the numbers in this section.

| Held-out metric | Value |
|---|---|
| Rows (train / held-out) | 840 / 360, from 1,200 synthetic receipts |
| Brier 0.178887 | mean squared error of the probability |
| ECE 0.058479 | expected calibration error over 10 bins |
| AUC 0.807756 | discrimination between positive and negative labels |
| Log loss 0.534744 | cross-entropy on the held-out split |

Model artifact: [engine/calibration/trust-model.json](engine/calibration/trust-model.json)
(version, parameters, training settings, corpus SHA-256, metrics, label rule).
Corpus: [engine/calibration/corpus.jsonl](engine/calibration/corpus.jsonl).
Fit: [scripts/calibrate-trust.cjs](scripts/calibrate-trust.cjs) — L2 logistic
regression, fixed seed, fixed iteration count, no randomness at inference.

Every result carries `scheme`, `model_version`, `dataset_sha256`, the feature
vector and `labels_origin: synthetic`, so a reader can identify which model
produced a number and what it was fitted on. `certify` recomputes the
probability from the receipt and the evidence on the verifying machine, and
prints the model, the data hash and any absent evidence.

The number depends on the evidence you can check: `--keyring`,
`--witness-keys`, `--tsa-ca`, `--batch` and `--determination` are what make
those dimensions count. Verify and certify given the same evidence report the
same probability; without it they report a lower one and print what is absent,
rather than assuming it.

### The old 0-100 score

It is kept as `documentQuality`: a document-substance heuristic used only to
gate lattice promotion at audit time. It is labelled `calibrated: false`,
`status: UNCALIBRATED`, and is printed as a heuristic. It is never written as a
trust score and never presented as a probability.

---

## Why it matters

Today when someone asks how an AI decision was made, the answer is a chat log. Maybe a screenshot. Maybe nothing.

Verifyd answers with a receipt. Hashes of every input. Anchors to every source. Confidence with decay. Policy checks with regulatory citations. A calibrated-style assurance probability over the evidence that actually exists. Lattice promotion path with required quorum. Ed25519 receipt signatures.

Email it. Print it. Re-validate it in milliseconds, anywhere, no network.

---

## Quick demo

```
node bin/verifyd.cjs demo
```

---

## Real audit run (in this repo)

A 22,886-word physics paper, audited in <3 seconds:

| Field | Value |
|---|---|
| Document quality (heuristic, uncalibrated) | 95/100 |
| Lattice status | RATIFIED |
| Standards cited | 9 (EU AI Act, NIST AI RMF, ISO/IEC 42001, FIPS 180-4, RFC 8785, RFC 6962, FAIR, OECD, FTC) |
| Chain valid | yes |

This case study predates witness identity proofing: its `RATIFIED` status was
recorded from label-based witnesses and would not meet the current quorum rules,
which require signed attestations from distinct verified keys. The 95/100 in
that table is the uncalibrated document-quality heuristic, not the assurance
probability introduced above; it is shown so the old record is not mistaken for
a calibrated result.

Full case study: [`RESULTS.md`](./RESULTS.md)

---

## Architecture

```
engine/
  citations.json       14 standards (full bibliographic)
  policy.cjs           4 compliance checks, each cited
  evidence.cjs         one verification pass shared by the report and the score
  trust-score.cjs      assurance probability (committed model) + uncalibrated document heuristic
  calibration/         labeled corpus (synthetic) + fitted model artifact
scripts/
  calibrate-trust.cjs  deterministic fit, held-out metrics, drift check
  audit-chain.cjs      SHA-256 + canonical JSON + linear prev_hash chain
  signing.cjs          Ed25519 receipt + root signatures, keyring, rotation
  witness.cjs          receipt-bound witness attestations, proof tiers, quorum accounting
  tsa.cjs              RFC 3161 client, token parser and verifier
  merkle.cjs           verifyd-merkle-v1 inclusion proofs (leaf/node domains)
  determination.cjs    signed, receipt-bound determinations; machine evidence vs human review
  legal-regimes.json   jurisdictions and regimes, each requirement traced to citations.json
  lattice.cjs          10-status lattice with quorum gates
  verifyd.cjs          orchestrator
bin/
  verifyd.cjs          CLI (audit / verify / batch / lattice / demo)
  certify.cjs          JSON -> human-readable .txt
  batch-audit.cjs      folder batch processor
```

---

## Forbidden by protocol

The engine actively rejects:
- Sole-sovereign ratification (single party tries to seal)
- Three-witness quorum (requires four of seven Oversight Board)
- DRAFT -> DEPOSITED (must pass PROVISIONAL gate)
- PATTERN -> RATIFIED (pattern-matching is not ratification)

Each rejection cites the standard it enforces.

---

## Sentinel: data-access monitoring

`sentinel/` adds a defensive monitoring service for Windows hosts and the APIs
they serve. It normalizes access logs and Windows telemetry, applies a
deterministic scoring rubric, writes hash-chained JSONL evidence, and delivers
signed webhook alerts with a durable retry queue. Detection-only by default; no
firewall changes, no tarpits, no third-party credentials.

```
node bin/sentinel.cjs simulate --scenario all
node bin/sentinel.cjs coverage --config sentinel/config.example.json
npm run test:sentinel
```

Full documentation, coverage matrix and incident runbook: [`sentinel/README.md`](./sentinel/README.md).

---

## Pricing

- **Free** — open-source MIT, this repo
- **$49** — VALF-1 spec PDF + integration guide
- **$499** — Verifyd Lattice (full governance framework, 7-seat oversight model, multi-org chain merging)

---

## Status

v1.0. Production-ready engine. Pure Node.js >= 18. No dependencies.

See [`BUILD.md`](./BUILD.md) for build/deploy. See [`AGENTS.md`](./AGENTS.md) for AI-agent collaboration instructions.

---

Built April 2026 by Shawn ([@komnsensei](https://github.com/komnsensei)).

Receipt format: VALF-1 (Verifyd Audit Log Format v1).

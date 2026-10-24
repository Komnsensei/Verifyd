# AGENTS.md — Instructions for AI Coding Agents (Codex, Cursor, Claude Code)

This repo is **Verifyd v1.0** — a tamper-evident audit-receipt engine for AI decisions, with full citation grounds in NIST AI RMF, EU AI Act, ISO/IEC 42001, FIPS 180-4, RFC 8785, and RFC 6962.

## Setup

No dependencies. Pure Node.js (>= 18).

```
node --version   # confirm >= 18
```

That's it. No `npm install`. No build step. The engine is 24KB of plain CommonJS.

## Run

This block is one working sequence. It keeps its keys in a scratch directory,
signs and verifies with that same keyring, and copies the example document so
the shipped, verify-only receipt in `examples/` is left intact.

```
export VERIFYD_KEYRING="$(mktemp -d)/demo-keys"
node bin/verifyd.cjs demo
node bin/verifyd.cjs keys init
cp "examples/Quantum Information Holography and the Born Rule.txt" demo.txt
node bin/verifyd.cjs audit demo.txt
node bin/verifyd.cjs verify demo.verifyd-receipt.json
node bin/verifyd.cjs certify demo.verifyd-receipt.json

# The shipped receipts are verify-only: examples/keyring has no private key.
node bin/verifyd.cjs verify "examples/Quantum Information Holography and the Born Rule.verifyd-receipt.json" --keyring examples/keyring

# Witness identity proofing: a keyring per witness, trusted separately.
node bin/verifyd.cjs witness init --keyring witnesses/alice
node bin/verifyd.cjs witness prove alice@example.org --proof-out alice.proof.txt --keyring witnesses/alice
node bin/verifyd.cjs witness attest demo.verifyd-receipt.json --identity alice@example.org --proof alice.proof.txt --keyring witnesses/alice
node bin/verifyd.cjs witness register witnesses/alice --into trusted-witnesses
node bin/verifyd.cjs verify demo.verifyd-receipt.json --witness-keys trusted-witnesses

# Determination: a signed record bound to the receipt digest.
node bin/verifyd.cjs determination create demo.verifyd-receipt.json --jurisdiction EU --regime EU_AI_ACT_2024 --reviewer "Jane Doe" --role "Head of Compliance" --conclusion compliant --fact actor_role=provider --fact high_risk=no
node bin/verifyd.cjs determination verify demo.verifyd-receipt.determination.json --receipt demo.verifyd-receipt.json
node bin/verifyd.cjs verify demo.verifyd-receipt.json --witness-keys trusted-witnesses --determination demo.verifyd-receipt.determination.json

# Merkle batch root over a folder of receipts, then anchored verification.
mkdir -p receipts
cp demo.verifyd-receipt.json receipts/
node bin/verifyd.cjs batch receipts/
node bin/verifyd.cjs verify receipts/demo.verifyd-receipt.json --artifact demo.txt --batch receipts/verifyd-batch.json

# Folder batch: audit every PDF, write receipts + certificates, verify each one.
node bin/batch-audit.cjs <folder-of-pdfs>

# Receipt ledger: init, audit into it, check membership and the log itself.
node bin/verifyd.cjs chain init --ledger demo.ledger.jsonl
node bin/verifyd.cjs audit demo.txt --ledger demo.ledger.jsonl
node bin/verifyd.cjs verify demo.verifyd-receipt.json --ledger demo.ledger.jsonl
node bin/verifyd.cjs chain verify --ledger demo.ledger.jsonl
```

A met quorum needs four verified witnesses; one proof above demonstrates the
flow. `batch` signs the root with the active key of the keyring that signed the
receipts, so it needs that private key (the bundled example keyring cannot sign
and fails with `PRIVATE_KEY_MISSING`).

## Verify

After any audit run, the signature and receipt hash must validate:

```
node bin/verifyd.cjs verify <receipt.json>
```

Expected output: `Signature: VALID`, `Receipt hash: VALID`, `Artifact: VALID`,
`Status: VALID`. Anything else is a non-zero exit with the reason (UNSIGNED,
UNTRUSTED_KEY, SIGNATURE_INVALID, RECEIPT_HASH_MISMATCH). Verification needs
the keyring that holds the signing key: `--keyring <dir>` or
`$VERIFYD_KEYRING`.

Verification also rehashes the document named by the receipt, looking beside
the receipt unless `--artifact <path>` says otherwise. A document that changed
after sealing, or one that is missing or unreadable, is `Status: REJECTED` with
a `Reason`, even though `Signature: VALID` and `Receipt hash: VALID` still
describe the receipt bytes. The signature binds the receipt; only the artifact
check binds the document.

With `--ledger <path>`, `verify` prints one `Ledger:` line. The `ledger` block
is outside the signed payload (it is computed from the signed bytes after
sealing), so it is a claim until a checkpoint under a trusted key is the one the
proof lands in: `IN CHAIN (UNANCHORED)` proves position, not publication. A
receipt with no block is `NOT RECORDED` and exits 0; a claimed membership that
cannot be proven (`NOT IN CHAIN`, `INCONSISTENT`, `UNKNOWN LEDGER`) is REJECTED
and exits 1 even though `Signature: VALID`. `--anchor <checkpoint.json>`
supplies the trusted head, and `--require-anchor` makes unrecorded or unanchored
membership a failure. `chain verify --anchor` also refuses a rollback (observed
head smaller than the anchor) and an equivocation (two checkpoint hashes at one
size), and `--heads <file>` applies the same rules against retained heads.
Consistency is checked with `Merkle.verifyConsistency`; proofs carry
`prefix_mth` because roots commit to the tree size. Plain verification writes
nothing: recording a head needs `--record-head`.

The policy body travels beside the ledger as `<ledger>.policy.json`, written by
`chain init`; append and verification hash it and refuse a body that does not
match the `policy_hash` in genesis (`LEDGER_POLICY_MISMATCH`) or that is missing
(`LEDGER_POLICY_MISSING`). If the sidecar is lost, `--policy <file>` supplies the
same body to `chain verify|append|fsck` and passes the same hash check, never a
bypass; an unreadable explicit file is a caller error, not a missing policy. A
trusted key is not enough to append: the signer must
be a listed writer under that policy, and its key status is re-read from the
keyring it names at append time. A revoked or expired record fails at the
record's own signed timestamp (`LEDGER_KEY_NOT_ACTIVE`), a signer whose status
cannot be established is refused rather than assumed active, and a retiredkey still proves what it signed. `chain verify` prints `writer_authorization`
separately from the signature checks.

Revocations live in `<ledger>.revocations.jsonl`: `chain revoke-writer <key_id>`
records an admin-signed statement (admin_keys only) bound to the head it was
issued against, and seals it as a ledger entry (payload digest = digest of the
record, `receipt_id` `verifyd-revocation:v1:<key_id>`) signed by a writer, or
by the admin who signed the record when the admin is not a writer and no
`--writer-keyring` is given. That seal is authorized as an admin act and grants
no append authority. The exemption is personal: a writer may use it only for
the seal of its own revocation, an admin only for a record it signed, and a
different listed writer seals the same entry as an ordinary append at its own
position. A revoked key therefore writes nothing past its boundary except the
seal of its own revocation. The sealing entry is the
commitment: deleting or truncating the file cannot restore authority, because
verification finds the entry and fails `LEDGER_REVOCATION_MISSING`; a record
with no commitment is `LEDGER_REVOCATION_UNCOMMITTED`. A lost sidecar can be
read with `chain verify --revocations <file>` (no writes) and restored with
`chain restore-revocations <file>`, which re-authenticates every record against
the commitment digests before writing; a record the ledger did not commit to is
refused. A supplied backup that is missing or unreadable is `LEDGER_IO`, and one
that holds no records is `LEDGER_REVOCATION_MALFORMED`;
`LEDGER_REVOCATION_MISSING` is reserved for a ledger that commits a record with
no sidecar. Restore verifies the whole ledger with the backup in place before
writing and rolls the sidecar back if the restored ledger does not verify, all
under the ledger lock, so no writer can append between the check and the write;
a repair that did not hold is never reported as one that did. `chain fsck`
re-seals a lost checkpoint tail, including the commitment checkpoint of a
sole-writer ledger: the admin that sealed the commitment may re-sign it under
the same narrow act, and gains no append authority. The marker is outside the
receipt-id vocabulary: `append` and `chain
append` refuse any receipt id beginning `verifyd-revocation:v1:`
(`LEDGER_RECEIPT_ID_RESERVED`) before writing, so a receipt can never be read
back as a commitment.

Authority is decided by position, not by the writer's clock. `revoked_at` dates
the statement and must postdate every record up to the head the record names,
so entries up to that head stay valid. Any entry that appears past that head is
outside the history the admin saw, so it is refused `LEDGER_WRITER_REVOKED`
whatever its `recorded_at` claims - a turned-back clock cannot place a new
entry before the boundary. `revoke-writer` binds the current head and cannot
backdate; a hand-written record bound to an older retained head can refuse an
entry that already existed past it, so the guarantee is about the head, not
about wall-clock history. `revoked_at` must be strictly after records up to the
bound head and after the record's own `recorded_at`
(`LEDGER_REVOCATION_BACKDATED`), a second revocation for one key is
`LEDGER_REVOCATION_DUPLICATE`, an unlisted
target is `LEDGER_REVOCATION_UNKNOWN_WRITER`, and a file that is present but
cannot be authenticated fails `LEDGER_REVOCATION_UNAUTHORIZED` or
`LEDGER_REVOCATION_MALFORMED` - never treated as empty.

First use of a fresh keyring directory builds the key in a sibling temporary
directory and renames it into place (engine/signing.cjs). Exactly one concurrent
creator wins; a loser reuses the winner's key or fails with KEYRING_RACE; a
crashed writer leaves no keyring at the target path, only a dot-prefixed temp
directory. Do not replace the rename with read-then-write.

When a receipt carries an RFC 3161 token, `verify` prints `Signed at` (the
signer's clock), `Attested` (TSA genTime) and `Time status` as separate values.
Pass `--tsa-ca <pem>` or set `$VERIFYD_TSA_CA` to check the token's chain; with
no root configured the token is reported `UNVERIFIED`, never attested, and the
exit code stays 0. A token that fails imprint, signature or chain checks exits
non-zero. `UNATTESTED` means no token was requested or the TSA was unavailable,
and the signature still verifies.

When a receipt carries a Merkle inclusion proof, `verify` prints `Inclusion:
PROOF VALID, ROOT UNVERIFIED (leaf i of n; pass --batch to authenticate)`
until a root is supplied, then `Inclusion: VALID (leaf i of n)`. The proof is
outside the signed payload, so the unanchored form proves arithmetic only; the
assurance score withholds inclusion credit in that state. Pass `--batch
<root.json>` to check the root's signature and batch id; `--tsa-ca` additionally
checks any attestation on the root. A receipt without a proof prints `Inclusion: NOT PRESENT` and is otherwise
unchanged. Exit is non-zero for an altered leaf, tampered path, wrong index, a
tree size that disagrees with the path, a proof lifted from another batch, or a
root whose signature does not cover it.

When a receipt carries witness attestations, `verify` prints `Witnesses: N counted
of 4 required` with one line per counted, rejected or conflicted witness. Quorum
is counted over verified keys and identities (engine/witness.cjs), never over
labels. Same key twice counts once; two keys on one label are a conflict counted
once; the audited party's own key never counts; revoked and expired keys do not
count; unreachable proofs and a missing witness keyring are reported, not
assumed. A receipt claiming `RATIFIED` without a met, assessed quorum exits
non-zero while still printing `Signature: VALID`. Witness tiers: `label` (signed,
no proof - never counted), `key` (resource proof binding key id and identity),
`vouched` (plus a voucher from a different trusted key).

A compliance determination (engine/determination.cjs) is a separate artifact,
signed by a named reviewer and bound to the receipt digest. `verify
--determination <file>` prints the reviewer, machine result, signature, binding,
expiry and status, and makes the receipt REJECTED unless the determination is
`compliant`. `compliant` requires: trusted signature, binding match, no expiry,
an indexed jurisdiction and regime, no missing or unresolved applicability
facts, every citation traced to citations.json, every machine requirement
satisfied, a named reviewer with a role, and a reviewer conclusion of compliant.
Everything else reports `undetermined`, `incomplete`, `non_compliant`,
`unsigned`, `tampered`, `wrong_receipt`, `expired`, `untrusted_reviewer_key` or
`evidence_mismatch`. This is an engineering record, NOT legal advice; itdoes not decide applicability or establish compliance.

`certify` has no checks of its own: it runs the same evidence pass
(engine/evidence.cjs) and prints `AssuranceEvidence.verdict`, so it cannot show
a stronger outcome than `verify`. A rejected receipt is stamped REJECTED with a
non-zero exit; a folder or light record has no signature, so its certificate is
stamped UNVERIFIED. Never add a second verification path to the certificate.

## Assurance score (calibrated on synthetic labels)

Every `audit` / `verify` / `certify` prints `Assurance: <p> (probability; model
<version>)`, computed by engine/trust-score.cjs from the evidence the other
modules produce: signature trust, attested time, proven inclusion, witness
count and tier, policy results, backed ratification, resolved anchors, and
determination status. Parameters are committed in
engine/calibration/trust-model.json; scoring is a dot product with no fitting,
randomness or I/O beyond reading the model.

```
npm run calibrate                          # check the model reproduces (exit 1 on drift)
node scripts/calibrate-trust.cjs --write   # regenerate corpus + model
```

The committed labels are SYNTHETIC, drawn from a documented latent rule. Held-out
Brier/ECE/AUC show the method is wired, not that it matches real audit outcomes.
Do not describe the probability as validated, and do not tune weights by hand:
refit, write, and update the numbers in README.md (a test checks they match).

Every scored dimension is binary: it pays only when checked and passed. A
failed or unverifiable result (untrusted signer key, token chain unchecked,
proof without an authenticated root, partial witness quorum, warning, skipped or
untraceable policy result, unresolved anchor, adverse or unverifiable
determination, membership without an anchored trusted checkpoint) scores exactly
what that evidence absent scores. The five verification dimensions are counted
by `missing`; `ledger` is a separate fitted feature that pays only for anchored
membership, and is neither a sixth missing dimension nor partial credit. Never
add partial credit for a failed check. Policy pays only when every recorded result is `pass`, carries a
`checked_at`, and its citations trace to `engine/citations.json`; anchors pay
only when every external anchor has a known resolver, resolution time, title,
and a URI host matching that resolver. Policy and anchor results are audit-time
records covered by the signature; the verifier checks the record's completeness
and trace, not a fresh policy run or network lookup. Absent evidence must
degrade the score and be named in `absent`. `RATIFIED` without a
met quorum scores as unbacked. The assurance number never changes `Status`: it
is an estimate over the checks, not a replacement for them.

The old 0-100 hand-tuned value survives as `documentQuality` (explicitly
uncalibrated, `scale: 0-100-heuristic`), used only for audit-time lattice gates
and printed as a heuristic. Never write it as a probability or a trust score.

## Test

```
npm test              # 297 node:test tests: signing, keyring creation race, rotation, receipts, artifact rehashing (changed/missing/unreadable), RFC 3161, Merkle inclusion and consistency proofs, ledger membership/anchoring/fork rules, writer revocation and commitment, restore locking and rollback, witness quorum, determinations, calibration reproduction, evidence agreement, failed-dimension monotonicity, shipped example receipts, end-to-end CLI lifecycle (audit, ledger, witnesses, determination, PDF batch), certificates and batch summary agree with examples/keyring
npm run demo          # engine demo
npm run calibrate     # refit check for the assurance model
npm run test:sentinel # 72 node:test tests for the monitoring service
```

## Sentinel (monitoring subsystem)

`sentinel/` is a zero-dependency Node service that monitors data access on
Windows hosts and their APIs. It is separate from the receipt engine: it reuses
`engine/canonicalize.cjs`, writes its own hash-chained JSONL store, and never
requires Windows to run its tests (Windows adapters accept injected telemetry
and report UNAVAILABLE on other platforms).

```
bin/sentinel.cjs            CLI: run/once/status/coverage/verify/rules/simulate
sentinel/adapters/          10 collector adapters with ACTIVE/UNAVAILABLE/NOT_CONFIGURED
sentinel/rules.cjs          deterministic rubric, correlation, dedupe
sentinel/store.cjs          hash-chained JSONL, rotation, retention, verification
sentinel/dispatcher.cjs     durable HMAC webhook queue
sentinel/test/              72 tests (node --test)
sentinel/windows/           install/control/uninstall/preflight PowerShell
sentinel/docs/              coverage matrix, runbook, rubric, verification record
```

Read `sentinel/README.md` before modifying an adapter or a rule. Rule changes
require the test suite to stay green, including the false-positive tests.

## Repo layout

```
engine/
  citations.json        # 14 standards (NIST, EU AI Act, ISO, FIPS, RFC, OWASP, FAIR, OECD, FTC, Reg.B)
  legal-regimes.json    # jurisdictions/regimes, every requirement traced to citations.json
  policy.cjs            # 4 compliance checks, each cited
  evidence.cjs          # one verification pass: signature, time, inclusion, batch root, ledger, witnesses, determination
  ledger-format.cjs     # frozen ledger shapes, tags, hashes, signing preimages (no I/O)
  ledger-store.cjs      # lock, fsync-ordered append, state cache, one read model
  ledger-recovery.cjs   # fsck: findings in, repairs and a verdict out
  ledger-verify.cjs     # local walk, receipt membership, anchored verification
  ledger.cjs            # public ledger facade (55 exports)
  trust-score.cjs       # assurance probability (committed model) + uncalibrated document heuristic
  calibration/          # synthetic labeled corpus + fitted model artifact
  audit-chain.cjs       # SHA-256 + RFC 8785 canonical JSON + RFC 6962 append-only chain
  extract.cjs           # shared text extraction so audit and verify hash the same text
  signing.cjs           # Ed25519 receipt signatures + keyring (generate/rotate/verify)
  asn1.cjs              # minimal DER reader/writer for RFC 3161
  tsa.cjs               # RFC 3161 timestamp client, token parser and verifier
  merkle.cjs            # verifyd-merkle-v1 inclusion proofs (0x00 leaf / 0x01 node domains)
  witness.cjs           # receipt-bound witness attestations, proof tiers, honest quorum accounting
  determination.cjs     # signed, receipt-bound determinations; machine evidence kept apart from review
  test/                 # node:test coverage for signing, receipts and timestamps
  lattice.cjs           # 10-status lattice walk with quorum gates
  lattice-domains.json  # status hierarchy + Oversight Board spec
  verifyd.cjs           # core orchestrator
bin/
  verifyd.cjs           # CLI: audit / verify / batch / witness / determination / lattice / demo
  certify.cjs           # JSON receipt -> human-readable .txt certificate
  batch-audit.cjs       # batch-process every PDF in a folder
scripts/
  calibrate-trust.cjs   # deterministic fit, held-out metrics, drift check
RESULTS.md              # case study writeup
README.md               # public face
BUILD.md                # build/deploy instructions
verifyd.bat             # Windows shortcut
```

## What the engine does

1. **Authenticated session** (auditor + agent + timestamp -> session_hash via SHA-256)
2. **Content extraction + hash** (PDF -> text -> content_hash)
3. **Source anchors** (arXiv / DOI / file URI)
4. **Confidence with exponential decay** (60-day half-life default)
5. **Policy checks** (no_coercion / transparency / audit_trail / independent_oversight) — each cites real regulation
6. **Assurance probability** (logistic model over signature, time, inclusion, witness quorum/tier, policy, ratification, anchors, determination, anchored ledger membership, missing evidence) and a separate uncalibrated document-quality heuristic for promotion gates
7. **Lattice walk** (DRAFT -> PROVISIONAL -> DEPOSITED -> RATIFIED, with >=4/7 Oversight Board quorum counted over verified witness keys, not labels)
8. **Receipt sealing** (VALF-1 = SHA-256 over canonical JSON, then an Ed25519 signature over the whole envelope)
9. **Batch commitment** (optional: SHA-256 leaf digests over signed payloads -> binary Merkle root, root signed with the same key and optionally timestamped)
10. **Compliance determination** (optional: signed, receipt-bound record of machine evidence and named reviewer conclusion; never legal advice)

## What's forbidden (engine actively rejects)

- Sole-sovereign ratification (single-party seal) — hard fail
- Skipping PROVISIONAL stage — hard fail
- PATTERN -> RATIFIED (pattern-matching is not ratification)
- Three-witness ratification (quorum requires four)
- Label-only ratification (a typed name is not a witness; attestations must be signed over the receipt bytes)
- Compliant determination without a trusted signature, receipt binding, unexpired record, machine evidence, and a named reviewer with a role

## Next tasks (priority order for any agent picking this up)

1. **Add Jest tests** for engine/policy.cjs, engine/lattice.cjs, engine/audit-chain.cjs
2. **Package as npm**: add bin field to package.json, publish as `verifyd`
3. **arXiv/Crossref live resolver** — currently scaffolded, needs HTTP fetch
4. **Web dashboard** — read receipts from a folder, render certificates in browser
5. **GitHub Action** — auto-audit any PDF added to /auditdeck on push

## Citation discipline

When adding new policy checks, **never write a check without grounding it**. Every check must reference at least one of:
- NIST AI RMF 1.0 (NIST AI 100-1) — DOI 10.6028/NIST.AI.100-1
- EU AI Act 2024/1689 — CELEX 32024R1689
- ISO/IEC 42001:2023 — AI management
- ISO/IEC 27001:2022 — info security
- FIPS 180-4 — SHA-256
- RFC 8785 — JCS canonical JSON
- RFC 6962 — Certificate Transparency append-only model
- OWASP LLM Top 10 (2025)
- FAIR Principles (Wilkinson 2016, DOI 10.1038/sdata.2016.18)
- OECD AI Principles (2019/2024)
- FTC AI guidance (2023)
- Reg. B / ECOA (12 CFR 1002.9)

Add new authorities to `engine/citations.json` first, then reference by key in the check.

## Style

- Direct. No filler. No emoji except in human-facing docs.
- Plain ASCII in code paths (avoid em-dashes, smart quotes, accented chars in source).
- All file writes use forward-slashes or double-backslashes.
- All hashes are SHA-256 hex (lowercase).
- All timestamps are ISO 8601 UTC.

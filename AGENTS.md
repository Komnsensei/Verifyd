# AGENTS.md — Instructions for AI Coding Agents (Codex, Cursor, Claude Code)

This repo is **Verifyd v1.0** — a tamper-evident audit-receipt engine for AI decisions, with full citation grounds in NIST AI RMF, EU AI Act, ISO/IEC 42001, FIPS 180-4, RFC 8785, and RFC 6962.

## Setup

No dependencies. Pure Node.js (>= 18).

```
node --version   # confirm >= 18
```

That's it. No `npm install`. No build step. The engine is 24KB of plain CommonJS.

## Run

```
node bin/verifyd.cjs demo
node bin/verifyd.cjs audit "examples/Quantum Information Holography and the Born Rule.txt"
node bin/verifyd.cjs verify "examples/Quantum Information Holography and the Born Rule.verifyd-receipt.json" --keyring examples/keyring
node bin/verifyd.cjs audit doc.pdf --tsa https://freetsa.org/tsr
node bin/verifyd.cjs batch examples --keyring examples/keyring
node bin/verifyd.cjs witness prove alice@example.org --proof-out alice.proof.txt --keyring witnesses/alice
node bin/verifyd.cjs witness attest receipt.json --identity alice@example.org --proof alice.proof.txt --keyring witnesses/alice
node bin/verifyd.cjs verify receipt.json --keyring examples/keyring --witness-keys trusted-witnesses
node bin/verifyd.cjs determination create receipt.json --keyring examples/keyring --jurisdiction EU --regime EU_AI_ACT_2024 --reviewer "Jane Doe" --role "Head of Compliance" --conclusion compliant --fact actor_role=provider --fact high_risk=no
node bin/verifyd.cjs determination verify receipt.determination.json --receipt receipt.json --keyring examples/keyring
node bin/verifyd.cjs verify receipt.json --keyring examples/keyring --determination receipt.determination.json
node bin/batch-audit.cjs examples
```

## Verify

After any audit run, the signature and receipt hash must validate:

```
node bin/verifyd.cjs verify <receipt.json>
```

Expected output: `Signature: VALID`, `Receipt hash: VALID`, `Status: VALID`.
Anything else is a non-zero exit with the reason (UNSIGNED, UNTRUSTED_KEY,
SIGNATURE_INVALID, RECEIPT_HASH_MISMATCH). Verification needs the keyring that
holds the signing key: `--keyring <dir>` or `$VERIFYD_KEYRING`.

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
determination) scores exactly what that evidence absent scores. The five
verification dimensions are counted by `missing`; never add partial credit for a
failed check. Policy pays only when every recorded result is `pass`, carries a
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
npm test              # 165 node:test tests: signing, keyring creation race, rotation, receipts, RFC 3161, Merkle inclusion, witness quorum, determinations, calibration reproduction, evidence agreement, failed-dimension monotonicity, shipped example receipts, certificates and batch summary agree with examples/keyring
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
  evidence.cjs          # one verification pass: signature, time, inclusion, batch root, witnesses, determination
  trust-score.cjs       # assurance probability (committed model) + uncalibrated document heuristic
  calibration/          # synthetic labeled corpus + fitted model artifact
  audit-chain.cjs       # SHA-256 + RFC 8785 canonical JSON + RFC 6962 append-only chain
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
auditdeck/              # sample PDFs to audit
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
6. **Assurance probability** (logistic model over signature, time, inclusion, witness quorum/tier, policy, ratification, anchors, determination, missing evidence) and a separate uncalibrated document-quality heuristic for promotion gates
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

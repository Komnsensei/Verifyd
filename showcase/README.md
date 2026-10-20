# Verifyd Campus

A zero-dependency showcase of Verifyd v1.0 applied to an online university.

Eight synthetic decision records from Northline Online University are sealed through the
real engine. Seven produce receipts. One is refused by the protocol. One is caught after a
post-seal content edit.

## Run

```bash
node showcase/seed.cjs        # regenerate data/cases.json (optional, it is committed)
node showcase/server.cjs      # http://localhost:3000
```

Or:

```bash
npm run showcase:seed
npm run showcase
```

No install. No build. Node 18 or newer.

## What you can do

- **Browse the case register.** Filter ratified, awaiting quorum, tampered, refused, and
  provisional records.
- **Verify a receipt.** Runs three checks: receipt hash, artifact hash, chain link.
- **Tamper with a sealed field.** Flips the receipt to TAMPERED, then restore it.
- **Inspect the chain.** Seven linked receipts with `prev_hash` / `this_hash`.
- **Seal a new decision.** Pick a decision type, confidence, and four seats. The real
  engine runs policy, trust, lattice, quorum, and receipt assembly.
- **Try a unilateral override.** One office signs on behalf of the board. The engine
  returns no receipt and the error `sole_sovereign ratification forbidden by Independent
  Oversight`.
- **Read a certificate.** `GET /api/cases/:id/certificate` renders a plain-text
  certificate with citations.

## Cases

| Case | Type | Status | What it demonstrates |
|---|---|---|---|
| AP-2291 | Grade appeal | RATIFIED | Correct rubric, four seats, trust 87 |
| AI-4471 | Academic integrity | RATIFIED | Thin evidence, one dissent, trust 48 |
| AC-1180 | Accommodation | RATIFIED | Human override of an AI denial |
| FB-0925 | Feedback release | AWAITING | Three seats; quorum gate holds |
| PR-3310 | Proctoring | BLOCKED | Sole-sovereign refusal, no receipt |
| TR-7742 | Credit transfer | PROVISIONAL | Missing external anchor |
| GR-5508 | Grade posting | TAMPERED | Artifact edited after sealing |
| AQ-8801 | Accreditation | RATIFIED | 214-item evidence packet |

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/state` | Institution, board, cases, summary, chain, standards |
| GET | `/api/cases/:id` | Full case with live verification |
| POST | `/api/cases/:id/verify` | Receipt + content + chain checks |
| POST | `/api/cases/:id/tamper` | Mutate a sealed receipt field in memory |
| POST | `/api/cases/:id/restore` | Remove the demo tamper |
| GET | `/api/cases/:id/certificate` | Plain-text certificate |
| GET | `/api/chain` | Chain view and validity |
| POST | `/api/intake` | Seal a new decision through the engine |
| GET | `/api/health` | Liveness |

All demo state is in memory. Restarting the server resets tamper demos and intake cases.

## What is real and what is synthetic

Real:

- every receipt, hash, chain link, policy check, trust score, and lattice decision;
- every refusal and tamper detection;
- the engine in `/engine`, untouched.

Synthetic:

- Northline Online University and all people, courses, students, and vendors;
- the artifacts and attestation rationales;
- the board roster.

No real student data is present.

## Files

```
showcase/
  lib/campus.cjs      domain layer, scenario corpus, verifier, certificate
  server.cjs          zero-dependency API + static server
  seed.cjs            writes data/cases.json
  data/cases.json     generated corpus (committed for convenience)
  public/
    index.html
    styles.css
    app.js
```

## Limits

This is a demonstration, not a production service. It has no auth, no database, no
persistence, no signing, and no rate limiting. The receipt chain is in memory. The
witness signatures are derived hashes, not cryptographic signatures. See
[the system report](../docs/SYSTEM-REPORT.md) section 10 and
[the university playbook](../docs/UNIVERSITY-PLAYBOOK.md) section 15.

## Demo script

1. Open AP-2291, verify it, tamper it, restore it.
2. Open PR-3310 and read the refusal.
3. Open FB-0925 and show a case held at three of seven seats.
4. Scroll to the intake desk, seal a grade appeal with four seats, then try the unilateral
   override.
5. Close on the ledger: seven receipts, each committing to the hash before it.

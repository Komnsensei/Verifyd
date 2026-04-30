# Verifyd

**Tamper-evident audit receipts for AI decisions. Zero dependencies. 13KB of Node.js.**

Every policy check grounded in real regulation: NIST AI RMF, EU AI Act, ISO/IEC 42001, FIPS 180-4, RFC 8785, RFC 6962.

---

## What it does

```
verifyd audit your-document.pdf
```

Produces a forensic-grade JSON receipt + human-readable certificate. SHA-256 hashed, append-only chain, citation-grounded. Survives offline. No vendor. No API. No login.

```
verifyd verify your-document.verifyd-receipt.json
```

Returns `VALID` (all hashes recompute) or `TAMPERED`.

---

## Why it matters

Today when someone asks how an AI decision was made, the answer is a chat log. Maybe a screenshot. Maybe nothing.

Verifyd answers with a receipt. Hashes of every input. Anchors to every source. Confidence with decay. Policy checks with regulatory citations. Trust score across four components. Lattice promotion path with required quorum. Append-only chain.

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
| Trust score | 95/100 |
| Lattice status | RATIFIED |
| Standards cited | 9 (EU AI Act, NIST AI RMF, ISO/IEC 42001, FIPS 180-4, RFC 8785, RFC 6962, FAIR, OECD, FTC) |
| Chain valid | yes |

Full case study: [`RESULTS.md`](./RESULTS.md)

---

## Architecture

```
engine/
  citations.json       14 standards (full bibliographic)
  policy.cjs           4 compliance checks, each cited
  trust-score.cjs      0-100 across 4 components
  audit-chain.cjs      SHA-256 + canonical JSON + append-only
  lattice.cjs          10-status lattice with quorum gates
  verifyd.cjs          orchestrator
bin/
  verifyd.cjs          CLI
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

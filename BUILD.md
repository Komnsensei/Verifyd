# BUILD.md

## One-line build (any machine with Node 18+)

```bash
git clone https://github.com/komnsensei/verifyd.git && cd verifyd && npm test
```

That's it. No `npm install` needed — zero dependencies.

## What Happens

1. `bin/verifyd.cjs demo` runs the engine end-to-end:
   - Creates an authenticated session
   - Hashes a sample document with SHA-256 (FIPS 180-4)
   - Records source anchors (FAIR Principles)
   - Records confidence with exponential decay
   - Runs 4 policy checks (NIST AI RMF, EU AI Act, ISO/IEC 42001, etc.)
   - Computes trust score (0-100, 4 components × 25)
   - Walks the lattice DRAFT → PROVISIONAL → DEPOSITED → RATIFIED
   - Enforces 4-of-7 Oversight Board quorum
   - Seals a VALF-1 receipt with canonical JSON (RFC 8785) + SHA-256 (FIPS 180-4) + prev-hash linkage (RFC 6962)
2. Demo prints `Chain valid: true` if receipt re-hashes correctly.
3. `examples/run-example.cjs` re-runs against `examples/sample.pdf`, producing `sample.verifyd-receipt.json` and a human-readable `.certificate.txt`.

## Verifying After a Change

```bash
node bin/verifyd.cjs verify <any-receipt.json>
```

Outputs `VALID` or `TAMPERED`. Pure protocol — no network, no central server.

## Batch Audit

```bash
node bin/batch-audit.cjs auditdeck/
```

Walks every PDF in the folder, produces a receipt + certificate per file, and writes `auditdeck/BATCH_SUMMARY.json`.

## Citations Registry

`engine/citations.json` is the legal grounding for every claim in a receipt. 14 international standards. Do not edit without legal review.

## Production Deploy

This package is the protocol. Hosted SaaS (verifyd.app) and IPFS/L2 anchor adapters are v1.1 roadmap.

Ship as-is to Gumroad / npm / GitHub releases.
udit.cjs      # Batch process a folder of PDFs
examples/
  run-example.cjs      # Minimal example
  audit-paper.cjs      # Paper-audit example
  lattice-demo.cjs     # Lattice walk demo
```

## Receipt Format: VALF-1

Every receipt is SHA-256 over canonical JSON, append-only chained. Grounded in:
- **FIPS PUB 180-4** (SHA-256)
- **RFC 8785** (JSON Canonicalization Scheme)
- **RFC 6962** (append-only Merkle log discipline)

## Standards Cited by the Engine

- NIST AI RMF 1.0 (10.6028/NIST.AI.100-1)
- NIST AI 600-1 (Generative AI Profile)
- EU AI Act Reg. 2024/1689 (Articles 12, 13, 14, 15, 50)
- ISO/IEC 42001:2023, 23894:2023, 27001:2022
- OECD AI Principles
- FAIR Principles (Wilkinson et al. 2016)
- OWASP LLM Top 10 (2025)
- FTC AI guidance (2023)
- Reg. B / ECOA (12 CFR 1002.9)

## For Codex / CI

Run `npm test` (which is `node bin/verifyd.cjs demo && node examples/run-example.cjs`).
Exit 0 = pass, non-zero = fail. No external services. No network needed.
ce, demo
  certify.cjs           # JSON receipt → human-readable certificate
  batch-audit.cjs       # batch over a folder

examples/
  run-example.cjs       # synthetic demo
  audit-paper.cjs       # real PDF demo
  lattice-demo.cjs      # walks the lattice + tests negative cases

verifyd.bat             # Windows shim
```

## Receipt format (VALF-1)

Every receipt is canonical JSON (RFC 8785) hashed with SHA-256 (FIPS 180-4)
and chained via prev_hash → this_hash (RFC 6962 model).

Tamper anywhere → hashes diverge → verify fails. No vendor, no network,
no escrow required.

# AGENTS.md — Codex / OpenAI Agent Instructions

This file tells autonomous coding agents (Codex, Cursor, Devin, Claude Code, etc.) how to build, test, and ship Verifyd.

## Project: Verifyd v1.0

Tamper-evident audit receipts for AI decisions. Zero-dependency, pure Node.js, ships forensic compliance receipts grounded in international standards.

## Quick Start (one command)

```bash
npm test
```

This runs the full audit demo and the physics-paper case study. Exit code 0 = ship-ready.

## Build Verification

```bash
npm run demo      # End-to-end engine + lattice + receipt sealing
npm run audit "examples/sample.pdf"   # Audit any PDF
npm run verify "examples/sample.verifyd-receipt.json"  # Verify receipt
npm run batch auditdeck               # Batch-process a folder
```

## Key Files

| File | Purpose |
|---|---|
| `engine/verifyd.cjs` | Core audit engine |
| `engine/policy.cjs` | 4 compliance checks (citations-grounded) |
| `engine/trust-score.cjs` | 0-100 trust scoring |
| `engine/audit-chain.cjs` | VALF-1 hash chain |
| `engine/lattice.cjs` | 10-status promotion ladder |
| `engine/lattice-domains.json` | 7-seat Oversight Board, transitions |
| `engine/citations.json` | 14 standards (NIST, EU AI Act, ISO, FIPS, RFC) |
| `bin/verifyd.cjs` | CLI: audit / verify / lattice / demo |
| `bin/certify.cjs` | Receipt → human-readable certificate |
| `bin/batch-audit.cjs` | Batch process a folder of PDFs |

## What Codex Should Do

1. **Verify the build runs clean**: `npm test` should produce a sealed VALF-1 receipt with chain_valid=true.
2. **Run the auditdeck batch**: `npm run batch auditdeck` should produce N receipts + N certificates + 1 BATCH_SUMMARY.json.
3. **Generate fresh case-study artifacts**: Write the sealed certificate text into `RESULTS-LATEST.md` so the marketing copy stays current.
4. **Stage release commit**: `git add . && git commit -m "ci: automated build verification"`

## Rules for Agents

- **Zero new dependencies.** This is a pure-Node project. Do not add npm packages.
- **Do not modify** `engine/citations.json` without justification — it's the legal grounding.
- **Do not modify** `engine/lattice-domains.json` without justification — it's the governance spec. `sole_sovereign` and `MANUS` are FORBIDDEN.
- **Always verify** receipts re-validate after any change: `node bin/verifyd.cjs verify <receipt>`.
- **Standards cited** must remain: NIST AI RMF (DOI 10.6028/NIST.AI.100-1), EU AI Act 2024/1689, ISO/IEC 42001:2023, FIPS 180-4, RFC 8785, RFC 6962.

## Pricing / Distribution Goals

- **Verifyd Core**: $49 (Gumroad) — engine + CLI + docs
- **Verifyd Lattice**: $499 (Gumroad) — adds full 7-seat Oversight Board governance
- **npm publish**: `npm publish --access public` once tested
- **Show HN**: title `Show HN: Verifyd — tamper-evident audit receipts for AI decisions (zero deps)`

## Success Criteria

- [ ] `npm test` exits 0
- [ ] Receipt chain validates
- [ ] Certificate renders 14 cited standards
- [ ] Batch processes all PDFs in `auditdeck/` without error
- [ ] Zero external dependencies in package.json

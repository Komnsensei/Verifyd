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
node bin/verifyd.cjs audit "auditdeck/Quantum Information Holography and the Born Rule.pdf"
node bin/verifyd.cjs verify "auditdeck/Quantum Information Holography and the Born Rule.verifyd-receipt.json"
node bin/batch-audit.cjs auditdeck
```

## Verify

After any audit run, the chain hash must validate:

```
node bin/verifyd.cjs verify <receipt.json>
```

Expected output: `Chain valid: true`. If `false`, the receipt has been tampered with.

## Test (when added)

```
npm test
```

Currently no test runner. Adding Jest is a v1.1 task.

## Repo layout

```
engine/
  citations.json        # 14 standards (NIST, EU AI Act, ISO, FIPS, RFC, OWASP, FAIR, OECD, FTC, Reg.B)
  policy.cjs            # 4 compliance checks, each cited
  trust-score.cjs       # 0-100 score across 4 components
  audit-chain.cjs       # SHA-256 + RFC 8785 canonical JSON + RFC 6962 append-only chain
  lattice.cjs           # 10-status lattice walk with quorum gates
  lattice-domains.json  # status hierarchy + Oversight Board spec
  verifyd.cjs           # core orchestrator
bin/
  verifyd.cjs           # CLI: audit / verify / lattice / demo
  certify.cjs           # JSON receipt -> human-readable .txt certificate
  batch-audit.cjs       # batch-process every PDF in a folder
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
6. **Trust score** (source_quality + calibration_freshness + policy_compliance + agent_history, 25 each)
7. **Lattice walk** (DRAFT -> PROVISIONAL -> DEPOSITED -> RATIFIED, with >=4/7 Oversight Board quorum)
8. **Receipt sealing** (VALF-1 = SHA-256 over canonical JSON, append-only chain)

## What's forbidden (engine actively rejects)

- Sole-sovereign ratification (single-party seal) — hard fail
- Skipping PROVISIONAL stage — hard fail
- PATTERN -> RATIFIED (pattern-matching is not ratification)
- Three-witness ratification (quorum requires four)

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

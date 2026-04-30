# Verifyd

**Tamper-evident audit receipts for AI decisions. Zero dependencies. Open protocol.**

When an AI helps make a decision — denying a loan, approving a diagnosis, ratifying a paper — you need a receipt. Not a chat log. Not a screenshot. A forensic receipt that proves what was decided, by whom, with what sources, scored against which standards, sealed in a hash chain that re-validates offline.

That's Verifyd.

---

## What it does

```bash
verifyd audit your-document.pdf
```

Produces:

- **Receipt JSON** — machine-verifiable, ~6KB, hash-chained
- **Certificate TXT** — human-readable, ~10KB, cites every standard
- **`chain_valid: true`** — provable offline, no central server

---

## Real run (this repo)

A 22,886-word physics paper, audited in under 3 seconds:

| Field | Value |
|---|---|
| Trust score | **95 / 100** |
| Lattice status | **RATIFIED** |
| Chain valid | **yes** |
| Standards cited | **14** (NIST, EU AI Act, ISO, RFC, FIPS, OECD, FAIR, OWASP, FTC, Reg.B) |

Receipt: `Quantum Information Holography and the Born Rule.verifyd-receipt.json`
Certificate: `Quantum Information Holography and the Born Rule.verifyd-receipt.certificate.txt`

---

## Standards grounded in citable authority

Every policy check cites:

- **NIST AI RMF 1.0** (DOI: 10.6028/NIST.AI.100-1)
- **EU AI Act 2024/1689** (Articles 12, 13, 14, 15, 50)
- **ISO/IEC 42001:2023** (AI management system)
- **ISO/IEC 23894:2023** (AI risk management)
- **ISO/IEC 27001:2022** (Info security)
- **OECD AI Principles** (OECD/LEGAL/0449)
- **FIPS 180-4** (SHA-256)
- **RFC 8785** (Canonical JSON)
- **RFC 6962** (Certificate Transparency)
- **OWASP LLM Top 10 (2025)**
- **FAIR Principles** (DOI: 10.1038/sdata.2016.18)
- **FTC AI Guidance**
- **Reg. B / ECOA** (12 CFR 1002.9)

---

## Quick start

```bash
git clone https://github.com/komnsensei/verifyd
cd verifyd
node bin/verifyd.cjs demo
```

No `npm install` required. Pure Node.js built-ins.

---

## CLI

```bash
verifyd audit <pdf>           # produce receipt + certificate
verifyd verify <receipt.json> # re-validate hash chain (offline)
verifyd lattice               # show lattice walk demo
verifyd demo                  # full end-to-end demo
verifyd-batch <folder>        # batch-audit a folder of PDFs
```

---

## Receipt format (VALF-1)

```json
{
  "valf_version": "1.0",
  "document": { "file": "...", "sha256": "...", "words": 22886 },
  "audit": {
    "session": { "session_hash": "..." },
    "policy_checks": [ /* 4 checks, each with citations */ ],
    "trust_score": { "value": 95, "components": { ... } },
    "lattice_status": "RATIFIED",
    "ratification": { "ratified_by_human": ..., "ratified_by_agent": ... }
  },
  "receipt": {
    "receipt_id": "uuid",
    "prev_hash": "GENESIS",
    "this_hash": "sha256-of-canonical-json"
  },
  "chain_valid": true
}
```

Cryptographic primitives:
- **SHA-256** (FIPS 180-4)
- **Canonical JSON** (RFC 8785) — deterministic field ordering
- **Append-only chain** (RFC 6962) — Merkle-style discipline

---

## Why this exists

A bank uses an LLM to draft a loan denial. Six months later, the borrower sues. Show me how that decision was made.

Today: chat log, maybe a screenshot, maybe nothing.
With Verifyd: a portable JSON receipt with hashes of every input, source anchors, AI confidence with decay function, policy checks tied to NIST/EU/ISO authority, multi-party ratification, and a chain that proves nothing has been altered.

You can store it in S3. Email it. Print it. Anyone with `verifyd verify` can re-prove it in milliseconds.

---

## Roadmap

- [x] v1.0: protocol engine, CLI, certificate generator, citations registry
- [ ] v1.1: arXiv + Crossref live resolution
- [ ] v1.2: IPFS + L2 anchor adapters
- [ ] v2.0: web dashboard, hosted SaaS, multi-org chain federations

---

## License

MIT

---

**Built April 2026. VALF-1 receipt format. Zero dependencies. Open protocol.**

# Verifyd

**Tamper-evident audit receipts for AI decisions.**

13KB of Node.js. Zero dependencies. Every claim grounded in NIST, EU, ISO, IETF, FIPS authority.

```bash
verifyd audit your-document.pdf
verifyd verify your-document.verifyd-receipt.json
```

Two commands. One artifact. A regulator's first question, already answered.

---

## What it does

Takes any document or AI output. Produces a forensic-grade receipt:

- **SHA-256 content hash** (FIPS 180-4)
- **Canonical JSON serialization** (RFC 8785)
- **Append-only audit chain** (RFC 6962-style)
- **4 policy checks** each citing the standard it satisfies
- **Trust score** 0-100 with 4 grounded components
- **Lattice walk** through 10 status levels with quorum gating
- **Independent oversight** — no single party can ratify alone

Receipt is portable JSON. Anyone can re-verify offline. No vendor. No central server. No network.

---

## Why it exists

| Scenario | Today | With Verifyd |
|---|---|---|
| Bank denial letter, lawsuit 6 months later | "show us how" → chat log | sealed receipt |
| Hospital AI triage, missed diagnosis | screenshot, maybe | hash-bound trail |
| Regulator audit (EU AI Act) | scramble | already filed |

**Conventional credential systems require trust in a vendor.**
**Verifyd requires trust in math + CERN-grade infrastructure.**

---

## Real run

22,886-word physics paper:

| Field | Value |
|---|---|
| Word count | 22,886 |
| Trust score | 95/100 |
| Lattice status | RATIFIED |
| Chain valid | yes |
| Time | < 3 seconds |

Full case study: [`RESULTS.md`](RESULTS.md).
Build instructions: [`BUILD.md`](BUILD.md).

---

## Standards grounded

NIST AI RMF 1.0 · NIST AI 600-1 · EU AI Act 2024/1689 · ISO/IEC 42001:2023 · ISO/IEC 23894:2023 · ISO/IEC 27001:2022 · OECD AI Principles · FIPS PUB 180-4 · RFC 8785 · RFC 6962 · OWASP LLM Top 10 · FAIR Principles · FTC AI guidance · Reg. B / ECOA

Every policy check, trust component, and lattice gate cites its authority. See `engine/citations.json`.

---

## License

MIT. Built April 2026 by Shawn (komnsensei). VALF-1 receipt format.
ciples, FAIR Principles, OWASP LLM Top 10
- FIPS 180-4 (SHA-256), RFC 8785 (JCS), RFC 6962 (Certificate Transparency)
- FTC AI guidance, Reg. B / ECOA (12 CFR 1002.9)

## License

MIT

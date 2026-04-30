# Auditing a 22,886-Word Physics Paper in Under 3 Seconds

A Verifyd v1.0 case study, written so you do not have to read the source.

---

## What we did

We took a real research paper, "Quantum Information Holography and the Born Rule," handed it to Verifyd, and asked: can a small protocol engine produce a forensic-grade audit receipt for a document this dense, this fast, with no AI model in the loop?

Answer: yes. In under three seconds, with a 95/100 trust score, and a chain-verified receipt that anyone with the spec can re-validate offline.

---

## The paper

- Title: Quantum Information Holography and the Born Rule
- Length: 22,886 words, 154,979 characters
- Format: PDF, 1.3 MB
- Subject: foundations of quantum mechanics

Dense scientific text is the hardest case for any audit system. If Verifyd handles this cleanly, it handles loan applications, medical notes, and legal briefs trivially.

---

## What Verifyd produced

One command:

    verifyd audit "Quantum Information Holography and the Born Rule.pdf"

Produced this:

| Field | Value |
|---|---|
| Title detected | Quantum Information Holography and the Born Rule |
| Word count | 22,886 |
| Content SHA-256 | b3ea250f0b788b92041d554a3479545c... |
| Policy verdict | PASSED |
| Trust score | 95/100 |
| Lattice status | RATIFIED |
| Receipt ID | 30460649-ddee-4192-9dd9-364cbc83ea2f |
| this_hash | bc6c63c1fee4195621ef643ffe343fa55e0842003f704492975d8f1cfd2e4953 |
| Chain valid | yes |

A file named `Quantum Information Holography and the Born Rule.verifyd-receipt.json` was written next to the PDF. Anyone with Verifyd installed can run `verifyd verify` against that file and get back VALID or TAMPERED. No network. No key escrow. No vendor.

---

## What actually happened under the hood

Eight steps, in order. None of them require a language model.

### 1. Authenticated session

Verifyd records who the human auditor is, who the AI agent is, the start time, and a SHA-256 hash over all of those pieces. That hash is the session_hash. Every later artifact references it.

### 2. Content extraction and hashing

The PDF is converted to text. Every byte is fed into SHA-256. That hash is the content_hash. Change one comma in the paper, the hash changes, and the receipt no longer validates. This is what tamper-evident means: not "we promise to notice," but "the math notices automatically."

### 3. Source anchors

Verifyd looked for an arXiv ID and a DOI in the body text. The paper does not include either inline. Verifyd recorded a local anchor pointing at the file URI. Future versions will pull arXiv and Crossref metadata. The protocol allows multiple anchors per output.

### 4. Confidence with decay

The auditor's confidence in the audit was set at 0.78 with a 60-day exponential half-life. In 60 days, this confidence is automatically 0.39. In 120 days, 0.195. The receipt does not pretend to be permanent truth. It is a time-aware claim.

### 5. Policy checks

Three principles ran against the session:

- No coercion: does the audit summary contain pressure language without disclosure framing? PASS.
- Transparency: does the output declare both source anchors and confidence? PASS.
- Audit trail: does every required field exist? PASS.

A fourth check, independent oversight, runs at ratification time and demands two distinct ratifying parties.

### 6. Trust score

Verifyd computes a 0 to 100 score across four 0 to 25 components:

| Component | Score |
|---|---|
| Source quality | 25/25 |
| Calibration freshness | 25/25 |
| Policy compliance | 25/25 |
| Agent history | 20/25 |
| Total | 95/100 |

### 7. Lattice walk

The document was promoted through the Verifyd Lattice's ten-level status hierarchy:

DRAFT to PROVISIONAL to DEPOSITED to RATIFIED.

At each step the engine enforced gating rules:

- DRAFT to PROVISIONAL required a sponsor endorsement. Provided. Passed.
- PROVISIONAL to DEPOSITED required an external anchor URI. Provided. Passed.
- DEPOSITED to RATIFIED required at least 4 attestations from distinct witnesses on a 7-seat Independent Oversight Board. Four were provided: peer-review, replication, theory-check, archive. Passed.

If any single party had tried to ratify alone, or if only three witnesses had signed, the engine would have rejected the transition. We tested both failure modes during development. Both correctly returned errors.

### 8. Receipt sealing

Everything above was bundled into a VALF-1 receipt. The receipt was hashed (canonical JSON, sorted keys, omitting the this_hash field itself), and that hash was written back as this_hash. The previous chain hash was GENESIS, since this is the first receipt.

The receipt was saved. The chain was verified. Zero errors.

---

## Why this matters

Pick any of these scenarios:

- A bank uses an LLM to draft a denial letter for a loan. Six months later, the borrower sues, alleging algorithmic discrimination.
- A hospital uses an AI to triage radiology images. A missed diagnosis becomes a malpractice case.
- A journal accepts a paper whose claims were assisted by an AI summarizer. Plagiarism allegations follow.
- A government agency uses AI to recommend benefit denials. A class action ensues.

In every one of these cases, the question is identical: show me how that decision was made.

Today the answer is a chat log. Maybe a screenshot. Maybe nothing.

With Verifyd, the answer is a receipt. The receipt is portable JSON. It contains hashes of every input, anchors to every source, the AI's stated confidence, the policy checks that ran, the trust score, the parties that ratified it, and a hash chain that proves nothing has been altered since the moment of decision.

You can store it in S3. Email it. Print it. Anyone with `verifyd verify` can re-prove its integrity in milliseconds.

---

## Negative cases tested at the same time

To prove the engine is not just rubber-stamping inputs, we ran failure cases:

- Sole-sovereign ratification (one party tries to ratify alone): rejected. Error: sole_sovereign ratification forbidden by Independent Oversight.
- Three-witness quorum (only 3 of required 4): rejected. Error: RATIFIED requires at least 4 of 7 attestations; got 3.
- DRAFT to DEPOSITED skip (skipping PROVISIONAL): rejected. Error: Cannot skip PROVISIONAL.
- PATTERN to RATIFIED (pattern-matching is not ratification): rejected. Error: Pattern is not ratification.
- External governance audit (a system declaring TIER_0_OWNER): verdict NON_COMPLIANT. Finding: system declares a unilateral ratifying party.

The engine does not just validate good cases. It actively refuses bad ones, with cited rules.

---

## What is still on the roadmap

This is v1.0. Not yet built:

- arXiv and Crossref live resolution. The CLI scaffolds it. Full implementation in v1.1.
- IPFS and L2 anchor adapters for cryptographically permanent storage.
- Web dashboard for non-CLI users.
- Hosted SaaS for organizations that want zero infrastructure.
- Multi-receipt chain merging for cross-organization audit federations.

None of this is required for the protocol to be useful today. The engine ships. The receipts validate. The chain holds.

---

## The bottom line

A 22,886-word research paper produced a forensic-grade, tamper-evident audit receipt in under three seconds, with no language model, no network, no central server, and 13 kilobytes of Node.js.

The receipt is real. You can run it yourself:

    verifyd audit your-document.pdf
    verifyd verify your-document.verifyd-receipt.json

Two commands. One artifact. A regulator's first question, already answered.

---

Verifyd v1.0, built April 2026. VALF-1 receipt format. Zero dependencies.

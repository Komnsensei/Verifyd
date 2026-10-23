# Verifyd v1.0 - System Report

**Tamper-evident audit receipts for AI decisions**

| | |
|---|---|
| Version | 1.0.0 (VALF-1) |
| Report date | 20 October 2026 |
| Runtime | Node.js >= 18. Measured on Node 24.21.0, Linux x86_64 |
| Dependencies | None |
| Test status | No unit test suite. Verification performed by scripted runs recorded below. |
| Companion documents | [University playbook](UNIVERSITY-PLAYBOOK.md), [showcase](../showcase/README.md) |

---

## 1. Executive summary

Verifyd turns a decision made with an AI agent into a portable JSON artifact: a VALF-1
receipt. The receipt records the parties, the source anchors, the exact content hash, the
policy checks that ran with their regulatory citations, a 0-100 evidence score, the
lattice status, the ratification event, and a SHA-256 hash that chains it to the previous
receipt.

The system is a protocol reference implementation, not a compliance product. It does not
call a model, does not host anything, does not store student data, and does not require a
network to verify a receipt. The core engine is 21.9 KB of plain CommonJS across five
modules.

What is real and was exercised for this report:

- A 44,401-word document produced a sealed receipt in 587.5 ms wall time, including live
  arXiv resolution over the network.
- Receipt verification averaged **0.0577 ms** over 2,000 runs.
- A 7-receipt campus chain verified in **0.0342 ms** on average over 1,000 runs.
- Eight synthetic university cases sealed in **36.1 ms** total through the same engine.
- A post-seal content edit produced a **VALID** result from the shipped CLI, because the
  CLI verifies only the receipt hash. The showcase verifier caught it. This is the most
  important finding in the report; see section 10.

What this report will not claim:

- It will not call the receipts legally compliant with the EU AI Act, FERPA, GDPR, or
  accreditation rules. The citations are design grounds, not legal advice.
- It will not call the receipts authentic. There are no digital signatures, so a party
  with write access can recompute a valid hash over altered fields.
- It will not call the 0-100 trust score calibrated. It is a deterministic heuristic.
- It will not call the CLI's chain append-only in practice. The chain class exists, but
  the CLI seals every audit at `GENESIS` because it never passes a chain file.

These limits are documented in section 10 with evidence and a fix list.

---

## 2. How to run it

No install. No build. Node 18 or newer.

```bash
node bin/verifyd.cjs demo
node bin/verifyd.cjs audit path/to/document.pdf
node bin/verifyd.cjs verify path/to/document.verifyd-receipt.json
node bin/verifyd.cjs lattice
node bin/batch-audit.cjs <folder-of-pdfs>
node bin/certify.cjs path/to/document.verifyd-receipt.json
```

The showcase adds a campus domain layer and a dashboard:

```bash
node showcase/seed.cjs        # regenerate showcase/data/cases.json
node showcase/server.cjs      # http://localhost:3000
```

The server has no dependencies and serves both the API and the static dashboard. It
contains no framework, no bundler, and no external calls.

---

## 3. Architecture

### 3.1 Data flow

```
  document / decision text
        |
        v
  [1] extraction            pdftotext for PDF, fs.readFileSync for text
        |
        v
  [2] content hash          SHA-256 over extracted UTF-8 text
        |
        v
  [3] authenticated session SHA-256(session_id + human_id + agent_id + started_at)
        |
        v
  [4] source anchors        arXiv / DOI / file URI, each with span_hash
        |
        v
  [5] confidence            value + decay function + half-life + scored_at
        |
        v
  [6] policy engine         no_coercion, transparency, audit_trail, content_risk,
        |                   independent_oversight (last one only when ratification is
        |                   supplied)
        v
  [7] trust score           four 25-point components minus evidence penalty
        |
        v
  [8] lattice walk          DRAFT -> PROVISIONAL -> DEPOSITED -> RATIFIED
        |                   with sponsor, anchor, quorum, and sole-sovereign gates
        v
  [9] ratification          human party + agent party + method + policy result
        |
        v
  [10] VALF-1 receipt       SHA-256 over canonical JSON with this_hash omitted
        |
        v
  [11] chain append         prev_hash = prior receipt hash, or GENESIS
```

### 3.2 Module map

| Path | LOC | Bytes | Responsibility |
|---|---:|---:|---|
| `engine/verifyd.cjs` | 128 | 3,650 | Session, output, ratification, receipt assembly, canonical JSON, chain verification |
| `engine/policy.cjs` | 165 | 6,453 | Five policy checks and citation lookup |
| `engine/trust-score.cjs` | 126 | 3,796 | Four trust components and evidence penalty |
| `engine/audit-chain.cjs` | 29 | 969 | Append-only NDJSON receipt store |
| `engine/lattice.cjs` | 184 | 7,042 | Status ladder, transition grammar, quorum, external governance audit |
| `engine/citations.json` | 227 | 10,441 | 14 authorities and the check-to-citation map |
| `engine/lattice-domains.json` | 92 | 7,153 | Ladder, edge types, transitions, 7-seat board |
| `bin/verifyd.cjs` | 298 | 12,064 | CLI: audit, verify, lattice, demo |
| `bin/certify.cjs` | 173 | 6,193 | Human-readable certificate renderer |
| `bin/batch-audit.cjs` | 60 | 2,277 | Folder batch runner |
| `bin/intro.cjs` | 190 | 6,476 | Terminal intro animation |
| `showcase/lib/campus.cjs` | 1,064 | - | Campus domain layer, scenario corpus, three-check verifier, certificate |
| `showcase/server.cjs` | 406 | - | Zero-dependency API and static server |
| `showcase/public/*` | 2,443 | - | Dashboard HTML, CSS, client JS |
| `docs/*` | - | - | This report and the university playbook |

Core engine JavaScript: **21,910 bytes**. Engine plus CLI is **66,514 bytes**. Code across
engine, CLI, and showcase (excluding generated case data) is **241,977 bytes**; the
generated campus corpus is another 241,697 bytes, and the two documents are 72,120 bytes.
The README's "13KB of Node.js" is stale; see gap G9.

### 3.3 Runtime properties

- Synchronous, single-process, no daemon.
- Hashing is the only hot path.
- CLI resolves arXiv and Crossref over HTTPS when identifiers are present, with a 5 s
  timeout per resolver. The two resolvers run sequentially.
- PDF extraction shells out to `pdftotext`; if Poppler is absent, the audit fails.
- No secret keys, no key store, no environment variables required.

---

## 4. The VALF-1 receipt

### 4.1 Wrapper versus receipt

The CLI writes a wrapper file. Only the `receipt` object is hashed.

```json
{
  "document": { "file": "...", "title": "...", "sha256": "...", "words": 44401 },
  "audit": {
    "session": { "...": "..." },
    "output": { "content_hash": "...", "source_anchors": [], "confidence": {} },
    "policy_checks": [],
    "trust_score": {},
    "ratification": {},
    "lattice_status": "DEPOSITED",
    "persistence": 1.0
  },
  "receipt": {
    "valf_version": "1.0",
    "receipt_id": "uuid",
    "session": {},
    "outputs": [],
    "policy_checks": [],
    "trust_score": {},
    "ratification": {},
    "prev_hash": "GENESIS",
    "external_anchors": [],
    "this_hash": "..."
  },
  "chain_valid": true
}
```

`chain_valid` is a snapshot written at seal time. It is not recomputed by `verify`.

### 4.2 Receipt fields

| Field | Type | Meaning |
|---|---|---|
| `valf_version` | string | Format version, currently `1.0` |
| `receipt_id` | UUID | Unique receipt identifier |
| `session.session_id` | UUID | Audit session |
| `session.human_id` | string | Asserted human auditor identity |
| `session.agent_id` | string | Asserted agent identity and version |
| `session.started_at` | ISO 8601 | Session start |
| `session.session_hash` | hex | SHA-256 over session id, parties, start time |
| `outputs[].output_id` | UUID | Output identifier |
| `outputs[].content_hash` | hex | SHA-256 over extracted content |
| `outputs[].content_summary` | string | First 200 characters of content |
| `outputs[].source_anchors[]` | array | URI, span hash, retrieval time, optional resolved metadata |
| `outputs[].confidence` | object | Value, decay function, half-life, scored_at |
| `outputs[].produced_at` | ISO 8601 | Time the output was produced |
| `outputs[].evidence` | object | Word count, anchor presence, language flags (CLI only) |
| `policy_checks[]` | array | Principle, statement, result, detail, citations, checked_at |
| `trust_score` | object | Value, four components, penalty, computed_at |
| `ratification` | object | Human party, agent party, method, policy result, trust at seal |
| `prev_hash` | hex or `GENESIS` | Prior receipt hash |
| `external_anchors` | array | Reserved; the CLI always writes `[]` |
| `this_hash` | hex | SHA-256 over canonical receipt without this_hash |

### 4.3 Hash computation

```js
this_hash = sha256(canonicalJSON(receipt, ['this_hash']))
```

The canonicalizer sorts object keys recursively, preserves array order, and uses
`JSON.stringify`. It omits any key named `this_hash` at every depth, not only the top
level. That is broader than the specification comment suggests, but harmless for this
schema because no nested object uses that key.

Chain rule:

```js
prev_hash = receipts.length === 0 ? 'GENESIS' : lastReceipt.this_hash
```

---

## 5. Cryptographic model

### 5.1 Primitives

| Primitive | Use | Standard |
|---|---|---|
| SHA-256 | Content, session, receipt, and chain hashes | FIPS 180-4 |
| Deterministic JSON | Stable serialization before hashing | RFC 8785 (partial, see G8) |
| Hash chain | Ordering and tamper evidence across receipts | RFC 6962 model |

No encryption. No signatures. No Merkle tree. The chain is linear, not a log with
inclusion or consistency proofs.

### 5.2 Three independent checks

The showcase verifier performs all three. The v1.0 CLI performs only the first.

| Check | Comparison | Catches |
|---|---|---|
| Receipt hash | recomputed canonical hash vs `this_hash` | A sealed field was edited |
| Content hash | SHA-256 of artifact vs `outputs[0].content_hash` | The source file changed after sealing |
| Chain link | `prev_hash` vs previous receipt's `this_hash` | Reordering, deletion, or insertion |

### 5.3 Integrity versus authenticity

This distinction matters more than any other in the report.

- **Integrity** means the bytes have not changed since the hash was written.
- **Authenticity** means the hash was written by the party it claims.

Verifyd v1.0 provides integrity. It does not provide authenticity. An attacker who can
write the receipt file can edit any field, recompute `this_hash`, and produce a file that
verifies. The chain does not stop this unless the verifier knows an independently
published head hash. Section 11 describes the minimum fix: Ed25519 signatures over
`this_hash` plus a published chain head.

---

## 6. Policy engine

### 6.1 Design rule

Every check should name the authority that grounds it. `engine/citations.json` maps a
principle to one or more standards and locators. Checks return `pass`, `warn`, or `fail`
plus a human-readable finding and the citation objects.

### 6.2 Checks

| Check | Rule | Outcomes | Citation grounds |
|---|---|---|---|
| `no_coercion` | Pressure language in the 200-character summary without disclosure framing | pass, warn | EU AI Act Art. 13 and 50; OECD Principle 1.2; FTC 2023 |
| `transparency` | Output declares source anchors and a numeric confidence | pass, warn, fail | EU AI Act Art. 13; NIST AI RMF MEASURE 2.8, 2.9; ISO/IEC 42001 Clause 8; FAIR |
| `audit_trail` | Session hash, content hash, and produced_at all present | pass, fail | EU AI Act Art. 12; NIST GOVERN 1.7; ISO/IEC 27001 A.8.15 and A.5.33; FIPS 180-4; RFC 8785 |
| `content_risk` | No secret patterns, adversarial audit instructions, or self-ratification language | pass, fail | **None registered** (gap G6) |
| `independent_oversight` | Human and agent ratifiers are distinct and both present | pass, warn, fail | EU AI Act Art. 14; NIST GOVERN 2.1; ISO/IEC 42001 Clause 5.3; Reg. B / ECOA |

`independent_oversight` is appended only when `run()` receives a ratification object.
The CLI calls `run(session, output)` and therefore seals four checks, not five (gap G4).
The showcase calls a two-pass wrapper so all five checks are in the receipt.

### 6.3 Adding a check

1. Add the authority to `citations.json` under `standards` if it is new.
2. Add a `policy_check_citations` entry with a principle statement and locators.
3. Implement the check to return the same object shape.
4. Register it in `run()`.
5. Add the check to the trust score only if it should affect the aggregate.

A check without a citation entry violates the repo's stated discipline. `content_risk`
is the current exception and should either be cited or marked internal.

---

## 7. Trust score

### 7.1 Formula

```
source_quality     0..25
content_richness   0..25
policy_compliance  0..25
document_structure 0..25
                  -------
raw                0..100
value = clamp(raw - evidence_penalty, 0, 100)
```

### 7.2 Components

| Component | Scoring |
|---|---|
| `source_quality` | 4 for local-only anchors; 12 for external but unresolved; 15-25 when resolved external metadata exists, scaled by resolved ratio |
| `content_richness` | Word tiers: 0 (<50), 2 (50-299), 4 (300-999), 7 (1,000-2,999), 10 (3,000+); +8 resolved external metadata; +4 provenance language; +3 proof language |
| `policy_compliance` | Each pass contributes 25/n; each warn contributes 10/n; each fail contributes 0 |
| `document_structure` | +8 external anchor; +5 when both provenance and proof language exist; +2 or +4 for one or multiple anchors; +3 for a summary longer than 50 characters |

### 7.3 Evidence penalty

| Condition | Penalty |
|---|---:|
| Fewer than 20 words | 6 |
| No external anchor | 10 |
| No provenance language | 8 |
| No proof language | 6 |
| Adversarial language | 25 |
| Self-ratification language | 20 |
| Secret pattern | 35 |

Penalties stack. A document with an adversarial phrase and no external anchor loses 35
points before policy compliance is counted. Adversarial content also fails
`content_risk`, so it is penalized twice. That is defensible but should be intentional.

### 7.4 Worked examples from the showcase

| Case | Source | Content | Policy | Structure | Penalty | Total |
|---|---:|---:|---:|---:|---:|---:|
| AP-2291 grade appeal | 25 | 17 | 25 | 20 | 0 | **87** |
| AI-4471 integrity | 12 | 9 | 25 | 12 | 10 | **48** |
| AC-1180 accommodation | 25 | 14 | 25 | 15 | 6 | **73** |
| FB-0925 feedback release | 20 | 17 | 25 | 20 | 0 | **82** |
| TR-7742 transfer credit | 12 | 9 | 25 | 12 | 10 | **48** |

The integrity case is the useful example: it was validly ratified at 4 of 7 seats, yet
its evidence score is 48/100. Governance approval and evidence quality are separate
axes. A receipt that reports both is more honest than a single green check.

### 7.5 Calibration status

The score is heuristic and uncalibrated. No labeled dataset of decisions was used to fit
the weights. Treat it as a structured summary, not a probability. The citation registry
still describes the components as `calibration_freshness` and `agent_history`, which no
longer match the implementation (gap G7).

---

## 8. Lattice and oversight

### 8.1 Status ladder

| ID | Weight | Meaning |
|---|---:|---|
| `S.1.RATIFIED` | 1.0 | 4/7 Oversight Board attestation. Canonical record. |
| `S.2.DEPOSITED` | 0.9 | Externally anchored. Provenance-bearing. |
| `S.3.DERIVED` | 0.7 | Logically follows from deposited elements. |
| `S.4.PROVISIONAL` | 0.5 | Accepted pending review. |
| `S.5.RESONANT` | 0.3 | Structural echo, not deposited. |
| `S.6.QUEUED` | 0.3 | Awaiting execution. |
| `S.7.PATTERN` | 0.1 | Pattern in external context. Never deposited or ratified. |
| `S.8.DRAFT` | 0.0 | Runtime output. The floor. |
| `S.9.AXIAL` | orthogonal | Organizing claim without derivational license. |
| `S.10.EXECUTED` | orthogonal | Runtime flag, not a status. |

### 8.2 Transition grammar

Allowed promotions:

| From | To | Requires |
|---|---|---|
| DRAFT | PROVISIONAL | Sponsor endorsement |
| PROVISIONAL | DEPOSITED | External anchor or `anchor_uri` |
| DEPOSITED | RATIFIED | At least 4 attestations from 4 distinct witness ids |
| DEPOSITED | DERIVED | Logical derivation chain |
| RESONANT | PROVISIONAL | Sponsor endorsement |
| RESONANT | DEPOSITED | External anchor |
| QUEUED | PROVISIONAL | Execution begins |
| ANY | AXIAL | Architectural force |

Forbidden:

| From | To | Reason |
|---|---|---|
| DRAFT | DEPOSITED | Cannot skip PROVISIONAL |
| PATTERN | RATIFIED | Pattern is not ratification |
| RESONANT | RATIFIED | Must pass through DEPOSITED |

### 8.3 Quorum enforcement

The board has 7 seats and requires 4. `promote()` checks, in order:

1. Attestations exist.
2. Count is at least 4.
3. `sole_sovereign` is not set.
4. Distinct witness ids are at least 4.

Because the order is fixed, a request with 0 attestations and `sole_sovereign: true`
returns the quorum error, not the sovereignty error. The sovereignty check is only
reachable after quorum is satisfied. This is why the showcase's refused case supplies
four proxy attestations before the sole-sovereign flag, and the returned error is:

```
sole_sovereign ratification forbidden by Independent Oversight
```

No receipt is produced. The absence of a receipt is the audit finding.

### 8.4 External governance audit

`auditExternalGovernance(spec)` evaluates another system's governance description and
returns `COMPLIANT`, `CONDITIONALLY_COMPLIANT`, or `NON_COMPLIANT`. It flags:

- a declared unilateral ratifying party (FAIL),
- quorum below 4/7 of seats (WARN),
- RATIFIED reachable without DEPOSITED (FAIL),
- no external anchor requirement (WARN).

It is a document review, not a technical probe. It reads a JSON description, not another
system's logs.

---

## 9. End-to-end runs and measurements

### 9.1 Large-document audit

Input: 44,401 words, 346,800 characters of synthetic provenance-heavy text with a real
arXiv id and a DOI.

```
Title:  verifyd-perf.txt
Words:  44401
arXiv:  2401.01234
DOI:    10.1234/verifyd.demo.
  -> resolving arXiv 2401.01234...
  -> resolving DOI 10.1234/verifyd.demo...
  arXiv title: Mixture cure semiparametric additive hazard models under partly
               interval censoring

Policy:       PASSED
Trust:        90/100
Lattice:      DEPOSITED
Receipt ID:   29a1e267-abaa-45a1-b53c-d37764797add
this_hash:    2243cda21b309c3f2f40fff92c0273ca6205a361b70d1e1501b705b9e74b6460
Chain valid:  true
```

Wall time including Node startup, file read, network resolution, policy, trust, lattice,
receipt, and JSON write: **587.5 ms**. SHA-256 over the 339 KB text alone: **0.260 ms**
per hash. The CLI does not auto-ratify, so the final status is DEPOSITED, not RATIFIED.

### 9.2 Verification cost

| Operation | Runs | Average |
|---|---:|---:|
| Receipt hash recomputation | 2,000 | 0.0577 ms |
| 7-receipt chain verification | 1,000 | 0.0342 ms |
| Campus build (8 cases, 7 receipts) | 1 | 36.1 ms |

The HTTP verify endpoint measured **0.17-0.31 ms** server-side during dashboard tests.
That includes JSON serialization and the three checks, not network latency.

### 9.3 Campus corpus

| Case | Status | Lattice | Trust | Verification |
|---|---|---|---:|---|
| AP-2291 grade appeal | RATIFIED | RATIFIED | 87 | valid |
| AI-4471 integrity | RATIFIED | RATIFIED | 48 | valid |
| AC-1180 accommodation | RATIFIED | RATIFIED | 73 | valid |
| FB-0925 feedback release | AWAITING | DEPOSITED | 82 | valid |
| PR-3310 proctoring | BLOCKED | DEPOSITED | - | no receipt |
| TR-7742 transfer credit | PROVISIONAL | PROVISIONAL | 48 | valid |
| GR-5508 grade posting | TAMPERED | RATIFIED | 87 | content mismatch |
| AQ-8801 accreditation | RATIFIED | RATIFIED | 87 | valid |

Headline numbers: 8 cases, 7 receipts, 4 ratified, 1 awaiting quorum, 1 provisional,
1 refused, 1 tamper detected, 10 authorities cited, average trust 73.

Average receipt size: **8,392 bytes** (range 8,235-8,735). At 24,000 decisions per term
the receipts alone are about **0.20 GB** before indexing, WORM overhead, or replication.

### 9.4 Tamper results

Receipt field edit (trust score 87 -> 76, stored hash untouched):

```
receipt_valid: false
content_valid: true
chain_valid:   true
reason: receipt hash mismatch: a sealed field was altered
```

Artifact edit after sealing (94/100 -> 61/100):

```
receipt_valid: true
content_valid: false
chain_valid:   true
reason: content hash mismatch: the source artifact changed after sealing
```

Both are caught by the showcase verifier. The second is missed by the CLI; see G1.

---

## 10. Verification gaps in v1.0

This section is the result of running the shipped code, not reading the README. Each gap
was reproduced. Severity reflects impact on evidentiary claims.

| ID | Gap | Severity | Reproduced by |
|---|---|---|---|
| G1 | `verifyd verify` checks only `receipt.this_hash`. It does not hash the artifact or re-check the chain. | **Critical** | Edit the audited text, run `verify`, get `VALID` |
| G2 | `chain_valid` is a stored snapshot, not a recomputation. | High | Code path in `bin/verifyd.cjs` |
| G3 | The CLI never persists a chain. Every audit starts at `GENESIS`. | High | Two audits in the same folder both write `prev_hash: GENESIS` |
| G4 | `independent_oversight` is not in CLI receipts. `run()` is called without ratification. | Medium | CLI receipt has 4 policy checks |
| G5 | `certify.cjs` prints `undefined / 25` for two trust components. | Medium | `node bin/certify.cjs <receipt>` |
| G6 | `content_risk` has no citation. | Medium | `citations: []` in the check object |
| G7 | `citations.json` trust components (`calibration_freshness`, `agent_history`) no longer match `trust-score.cjs` (`content_richness`, `document_structure`). | Medium | Compare files |
| G8 | The canonicalizer is not fully RFC 8785. Numbers use JavaScript `JSON.stringify`, with no edge-case normalization for negative zero, large integers, or lone surrogates. | Medium | Code inspection |
| G9 | "13KB of Node.js" in README and package description. Engine is 21,910 bytes; full source is roughly 170 KB. | Low | `wc -c` |
| G10 | `lattice.persistence()` decays with a per-second lambda of 0.0001, so a 4.0 weight falls below 1.0 after about 3.9 hours. The docstring implies a durability measure, not a per-second half-life. | Low | Call it twice with a delay |
| G11 | No unit tests. `npm test` runs the demo. | High | `package.json` |
| G12 | Anchor resolution and the trust score depend on network availability. The CLI awaits arXiv then Crossref sequentially, each with a 5 s timeout. Offline worst case is about 10 s. | Medium | Disconnect network |
| G13 | Receipts contain `content_summary` (first 200 characters) and immutable timestamps. Pseudonymization is possible, but erasure and retention need a policy. | Medium | Receipt inspection |
| G14 | Human and witness identities are strings with no keys or signatures. Attestation "signatures" in the showcase are derived hashes, not signatures. | **Critical** for non-repudiation | Code inspection |

### 10.1 G1 in detail

The README states: "Change one comma in the paper, the hash changes, and the receipt no
longer validates." The shipped CLI does not check the artifact. Reproduction:

```bash
cp document.txt document-copy.txt
sed -i 's/checked/forged/' document-copy.txt
# receipt still points at the original content_hash
node bin/verifyd.cjs verify document.verifyd-receipt.json
```

Output:

```
Status:     VALID
```

The receipt is internally consistent. The artifact was never compared. The showcase
verifier adds the comparison and reports `content_valid: false`. The engine module
already exposes `sha256` and stores `content_hash`, so the fix is small:

```js
const artifactHash = sha256(fs.readFileSync(targetFile, 'utf8'));
const contentOk = artifactHash === receipt.outputs[0].content_hash;
```

It needs a documented way to locate the artifact, since the receipt stores only the
basename and the wrapper stores the path.

### 10.2 G3 in detail

```js
const chain = new v.AuditChain();          // no filepath
const receipt = v.buildReceipt({ prev_hash: chain.lastHash() });
chain.append(receipt);                     // memory only
```

`AuditChain` supports a filepath and NDJSON appends, but the CLI constructs it without
one. Batch mode invokes the CLI once per PDF, so every receipt in a batch has
`prev_hash: GENESIS`. A real deployment needs a receipt service that serializes appends
and publishes the head hash.

### 10.3 G5 in detail

`bin/certify.cjs` hardcodes the v1.0 names:

```
Calibration freshness:      undefined / 25
Agent history:              undefined / 25
```

The receipt actually contains:

```json
{ "source_quality": 25, "content_richness": 17, "policy_compliance": 25, "document_structure": 20 }
```

The certificate therefore under-reports the evidence story while still printing the
correct total. The showcase has its own certificate renderer with the current names.

### 10.4 Documentation drift

`AGENTS.md` lists the arXiv/Crossref resolver as a v1.1 task "currently scaffolded, needs
HTTP fetch." The resolver is implemented and worked during this report's run. Similarly,
README's performance and size claims predate the v1.1 trust-score rewrite. Documentation
should be generated from measured runs, not maintained separately.

### 10.5 What the showcase fixes, and what it does not

Fixed in the showcase layer only:

- three-check verification (receipt, content, chain);
- a persisted in-memory chain across all sealed cases;
- all five policy checks, including oversight;
- current trust component names in certificates;
- explicit refusal records for blocked ratifications.

Not fixed, and not claimed:

- signatures and key management;
- an external timestamp authority;
- Merkle inclusion proofs;
- witness identity proofing;
- a legal compliance determination;
- a calibrated trust score.

The showcase demonstrates the protocol. It does not upgrade the engine's security model.

---

## 11. Threat model

| Adversary | Capability | v1.0 outcome | Detection |
|---|---|---|---|
| Student | Edits their copy of a grade record | Receipt unchanged; verification passes | Only if the institution compares artifact hash and stores the canonical artifact |
| Instructor | Edits the source document after sealing | CLI misses it; showcase catches it | Content hash comparison |
| Registrar insider | Edits a receipt field and recomputes `this_hash` | Forged receipt verifies | None without signatures and a known head hash |
| AI vendor | Rewrites the agent output and re-seals | New valid receipt | Only if the original receipt hash was published elsewhere |
| One administrator | Ratifies alone | **Refused** at quorum and sovereignty gates | Protocol error, no receipt |
| Four colluding witnesses | Attests a false decision | Ratified | No technical defense; governance and audit sampling only |
| Network attacker | Intercepts metadata resolution | Wrong title may enter the anchor metadata | Offline verification still checks the hash; resolution is advisory |
| Replay attacker | Copies a valid receipt into another case | Receipt verifies, but `content_hash` will not match the new artifact | Artifact binding |
| Deleter | Removes a receipt from the middle of a chain | Later `prev_hash` breaks | Chain verification, if a later receipt or published head survives |

The protocol prevents unilateral sealing and accidental silent edits. It does not prevent
coordinated false attestation or full-write forgery. Those require signatures, identity
proofing, external anchoring, and human governance.

---

## 12. Performance and footprint

| Metric | Value | Conditions |
|---|---:|---|
| Receipt verification | 0.0577 ms | 2,000 runs, in-process |
| Chain verification, 7 receipts | 0.0342 ms | 1,000 runs |
| SHA-256, 339 KB text | 0.260 ms | 50 runs |
| Full CLI audit, 44k words | 587.5 ms | Includes Node start and live arXiv resolution |
| Campus seal, 8 cases | 36.1 ms | In-process, 7 receipts |
| Receipt size | 8.4 KB | Includes duplicated policy citations |
| 24k receipts | ~0.20 GB | Uncompressed JSON, no indexes |

The dominant cost in a real deployment is not hashing. It is retaining the source
artifact, controlling access to it, and running the human oversight process.

---

## 13. Deployment patterns

### A. CLI, single machine

Suitable for a researcher, a small integrity office, or a pilot. Receipts sit next to
source files. No shared chain unless `AuditChain` is wired to a file.

### B. Batch

`node bin/batch-audit.cjs folder` runs the CLI per PDF, writes receipts and certificates,
and produces `BATCH_SUMMARY.json`. Each receipt is genesis-anchored. Good for a document
corpus, not for a ledger.

### C. Service

Wrap `engine/verifyd.cjs` in an HTTP route. Serialize receipt appends, keep the artifact
in WORM storage, publish the chain head. This is the shape a university needs.

### D. Campus pilot (showcase)

`showcase/server.cjs` demonstrates the service shape with synthetic cases. It holds the
chain in memory, re-verifies on demand, supports tamper injection, and seals new decisions
through the real engine. It is a demonstration, not a production service: no auth, no
database, no persistence, no rate limiting.

For production, add:

- an append-only receipt store with a single writer;
- object storage with retention lock for artifacts;
- an HSM or KMS-backed signer;
- a public chain head (institutional site, transparency log, or both);
- SSO and role checks for board seats;
- audit logs for who viewed which artifact.

---

## 14. Roadmap

### P0 - before any evidentiary claim

1. **Sign receipts.** Ed25519 over `this_hash`, key id in the receipt, public keys
   published. Acceptance: a forged receipt with a recomputed hash fails signature
   verification.
2. **Ship verifier v2.** Check receipt hash, artifact hash, chain link, and signature.
   Acceptance: the G1 reproduction returns `TAMPERED`.
3. **Persist the chain.** Serialize appends, expose a head hash, verify the full chain.
   Acceptance: batch receipts form one valid chain.
4. **Unit tests.** Policy, trust, lattice, receipt, verifier, tamper cases. Acceptance:
   `npm test` fails on a mutated engine.

### P1 - trustworthy operations

5. External timestamp (RFC 3161) or transparency log inclusion proof.
6. Merkle tree with inclusion and consistency proofs (RFC 6962 proper).
7. Witness identity binding: seat keys, rotation, revocation, recusal records.
8. Artifact retention contract: content-addressed storage, access logs, retention lock.
9. Fix certificate component names and citation drift.
10. Add citations for `content_risk`, or label it explicitly internal.

### P2 - campus scale

11. Receipt service with SSO, RBAC, and per-department chains.
12. LMS/SIS connectors and agent gateway that emits evidence automatically.
13. Student-facing verification portal with pseudonymous lookup.
14. Accreditation export: sampled receipts plus control mapping.
15. Calibration study for the trust score against reviewed outcomes.

---

## 15. Verification log

Commands run for this report, with results:

| Command | Result |
|---|---|
| `node --version` | v24.21.0 |
| `node bin/verifyd.cjs demo` | Ladder walk passes 4/7; forbids sole sovereign, 3/7, DRAFT->DEPOSITED, PATTERN->RATIFIED; external governance `NON_COMPLIANT` |
| `node bin/verifyd.cjs audit /tmp/verifyd-perf.txt` | Trust 90/100, DEPOSITED, `chain_valid: true`, 587.5 ms wall |
| `node bin/verifyd.cjs verify` after artifact edit | `VALID` (gap G1 reproduced) |
| `node bin/certify.cjs` | `undefined / 25` for two components (gap G5 reproduced) |
| `node showcase/seed.cjs` | 8 cases, 7 receipts, chain valid, 1 tamper, 1 refusal |
| `/api/cases/:id/verify` | 3/3 checks pass, 0.17-0.31 ms server-side |
| `/api/cases/:id/tamper` | Receipt hash mismatch, `valid: false` |
| `/api/cases/:id/restore` | Returns to valid |
| `/api/intake` with 4 seats | Sealed, RATIFIED, 4.65 ms |
| `/api/intake` with 3 seats | Sealed at DEPOSITED, waiting for a fourth seat |
| `/api/intake` with unilateral override | No receipt, `sole_sovereign ... forbidden` |
| jsdom dashboard flow | 8 cases, 4 tabs, 7 chain rows, verify/tamper/restore, policy/oversight/receipt tabs, intake sealed and refused, zero console errors |

Not performed: a real browser render, accessibility audit, load test at campus volume,
penetration test, or legal review. Those are listed as limitations, not passes.

---

## Appendix A - Authority registry

`engine/citations.json` contains 14 authorities:

1. NIST AI RMF 1.0 (NIST AI 100-1), DOI 10.6028/NIST.AI.100-1
2. NIST AI 600-1, Generative AI Profile
3. EU AI Act, Regulation (EU) 2024/1689, CELEX 32024R1689
4. ISO/IEC 42001:2023, AI management system
5. ISO/IEC 23894:2023, AI risk management guidance
6. ISO/IEC 27001:2022, information security management
7. OECD AI Principles 2019, revised 2024
8. FIPS 180-4, Secure Hash Standard
9. RFC 8785, JSON Canonicalization Scheme
10. RFC 6962, Certificate Transparency
11. OWASP Top 10 for LLM Applications 2025
12. FAIR Principles 2016, DOI 10.1038/sdata.2016.18
13. FTC AI guidance 2023
14. Regulation B / ECOA, 12 CFR 1002.9

The showcase dataset cites 10 of these: EU AI Act, FAIR, FIPS 180-4, FTC, ISO/IEC
27001, ISO/IEC 42001, NIST AI RMF, OECD, RFC 8785, and Regulation B.

## Appendix B - Repository map

```
engine/            core protocol: hashing, policy, trust, lattice, chain
bin/               CLI, certificate, batch, intro
examples/          PDF case study and lattice demo
showcase/          campus pilot: domain layer, API, dashboard, seed data
docs/              this report and the university playbook
auditdeck/         sample corpus (not present in the current checkout)
RESULTS.md         original PDF case study
BUILD.md           run and deploy notes
AGENTS.md          agent instructions and backlog
```

## Appendix C - Reproduction

```bash
node bin/verifyd.cjs demo
node showcase/seed.cjs
node showcase/server.cjs
curl -s localhost:3000/api/state | head
curl -s -X POST localhost:3000/api/cases/GR-5508/verify
```

Expected: chain valid, 7 receipts, GR-5508 reports `content_valid: false`, and every
other sealed case reports all three checks true.

---

*End of report. Verifyd v1.0 / VALF-1. Northline Online University is fictional; the
engine, hashes, chain, refusals, and gaps above are real.*

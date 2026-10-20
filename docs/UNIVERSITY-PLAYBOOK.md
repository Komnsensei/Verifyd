# Verifyd in an Online University

**A pilot blueprint, use-case catalogue, and impact case for AI decision receipts**

| | |
|---|---|
| Version | 1.0 |
| Date | 20 October 2026 |
| Setting | Northline Online University (fictional), a distance-first institution |
| Companion | [System report](SYSTEM-REPORT.md), [showcase](../showcase/README.md) |
| Status | Demonstration blueprint. Not legal advice. Not a certified compliance product. |

---

## 1. The setting

Northline Online is a fictional distance university used to make the demonstration
concrete. It has the properties that matter:

- 48,000 enrolled students, 92 percent part-time, 31 countries.
- No campus. Every interaction is mediated by software.
- 8 production AI agents: grading review, integrity screening, accommodation triage,
  tutoring feedback, proctoring, credit mapping, records publishing, accreditation
  evidence assembly.
- 24,000 AI-assisted decisions a term, ranging from a rubric recalculation to a
  misconduct referral.
- A 7-seat Independent Oversight Board that is supposed to review high-materiality
  decisions, but currently reviews screenshots and email threads.
- An accreditation review every seven years, assembled by hand.

The institution already has policies. What it lacks is a reliable way to show that the
policies were followed in a specific case, months later, to a student, an auditor, or a
court.

Verifyd supplies that missing artifact.

---

## 2. Why an online university is the right first vertical

Distance education is not a softer version of campus governance. It is a harder one.

1. **There is no hallway accountability.** A student cannot walk to the registrar's
   office. A faculty member cannot buttonhole the dean. The record has to stand alone.
2. **Decisions are already digital.** Grades, accommodations, integrity findings, and
   proctoring flags are events in software. Capturing evidence at decision time is
   cheaper here than in any paper-based institution.
3. **Agent sprawl is real.** A single term can involve eight vendors, twelve model
   versions, and dozens of prompt changes. Nobody can reconstruct which version touched
   which student.
4. **The student population is vulnerable to silent error.** Part-time, remote, often
   working adults. A denied accommodation or an unexamined integrity flag can end an
   enrolment before anyone notices.
5. **Regulators and accreditors ask the same question.** Show me how that decision was
   made, and show me it was not changed afterward.
6. **The volume makes manual evidence untenable.** At 24,000 decisions a term, even ten
   minutes of evidence assembly per decision is 4,000 hours.

The campus pilot demonstrates the full loop with eight synthetic cases. Every receipt is
produced by the real engine, not a mock.

---

## 3. The operating problem today

Four failure patterns recur in AI-assisted university administration.

### 3.1 Evidence is scattered

The agent log is in one vendor. The rubric is in an LMS. The appeal is in a ticket. The
board vote is in a meeting note. The final grade is in the SIS. Reconstructing one case
takes hours and depends on who remembers the context.

### 3.2 The agent sounds more certain than its evidence

A detector says 0.63. A triage model says "ineligible." A proctoring model says
"anomalous." The output is formatted as a conclusion, not as a claim with a confidence
and a source base. Staff either over-trust it or ignore it.

### 3.3 Oversight is asserted, not demonstrated

"Reviewed by the board" often means one administrator clicked approve. There is no
record of which seats voted, whether anyone dissented, or whether the same office signed
on behalf of four people. The policy says 4 of 7. The practice says trust us.

### 3.4 Records are easy to change

A gradebook export, a PDF, or a JSON file can be edited after the fact. Version history
may exist in one system, not across systems. The institution cannot prove that the record
it shows today is the record it sealed in week six.

Verifyd addresses all four at the artifact layer. It does not fix bad policy, biased
models, or a captured board. It makes those failures visible.

---

## 4. Regulatory and standards map

The table is a design orientation, not a legal opinion. Confirm obligations with counsel
and the institution's regulator.

| Instrument | What it asks for | Verifyd field that helps |
|---|---|---|
| EU AI Act, Annex III point 3 (education) | High-risk classification for systems used in admissions, learning outcome evaluation, or monitoring during tests | Case type, agent identity, model version, decision record |
| EU AI Act, Art. 12 | Automatic record-keeping over the system lifetime | Sealed receipt, append-only chain, timestamps |
| EU AI Act, Art. 13 | Transparency and instructions for deployers | Source anchors, confidence value and decay, agent purpose |
| EU AI Act, Art. 14 | Effective human oversight, ability to override | Ratification event, board attestations, override cases, dissent |
| EU AI Act, Art. 15 | Accuracy, robustness, cybersecurity | Content hash, policy checks, three-check verification |
| EU AI Act, Art. 50 | Transparency for AI interaction and synthetic content | AI-assisted disclosure flag, agent identity in receipt |
| EU AI Act, Art. 5(1)(f) | Prohibits emotion recognition in education and workplaces, with narrow exceptions | Case type and agent purpose expose proctoring emotion inference; Verifyd cannot make a prohibited practice lawful |
| GDPR Art. 22 | Rights around solely automated decisions with legal or significant effects | Human ratification, board review, contestability record |
| GDPR Art. 9 and 35 | Special-category data and impact assessment | Pseudonymous student refs, artifact access controls, DPIA input |
| FERPA (20 U.S.C. 1232g; 34 CFR Part 99) | Protection of education records and legitimate access | Pseudonymous identifiers, access-controlled artifacts, audit trail |
| ADA Title II / Section 504 | Accommodation decisions and effective access | Accommodation case record, human override evidence |
| Title VI and institutional non-discrimination policy | Consistent treatment across protected groups | Decision sampling, board composition, trust and dissent data |
| Accreditation standards (e.g. 34 CFR Part 602) | Evidence of institutional quality and control | Accreditation evidence case with per-item source hashes |
| NIST AI RMF 1.0 | Govern, map, measure, manage | Policy checks and citations, trust components |
| ISO/IEC 42001:2023 | AI management system, roles, operation | Separation of duties, board roles, documented operation |

### 4.1 Dates that matter

As of October 2026, following the Digital Omnibus amendments:

- **2 August 2026:** most AI Act rules and enforcement began, including Article 50
  transparency obligations.
- **2 December 2027:** high-risk obligations for standalone Annex III systems, including
  education, apply. The original date was 2 August 2026; the deferral is a runway, not a
  repeal.
- **2 August 2028:** high-risk AI embedded in regulated products under Annex I.

The practical consequence: an institution deploying AI in admissions, grading, or exam
monitoring has roughly fourteen months from this report to have conformity assessment,
technical documentation, human oversight, and record-keeping in place. Receipts are not
the whole of conformity, but they are the evidence layer that makes the rest auditable.

Primary sources for the timeline: the European Commission AI Act Service Desk timeline
(https://ai-act-service-desk.ec.europa.eu/en/ai-act/timeline/timeline-implementation-eu-ai-act)
and the Digital Omnibus analysis published in July 2026
(https://www.joneswalker.com/en/insights/blogs/ai-law-blog/yes-august-2-still-matters-the-eu-approved-a-high-risk-ai-delay-but-most-trans.html).
Confirm the Official Journal status before relying on the deferred date.

### 4.2 What Verifyd does not establish

A receipt is not a conformity assessment, a DPIA, a legal basis, or a fairness finding.
It records what happened. It does not prove the decision was lawful, accurate, or
non-discriminatory. Those require policy, testing, and human judgment.

---

## 5. Use-case catalogue

Each case below maps to a synthetic record in the showcase.

### 5.1 Grade appeal recalculation

**Scenario.** A student appeals a rubric application in CS 210. A grading assistant
recomputes the item and recommends a correction.

**Today.** The assistant's output is pasted into a ticket. The rubric version is
ambiguous. The instructor's countersignature is an email. Six months later, nobody can
prove which rubric was applied.

**What Verifyd records.** The rubric URI and version, the submission hash, the corrected
score, the assistant's confidence and decay, the policy check results, and four board
attestations, including the instructor and registrar.

**Oversight.** Four seats: standards chair, faculty senate, registrar, assessment
integrity. Quorum 4 of 7.

**What changes.** The appeal file becomes self-describing. A reviewer can verify it
offline in under a millisecond and see whether the rubric on file today is the rubric
that was used.

**Showcase case:** AP-2291, ratified, trust 87, content verified.

### 5.2 Academic integrity screening

**Scenario.** A detector flags an essay at 0.63 likelihood of generative drafting. The
committee must decide whether to investigate.

**Today.** The detector score circulates as if it were a finding. The student's statement
is in another system. The committee's reasoning is a meeting note. If the case is
challenged, the institution cannot show what evidence was actually weighed.

**What Verifyd records.** The detector model card, the revision history hash, the oral
defense record, the committee's finding, the dissent, and the disclosure to the student.
The trust score is 48/100 because the evidence base is thin. That is a feature: the
receipt does not launder a weak case into a strong one.

**Oversight.** Four seats, one dissent. Ratification is not unanimity.

**What changes.** The institution can defend a no-finding decision as rigorously as a
sanction. Due process becomes visible. The trust score gives the board a reason to ask
for more evidence before sealing.

**Showcase case:** AI-4471, ratified, trust 48, one dissent.

### 5.3 Accommodation triage

**Scenario.** An AI triage assistant recommends denying extra time because the clinical
letter does not match its eligibility template.

**Today.** The denial may be issued by whoever processes the queue. The fact that the
template was outdated is discovered only if the student appeals. The override, if it
happens, leaves no trace.

**What Verifyd records.** The assistant's recommendation, the human decision to approve,
the clinical basis (as a hash, not the letter itself), the Section 504 reference, and the
four seats that approved the reversal.

**Oversight.** Accessibility director, standards chair, registrar, student advocate.

**What changes.** Human override becomes evidence of oversight working, not an exception
to be hidden. The student can be shown the basis of the final decision without exposing
clinical detail.

**Showcase case:** AC-1180, ratified, trust 73, human override of an AI denial.

### 5.4 AI tutor feedback release

**Scenario.** A tutor agent generates formative feedback for 312 students. The teaching
team wants to release it with a disclosure banner.

**Today.** Release is a bulk action. Nobody can show that each item was reviewed or that
the banner was present. If a student receives a fabricated citation, the institution
cannot bound the blast radius.

**What Verifyd records.** The unit rubric, the review log hash, the number of items
removed, the disclosure banner, and the release decision. The record is sealed at
DEPOSITED because only three seats attested. It is not called RATIFIED.

**Oversight.** Three of seven. The gate holds until a fourth distinct seat signs.

**What changes.** The difference between "reviewed" and "ratified" becomes machine
readable. A dashboard can show which releases are blocked on quorum instead of discovering
it in an audit.

**Showcase case:** FB-0925, awaiting quorum, trust 82.

### 5.5 Proctoring misconduct referral

**Scenario.** A proctoring vendor flags background audio and gaze deviation and
recommends a misconduct referral. One office attempts to ratify on behalf of four board
seats.

**Today.** The referral is issued. The student is placed in a conduct process. The
"board approval" is a proxy signature that nobody examines until litigation.

**What Verifyd records.** The recommendation, the missing student statement, the proxy
attestations, and the refusal. No receipt is produced. The refusal reason is the audit
finding.

**Oversight.** The protocol rejects sole-sovereign ratification even when four seat ids
are supplied.

**What changes.** The institution cannot accidentally create a false quorum record. The
case returns to the integrity panel for real review. This is the single most important
demonstration for a provost: the system says no.

**Showcase case:** PR-3310, refused, `sole_sovereign ratification forbidden`.

### 5.6 Transfer credit and prior learning

**Scenario.** A credit mapping agent proposes six elective credits for a professional
certificate.

**Today.** The mapping is endorsed by a program director and later becomes a catalog
exception. The evidence for equivalence is lost.

**What Verifyd records.** The program map, certificate syllabus hash, prior-learning
policy, sponsor endorsement, and the provisional status. External anchoring and board
review are still pending, so the record cannot become RATIFIED.

**Oversight.** None yet. The status is PROVISIONAL.

**What changes.** Provisional decisions are visibly provisional. Staff cannot cite a
provisional mapping as if it were final, and a future reviewer can see exactly what was
missing.

**Showcase case:** TR-7742, provisional, trust 48.

### 5.7 Accreditation evidence

**Scenario.** The institution prepares its seven-year review. The AI assistant assembles
214 evidence items across assessment integrity, accommodation timeliness, and AI
governance.

**Today.** A binder is assembled by hand. By the time the reviewer samples it, the
underlying records have changed. Traceability is a spreadsheet.

**What Verifyd records.** A per-item source hash, control mapping to NIST AI RMF and
ISO/IEC 42001, the institution's self-study hash, and four attestations including an
external examiner who traced 20 sampled items.

**Oversight.** Quality assurance, faculty senate, accessibility, external examiner.

**What changes.** The accreditation packet becomes a verifiable index rather than a
narrative. An examiner can sample a claim and check it against a hash and a receipt.

**Showcase case:** AQ-8801, ratified, trust 87.

### 5.8 Advising and registration recommendations (next case type)

**Scenario.** An advising agent recommends a course sequence or flags a student as
at-risk. The student disagrees.

**Today.** The recommendation is a nudge in a portal with no record of the inputs or the
model version.

**What Verifyd would record.** The degree audit hash, the policy version, the agent
version, the confidence, and whether a human advisor reviewed it. Low-materiality
recommendations could be batched into a daily chain rather than sealed individually.

**Why it matters.** Advising is lower stakes per decision but higher volume. It is where
a campus learns whether receipt overhead is sustainable.

---

## 6. Four failure demonstrations

A pilot should be judged by what it refuses, not only by what it seals.

| Demo | What to show | Expected result | Why it matters |
|---|---|---|---|
| Unilateral override | One office tries to ratify on behalf of four seats | No receipt; `sole_sovereign ... forbidden` | Prevents fabricated quorum |
| Three-witness vote | Three seats attest | Receipt sealed at DEPOSITED only | Makes "pending oversight" operational |
| Skipped stage | Attempt DRAFT -> DEPOSITED | Transition rejected | Prevents shortcutting review |
| Post-seal edit | Change the artifact after sealing | Content hash mismatch | Catches silent record changes |

The first three are protocol rules. The fourth is an evidence practice: the verifier must
compare the artifact, not only the receipt. The shipped CLI does not do that yet; the
showcase does. A production pilot must adopt the three-check verifier.

---

## 7. The leverage: what changes when evidence is native

This section is the "how powerful can it be" argument. Numbers labelled **modeled** are
planning assumptions for a 48,000-student online institution, not measurements from a
live deployment. Engine timings are measured.

### 7.1 The core shift

Today, evidence is reconstructed after a dispute. With receipts, evidence is a
by-product of the decision. That changes four quantities:

1. **Time to evidence:** from hours or weeks to milliseconds.
2. **Cost per contested decision:** from staff archaeology to review.
3. **Scope of audit:** from a handful of sampled cases to every sealed case.
4. **Defensibility:** from "we believe the process was followed" to "here is the record
   and here is the hash."

### 7.2 Modeled operational impact

| Activity | Volume per term | Today | With receipts | Basis |
|---|---:|---|---|---|
| Grade appeals | 1,200 | 2-6 staff hours to reconstruct each | 10-20 minutes to review a verified file | Modeled |
| Integrity cases | 600 | 3-8 hours of evidence assembly | 1-2 hours, with dissent and sources already bound | Modeled |
| Accommodation requests | 4,000 | 20-40 minutes triage, evidence often re-requested | 10-15 minutes, with prior decisions and policy anchors visible | Modeled |
| Proctoring escalations | 450 | 2-5 hours, often based on vendor log alone | 45-90 minutes, with refusal or quorum evidence | Modeled |
| Accreditation evidence | 1 packet / 7 years | 6-12 weeks of staff time | Continuous capture, 1-2 weeks of sampling | Modeled |

Illustrative annual effect at these volumes: roughly **5,000 to 12,000 staff hours**
returned, almost all of it from evidence assembly rather than judgment. The point is not
headcount reduction. It is that staff can spend the recovered time on the review itself.

Label this a hypothesis to test in the pilot. Do not put it in a budget as a certainty.

### 7.3 What becomes newly possible

**Audit every high-materiality decision, not a sample.** At 0.06 ms per verification,
checking 24,000 receipts is under two seconds of compute. The constraint becomes human
attention, not machine time.

**Make quorum real.** A board that meets monthly cannot review thousands of decisions.
Receipts let the board delegate routine cases to a defined panel while retaining a
verifiable record of who attested. Proxy signatures are rejected at the protocol layer.

**Hold vendors to a machine-checkable contract.** The receipt records agent id, model
version, purpose, confidence, and evidence anchors. A vendor that cannot emit those
fields cannot be sealed. Procurement gains a concrete acceptance test.

**Give students a contestable record.** A student can receive a receipt reference and a
plain-language explanation, without receiving other students' data or clinical detail.
Contestability stops depending on institutional goodwill.

**Carry institutional memory across staff turnover.** When the registrar leaves, the
receipts remain. The next registrar can verify what happened without reconstructing
relationships.

**Federate without a central database.** Two institutions can exchange receipt hashes and
chain heads, proving that a transfer credit decision was sealed and unchanged, without
pooling student records. This is future work, but the artifact shape supports it.

**Price AI risk in procurement.** A vendor with signed receipts, resolved anchors, and
clean quorum evidence is cheaper to govern than one without. The trust score is a crude
signal, but the underlying evidence fields are concrete.

### 7.4 Throughput and storage

| Quantity | Value | Note |
|---|---:|---|
| Receipt size | 8.4 KB | Measured, includes citations |
| 24,000 receipts | ~0.20 GB | Uncompressed JSON |
| Verify time per receipt | 0.058 ms | Measured in-process |
| Chain verify, 7 receipts | 0.034 ms | Measured |
| Seal time per case | ~4.5 ms | Measured, 8 cases in 36.1 ms |
| Signing and timestamp (planned) | add 1-5 ms | Estimate, not implemented |

Storage is not the problem. Retention policy, access control, and artifact custody are.

### 7.5 The limits of the leverage

- A receipt cannot make a biased model fair.
- A receipt cannot stop four colluding witnesses from attesting a false decision.
- A receipt cannot replace a student's right to a human explanation.
- A receipt cannot prove authenticity without signatures and a published chain head.
- A receipt cannot satisfy a regulator on its own; it is evidence, not compliance.

The correct claim is narrow and strong: **the institution can prove what it decided, on
what evidence, with whose approval, and that the record has not changed since.**

---

## 8. Governance design for the pilot

### 8.1 Board composition

Seven seats, four required. A workable composition for an online institution:

| Seat | Role | Rationale |
|---|---|---|
| W-01 | Chair, Academic Standards | Owns policy interpretation |
| W-02 | University Registrar | Owns records and posting |
| W-03 | Faculty Senate, Curriculum | Owns academic judgment |
| W-04 | Director, Accessibility | Owns accommodation and access |
| W-05 | Student Advocate / Ombuds | Represents student interest |
| W-06 | Assessment Integrity Lead | Owns exam and integrity controls |
| W-07 | External Examiner | Independence from the institution |

### 8.2 Rules that must be explicit

1. **No proxy signatures.** A seat is a named person, not an office. The protocol checks
   distinct ids; the institution must check that the ids are backed by real keys.
2. **Recusal.** A seat with a conflict (e.g. the instructor in their own grade appeal)
   must be recorded as recused, not silently absent.
3. **Dissent is preserved.** A dissent is not a failure of quorum. It is evidence that
   review happened.
4. **The agent owner cannot be the sole reviewer.** Separation of duties is the point.
5. **The board can refuse.** A refusal produces no receipt, and that is a valid outcome.
6. **Appeals of board decisions go outside the board.** Otherwise the quorum becomes
   self-confirming.

### 8.3 Cryptographic roles (required for production)

The v1.0 showcase derives witness "signatures" as hashes. That is not a signature. In
production:

- Each seat holds an Ed25519 key in an authenticator or managed keystore.
- The receipt includes the key id and a signature over `this_hash` for each attestation.
- The institution publishes its public keys and a chain head at a stable URL.
- Key rotation and revocation are logged and linked to old receipts.
- The receipt service signs the sealed receipt; the signer is separate from the agent
  runtime.

Without these, the system proves integrity but not who approved what.

---

## 9. Data protection and student rights

### 9.1 Data minimization

- Use pseudonymous student references (`N-4471`), not names or emails, in the receipt.
- Do not put clinical letters, disability details, or full essays in the receipt. Store
  a hash and keep the artifact in an access-controlled repository.
- `content_summary` is the first 200 characters of the decision text. Draft it with
  pseudonyms and without sensitive detail.
- Board rationale should state the reasoning, not repeat personal data.

### 9.2 Retention and erasure

Receipts are immutable by design. That collides with erasure requests if a receipt
contains personal data. Resolve it before the pilot:

- keep personal data out of the receipt;
- keep the artifact in a store with a documented retention schedule;
- treat the receipt as a metadata record with a lawful basis and a retention period;
- document how a deletion request is handled when the hash remains but the artifact is
  removed (the hash no longer resolves to content, which is itself a record).

### 9.3 Student-facing rights

- **Notice:** tell students which decisions use AI, what the agent does, and that a
  receipt exists.
- **Access:** provide the receipt reference and a plain-language decision explanation.
- **Contest:** route appeals to a human who can see the artifact, not only the summary.
- **Correction:** if a decision is overturned, seal a new receipt that references the
  original. Do not rewrite history.
- **Non-retaliation:** the receipt must not become a surveillance record of who appealed.

### 9.4 Vendor and cross-border issues

The receipt may leave the institution. Keep it free of personal data so it can be shared
with an accreditor or another institution without a data transfer agreement. The artifact
stays under institutional control. Document subprocessors and residency in the DPIA.

---

## 10. Integration architecture

```
  LMS / SIS / appeal portal / proctoring vendor
                    |
                    v
          [agent gateway]
          - captures agent id, model version, prompt class
          - captures inputs by hash, not by copy
          - captures confidence and source anchors
                    |
                    v
          [receipt service]
          - policy checks + trust score + lattice walk
          - serializes chain appends
          - signs receipt (planned)
          - writes artifact reference, not artifact
                    |
        +-----------+------------+
        |                        |
        v                        v
  [WORM artifact store]    [receipt store + chain]
  retention lock            append-only, single writer
        |                        |
        +-----------+------------+
                    |
                    v
          [verification portal]
          - student view (pseudonymous)
          - board view (quorum, dissent)
          - auditor view (chain head, sampling)
          - public chain head (hash only)
```

### 10.1 Integration rules

- The gateway is the only path that can create a receipt. Manual overrides also go
  through it.
- The receipt service owns the chain. Agents cannot append directly.
- The artifact store is content-addressed and write-once. Deleting an artifact must be a
  governed, logged event.
- The chain head is published on a schedule (hourly or daily) to an external location.
- The verification portal reads receipts, not the chain head alone.

### 10.2 What can stay manual in the pilot

Board votes can be collected in a meeting and entered by a clerk, as long as each seat's
key signs. The pilot does not need full SSO integration on day one. It does need a real
chain, real artifacts, and a verifier that checks all three layers.

---

## 11. 90-day pilot plan

### Scope

- Two faculties, three decision types: grade appeal, accommodation, integrity screening.
- One term.
- Target: 300 sealed decisions with artifacts retained.
- One deliberate refusal drill and one tamper drill.

### Milestones

| Week | Milestone | Exit criterion |
|---:|---|---|
| 1-2 | Policy and data mapping | Three decision types mapped to policy anchors and board seats |
| 3-4 | Receipt service and artifact store | Chain persists across restarts; single writer; backup tested |
| 5 | Signing and key ceremony | Each seat has a key; a signed receipt verifies |
| 6 | Gateway integration | Real decisions produce receipts, not test fixtures |
| 7-8 | Board training | Four seats complete a live quorum; one dissent recorded |
| 9 | Student notice and portal | 20 students can retrieve and understand their receipt reference |
| 10 | Tamper and refusal drills | Artifact edit caught; unilateral attempt refused |
| 11 | Audit sample | 50 receipts sampled and verified by an internal auditor |
| 12 | Go/no-go | Metrics below met; residual risks accepted in writing |

### Pilot metrics

| Metric | Target | How measured |
|---|---:|---|
| In-scope decisions with a sealed receipt | 100% | Receipt count vs decision count |
| Receipts with retained artifact | 100% | Store join |
| Verification pass rate | 100% | Daily batch verify |
| Quorum violations | 0 | Protocol errors |
| Unilateral attempts | 0 accepted | Refusal log |
| Median evidence retrieval time | < 1 minute | Time from request to verified receipt |
| Appeal cycle time | 30% reduction | Case timestamps |
| Board review time per case | < 15 minutes | Board log |
| Student comprehension | 80% can explain the outcome | Short survey |
| Critical findings from audit sample | 0 unexplained | Auditor report |

### Red lines

Stop the pilot if any of these occur:

- a receipt is sealed without a retained artifact;
- a seat key is shared;
- the chain is rewritten or restored from an unsigned backup;
- a refusal is overridden outside the protocol;
- personal or clinical data appears in a receipt;
- the board rubber-stamps without reading.

---

## 12. Procurement questions for AI vendors

Ask these before renewing an agent contract. A vendor that cannot answer is a governance
liability.

1. What is the exact model and version used for this decision, and how is it recorded?
2. Does the system emit a confidence value with a documented calibration basis?
3. Does it emit source anchors (policy id, rubric version, document hash)?
4. Can it produce a per-decision evidence payload in a documented schema?
5. Can it prove the output was not modified between generation and delivery?
6. What human oversight does the system support, and can it record the reviewer identity?
7. How are model updates announced and versioned?
8. What logs are retained, for how long, and can the institution export them?
9. How does the vendor handle a contested decision and a data subject request?
10. Will the vendor accept a receipt-verification acceptance test in the contract?

---

## 13. How this becomes governance theater

The receipt is not self-executing. These failure modes are common and should be named in
the pilot charter.

| Failure | Symptom | Mitigation |
|---|---|---|
| Quorum capture | Same four people, same vote, every time | Rotate seats, record dissent, sample decisions |
| Receipt without artifact | Hash exists, source is gone | Retention lock, artifact join check |
| Signature theater | Hashes called signatures, no keys | Real Ed25519 keys, published public keys |
| Trust score gaming | Long documents with anchor words score high | Calibrate against outcomes; do not use as approval |
| Refusal laundering | Blocked case is re-entered until it passes | Immutable refusal log; board review of overrides |
| Board rubber stamp | 4/7 in under a minute | Review-time telemetry, dissent expectation |
| PII leakage | Clinical letters inside receipts | Data minimization review, automated scanning |
| Vendor opacity | Agent id is a product name, not a version | Contractual evidence fields, hash of model card |
| Metric fixation | "100% sealed" while outcomes worsen | Pair receipt metrics with appeal and fairness metrics |

The protocol makes some failures harder. It cannot make people govern well.

---

## 14. Five-minute demo script

For a provost, registrar, or regulator.

1. **Open the dashboard.** Eight cases, seven receipts, one refusal, one tampered record.
   State the premise: every AI decision that touches a student has a receipt.
2. **Open AP-2291.** Show the decision, the rubric anchor, the confidence decay, and the
   four seats. Click Verify: three checks pass in under a millisecond.
3. **Click Tamper.** Change a sealed trust field. The verdict flips to TAMPERED. Click
   Restore. Say: this is what a post-seal edit looks like.
4. **Open PR-3310.** Show the refused proctoring referral. Read the error:
   `sole_sovereign ratification forbidden by Independent Oversight`. Say: the system
   cannot produce a receipt for a fake quorum.
5. **Open FB-0925.** Show a case sealed at DEPOSITED with three of seven seats. Say: this
   is what "pending oversight" looks like when it is real.
6. **Open the Intake desk.** Seal a grade appeal with four seats. Then check the unilateral
   override and submit again. Show the refusal.
7. **Close on the ledger.** Seven linked hashes. Ask: which of these decisions could you
   reconstruct today without this artifact?

Do not lead with the trust score. Lead with the refusal and the tamper detection. Those
are the claims a skeptic will test.

---

## 15. Honest limitations for this setting

| Limitation | Consequence | Needed for production |
|---|---|---|
| No signatures | Receipts prove integrity, not authorship | Ed25519 signing, key ceremony, published keys |
| Phony witness signatures in showcase | Board identity is asserted, not proven | Seat keys, SSO, identity proofing |
| CLI verifies only the receipt hash | Artifact edits pass `verifyd verify` | Three-check verifier, tested |
| Chain not persisted by CLI | Batch receipts are all GENESIS | Receipt service with single writer |
| Trust score uncalibrated | Scores are not comparable across institutions | Calibration study against reviewed outcomes |
| No Merkle proofs | Cannot prove inclusion to an external party efficiently | RFC 6962 tree and proofs |
| No timestamp authority | Timestamps rely on the host clock | RFC 3161 or transparency log |
| FERPA/GDPR not implemented | Receipts could carry personal data | Data minimization, DPIA, retention policy |
| No accessibility audit | Student portal may exclude users | WCAG 2.2 AA review |
| Synthetic corpus | No evidence of field performance | 300-case pilot with real artifacts |

The showcase is a demonstration of the protocol and the operating model. It is not a
production system, and the report should never be presented as one.

---

## 16. Twelve-month roadmap for the institution

| Quarter | Objective | Deliverable |
|---|---|---|
| Q4 2026 | Pilot readiness | Signed receipts, three-check verifier, artifact store, board keys |
| Q1 2027 | Three-case pilot | 300 receipts, audit sample, student portal prototype |
| Q2 2027 | Expand to all high-materiality cases | Gateway integration, retention policy, vendor clauses |
| Q3 2027 | Accreditation and regulator readiness | Control mapping, evidence export, external examiner access |
| Q4 2027 | External verification and federation | Published chain head, cross-institution receipt exchange, independent audit |
| 2028 | Continuous assurance | Sampling automation, calibration study, public transparency report |

The December 2027 Annex III deadline is the forcing function. A pilot that starts in Q4
2026 has four quarters to move from demo to evidence.

---

## 17. Conclusion

The power of Verifyd in an online university is not that it seals a JSON file. It is that
it changes the default unit of accountability from a narrative to a verifiable record.

At 48,000 students and 24,000 AI-assisted decisions a term, the institution cannot review
everything by hand. It can, however, make every decision produce evidence, refuse
unilateral ratification, preserve dissent, and let any authorized reviewer re-prove the
record in milliseconds. That is a meaningful shift in what a distance institution can
promise a student and demonstrate to a regulator.

The demonstration is deliberately honest about what is missing. Signatures, key
management, artifact custody, and calibration are not optional for production. They are
the next build, and the playbook names them.

Northline Online is fictional. The eight cases are synthetic. The engine, the hashes, the
chain, the refusals, and the limits are real.

---

## Appendix A - Case to control mapping

| Case | Primary control question | Receipt evidence |
|---|---|---|
| AP-2291 grade appeal | Was the correct rubric applied, and who approved the change? | Rubric URI, submission hash, four attestations |
| AI-4471 integrity | Was the finding based on evidence, and was dissent preserved? | Detector model card, revision hash, one dissent, trust 48 |
| AC-1180 accommodation | Did a human review the AI denial and apply the law? | AI recommendation, override, Section 504 anchor, four seats |
| FB-0925 feedback release | Was AI-generated feedback reviewed before release? | Rubric, review log, disclosure banner, quorum pending |
| PR-3310 proctoring | Was a high-stakes referral validly authorized? | Refusal, no receipt, sole-sovereign error |
| TR-7742 credit transfer | Is the credit award final or provisional? | PROVISIONAL status, missing external anchor |
| GR-5508 grade posting | Is the posted record the sealed record? | Content hash mismatch, tamper detection |
| AQ-8801 accreditation | Can the institution trace every claim to a source? | 214 item hashes, control mapping, external examiner |

## Appendix B - Glossary

| Term | Meaning |
|---|---|
| VALF-1 | Verifyd's receipt format: SHA-256 over canonical JSON with chain linkage |
| Content hash | SHA-256 of the extracted document or decision text |
| Session hash | SHA-256 binding auditor, agent, and start time |
| this_hash | Hash of the receipt itself |
| prev_hash | Hash of the previous receipt, or GENESIS |
| DEPOSITED | Externally anchored but not ratified |
| RATIFIED | At least 4 of 7 distinct board attestations |
| Sole sovereign | A single party attempting to ratify alone; forbidden |
| Trust score | Heuristic evidence-quality score, 0-100, not a probability |
| Quorum | Four distinct seats required for ratification |

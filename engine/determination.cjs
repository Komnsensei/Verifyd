// Verifyd compliance determinations - verifyd-determination-v1
// Zero dependencies. Reuses engine/signing.cjs (Ed25519 + keyring).
//
// NOT LEGAL ADVICE
//   A determination is an engineering record of what was checked, against which
//   repo-cited requirements, with which evidence, and who reviewed it. It does
//   not decide whether a law applies, does not interpret a legal text, and does
//   not establish compliance. That takes a qualified reviewer in the relevant
//   jurisdiction, using material this tool does not hold.
//
// TWO JUDGEMENTS, KEPT APART
//   machine: what this tool can check from the receipt bytes. Each requirement
//            carries its predicate, the evidence paths and values it inspected,
//            and one of satisfied / partial / not_satisfied / no_evidence.
//   review:  what a named human with a role concluded, in their own words, and
//            signed with their key. The reviewer may disagree with the machine;
//            both judgements are recorded and neither erases the other.
//
//   A final `compliant` requires ALL of: the determination is signed by a key
//   the verifier trusts, bound to this exact receipt, unexpired, under a known
//   jurisdiction and regime, no required applicability fact missing, unresolved
//   or invalid, every citation traced to engine/citations.json, every machine
//   requirement satisfied, a named reviewer with a role, and that reviewer's
//   conclusion of `compliant`. Any other combination is `incomplete`,
//   `undetermined`, `non_compliant` or a validity failure - never `compliant`.
//
// BINDING
//   `receipt_digest` is SHA-256 of Signing.signingPayload(receipt): the same
//   bytes the receipt signature and timestamp cover. The determination signs a
//   domain-separated payload containing that digest, so it cannot be moved to
//   another receipt or edited after signing.
//
// SOURCES
//   Requirements come from engine/legal-regimes.json, whose every source ref
//   must exist in engine/citations.json and whose locator must match a cited
//   ground. A reviewer may add requirements; a ref missing from the repo is
//   recorded as `source_unverified` and forces `incomplete`. Nothing here
//   invents a statute, article, case or locator.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const Signing = require('./signing.cjs');

const CITATIONS = JSON.parse(fs.readFileSync(path.join(__dirname, 'citations.json'), 'utf8'));
const REGISTRY = JSON.parse(fs.readFileSync(path.join(__dirname, 'legal-regimes.json'), 'utf8'));

const SCHEME = 'verifyd-determination-v1';
const DOMAIN = 'verifyd-determination-v1\n';
const ARTIFACT_TYPE = 'compliance-determination';
const NOTICE = 'Engineering record of evidence and review status. NOT LEGAL ADVICE. ' +
  'It does not decide applicability, interpret law, or establish compliance without a qualified reviewer in the relevant jurisdiction.';

const FINAL = {
  COMPLIANT: 'compliant',
  NON_COMPLIANT: 'non_compliant',
  INCOMPLETE: 'incomplete',
  UNDETERMINED: 'undetermined',
  UNSIGNED: 'unsigned',
  TAMPERED: 'tampered',
  EXPIRED: 'expired',
  WRONG_RECEIPT: 'wrong_receipt',
  UNTRUSTED_KEY: 'untrusted_reviewer_key',
  EVIDENCE_MISMATCH: 'evidence_mismatch',
};

const PREDICATES = {
  human_ratification_recorded: true,
  source_anchors_present: true,
  content_hash_present: true,
};

function sha256hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function receiptDigest(envelope) {
  return sha256hex(Signing.signingPayload(envelope));
}

function copy(value) {
  return JSON.parse(JSON.stringify(value));
}

// ----- Registry validation -----

function groundsFor(principle) {
  const entry = CITATIONS.policy_check_citations[principle];
  return entry ? entry.grounds : [];
}

function validateRegistry(registry) {
  registry = registry || REGISTRY;
  const problems = [];
  for (const [code, jurisdiction] of Object.entries(registry.jurisdictions || {})) {
    for (const ref of jurisdiction.basis || []) {
      if (!CITATIONS.standards[ref]) problems.push('jurisdiction ' + code + ' cites unknown standard ' + ref);
    }
    for (const id of jurisdiction.regimes || []) {
      const regime = (registry.regimes || {})[id];
      if (!regime) problems.push('jurisdiction ' + code + ' names unknown regime ' + id);
      else if (regime.jurisdiction !== code) problems.push('regime ' + id + ' declares jurisdiction ' + regime.jurisdiction + ', indexed under ' + code);
    }
  }
  for (const [id, regime] of Object.entries(registry.regimes || {})) {
    if (!(registry.jurisdictions || {})[regime.jurisdiction]) problems.push('regime ' + id + ' names unknown jurisdiction ' + regime.jurisdiction);
    for (const requirement of regime.requirements || []) {
      const source = requirement.source || {};
      if (!CITATIONS.standards[source.ref]) {
        problems.push('regime ' + id + ' requirement ' + requirement.id + ' cites unknown standard ' + source.ref);
        continue;
      }
      const predicate = String(requirement.predicate || '');
      if (predicate.startsWith('policy_check_passed:')) {
        const principle = predicate.split(':')[1];
        if (!CITATIONS.policy_check_citations[principle]) {
          problems.push('regime ' + id + ' requirement ' + requirement.id + ' names unknown policy check ' + principle);
          continue;
        }
        const matched = groundsFor(principle).some(g => g.ref === source.ref && g.locator === source.locator);
        if (!matched) {
          problems.push('regime ' + id + ' requirement ' + requirement.id + ' locator is not a cited ground for ' + principle + ': ' + source.locator);
        }
      } else if (!PREDICATES[predicate]) {
        problems.push('regime ' + id + ' requirement ' + requirement.id + ' uses unknown predicate ' + predicate);
      }
    }
  }
  if (problems.length) {
    const error = new Error('legal-regimes.json failed validation:\n  ' + problems.join('\n  '));
    error.code = 'LEGAL_REGISTRY_INVALID';
    throw error;
  }
  return true;
}

validateRegistry();

// ----- Source tracing -----

function traceSource(ref, locator, principle) {
  const standard = CITATIONS.standards[ref];
  if (!standard) {
    return {
      ref: ref || null,
      locator: locator || null,
      title: null,
      url: null,
      verification: 'unverified',
      note: 'reference is not present in engine/citations.json; it needs reviewer-supplied authoritative material before it can support a determination',
    };
  }
  const base = {
    ref,
    locator: locator || null,
    title: standard.title || ref,
    url: standard.url || null,
  };
  if (!locator) return Object.assign(base, { verification: 'repo-ref' });

  const matched = principle
    ? groundsFor(principle).some(g => g.ref === ref && g.locator === locator)
    : Object.values(CITATIONS.policy_check_citations).some(e =>
      (e.grounds || []).some(g => g.ref === ref && g.locator === locator));

  return Object.assign(base, matched
    ? { verification: 'repo-ref+repo-locator' }
    : { verification: 'repo-ref', note: 'locator was supplied by the reviewer and is not matched in the repo citations' });
}

// ----- Machine checks -----

function policyCheck(envelope, principle) {
  const checks = envelope && envelope.receipt && Array.isArray(envelope.receipt.policy_checks)
    ? envelope.receipt.policy_checks
    : [];
  return checks.find(c => c && c.principle === principle) || null;
}

function evaluateRequirement(requirement, envelope) {
  const evidence = [];
  let status = 'no_evidence';
  let detail = null;
  const receipt = envelope && envelope.receipt ? envelope.receipt : {};

  if (!requirement.predicate) {
    detail = 'reviewer-supplied requirement has no machine check; it needs reviewer assessment, so this tool cannot satisfy it';
    evidence.push({ path: '(none)', value: 'no machine predicate' });
  } else if (requirement.predicate.startsWith('policy_check_passed:')) {
    const principle = requirement.predicate.split(':')[1];
    const check = policyCheck(envelope, principle);
    if (!check) {
      detail = 'receipt carries no policy check named ' + principle;
      evidence.push({ path: 'receipt.policy_checks', value: 'missing: ' + principle });
    } else {
      evidence.push({ path: 'receipt.policy_checks[' + principle + '].result', value: check.result || null });
      evidence.push({ path: 'receipt.policy_checks[' + principle + '].detail', value: check.detail || null });
      if (check.result === 'pass') status = 'satisfied';
      else if (check.result === 'warn') status = 'partial';
      else if (check.result === 'fail') status = 'not_satisfied';
      else status = 'no_evidence';
    }
  } else if (requirement.predicate === 'human_ratification_recorded') {
    const ratification = receipt.ratification || {};
    const human = ratification.ratified_by_human || {};
    const agent = ratification.ratified_by_agent || {};
    evidence.push({ path: 'receipt.ratification.ratified_by_human.human_id', value: human.human_id || null });
    evidence.push({ path: 'receipt.ratification.ratified_by_agent.agent_id', value: agent.agent_id || null });
    if (!human.human_id || !agent.agent_id) {
      status = 'no_evidence';
      detail = 'human or agent ratification party is missing';
    } else if (human.human_id === agent.agent_id) {
      status = 'not_satisfied';
      detail = 'human and agent identifiers are identical (one-party record)';
    } else {
      status = 'satisfied';
    }
  } else if (requirement.predicate === 'source_anchors_present') {
    const outputs = Array.isArray(receipt.outputs) ? receipt.outputs : [];
    const anchored = outputs.filter(o => Array.isArray(o.source_anchors) && o.source_anchors.length > 0 &&
      o.source_anchors.every(a => a && a.uri && a.span_hash));
    evidence.push({ path: 'receipt.outputs[].source_anchors', value: anchored.length + '/' + outputs.length + ' outputs anchored' });
    if (outputs.length === 0) status = 'no_evidence';
    else if (anchored.length === outputs.length) status = 'satisfied';
    else status = 'not_satisfied';
  } else if (requirement.predicate === 'content_hash_present') {
    const outputs = Array.isArray(receipt.outputs) ? receipt.outputs : [];
    const hashed = outputs.filter(o => o && typeof o.content_hash === 'string' && /^[0-9a-f]{64}$/.test(o.content_hash));
    evidence.push({ path: 'receipt.outputs[].content_hash', value: hashed.length + '/' + outputs.length + ' outputs hashed' });
    if (outputs.length === 0) status = 'no_evidence';
    else if (hashed.length === outputs.length) status = 'satisfied';
    else status = 'not_satisfied';
  } else {
    detail = 'no machine evaluator exists for predicate ' + requirement.predicate;
  }

  return {
    id: requirement.id,
    statement: requirement.statement,
    predicate: requirement.predicate,
    source: requirement.source,
    status,
    detail,
    evidence,
    checked_by: 'machine',
  };
}

function machineCheck(envelope, requirements) {
  const results = requirements.map(r => evaluateRequirement(r, envelope));
  const summary = { total: results.length, satisfied: 0, partial: 0, not_satisfied: 0, no_evidence: 0 };
  for (const r of results) summary[r.status] += 1;

  let result = 'satisfied';
  if (summary.not_satisfied > 0) result = 'not_satisfied';
  else if (summary.partial > 0 || summary.no_evidence > 0 || summary.total === 0) result = 'incomplete';

  return {
    checked_at: new Date().toISOString(),
    result,
    summary,
    requirements: results,
  };
}

// ----- Requirement and fact assembly -----

function resolveJurisdiction(code, registry) {
  registry = registry || REGISTRY;
  if (!code) {
    return { code: null, known: false, status: 'undeclared', label: null, basis: [] };
  }
  const entry = registry.jurisdictions[code];
  if (!entry) {
    return { code, known: false, status: 'unknown', label: null, basis: [], note: 'not indexed in engine/legal-regimes.json; no requirements can be checked' };
  }
  return {
    code,
    known: true,
    status: 'indexed',
    label: entry.label,
    basis: (entry.basis || []).map(ref => {
      const s = CITATIONS.standards[ref] || {};
      return { ref, title: s.title || ref, url: s.url || null };
    }),
  };
}

function resolveRegime(jurisdictionCode, regimeId, registry) {
  registry = registry || REGISTRY;
  const entry = regimeId ? registry.regimes[regimeId] : null;
  if (!entry) {
    return {
      id: regimeId || null,
      known: false,
      label: null,
      jurisdiction: jurisdictionCode || null,
      requirements: [],
      required_facts: [],
      coverage_note: null,
      note: regimeId ? 'regime is not indexed in engine/legal-regimes.json' : 'no regime declared',
    };
  }
  const matches = entry.jurisdiction === jurisdictionCode;
  return {
    id: regimeId,
    known: matches,
    label: entry.label,
    jurisdiction: entry.jurisdiction,
    coverage_note: entry.coverage_note || null,
    requirements: matches ? copy(entry.requirements || []) : [],
    required_facts: matches ? copy(entry.required_facts || []) : [],
    note: matches ? null : 'regime is indexed under ' + entry.jurisdiction + ', not ' + jurisdictionCode,
  };
}

function buildFacts(requiredFacts, supplied) {
  const facts = [];
  const missing = [];
  const unresolved = [];
  const invalid = [];
  for (const definition of requiredFacts) {
    const value = supplied ? supplied[definition.id] : undefined;
    const record = {
      id: definition.id,
      question: definition.question,
      allowed: definition.allowed || [],
      value: value === undefined ? null : value,
      source: value === undefined ? null : 'reviewer-supplied',
      status: 'missing',
    };
    if (value === undefined) {
      missing.push(definition.id);
    } else if (definition.allowed && definition.allowed.length && !definition.allowed.includes(value)) {
      record.status = 'invalid';
      invalid.push(definition.id);
    } else if (value === 'unknown' || value === 'unsure') {
      record.status = 'unresolved';
      unresolved.push(definition.id);
    } else {
      record.status = 'supplied';
    }
    facts.push(record);
  }
  const extra = Object.keys(supplied || {}).filter(id => !requiredFacts.some(f => f.id === id));
  return {
    facts,
    missing,
    unresolved,
    invalid,
    extra: extra.map(id => ({ id, value: supplied[id], source: 'reviewer-supplied', status: 'extra' })),
  };
}

function parseExtraRequirements(list) {
  return (list || []).map(item => {
    if (typeof item === 'string') {
      const parts = item.split('|');
      return { id: parts[0], statement: parts[1] || '', ref: parts[2] || null, locator: parts[3] || null };
    }
    return item;
  }).map(item => ({
    id: String(item.id || '').trim(),
    statement: String(item.statement || '').trim(),
    predicate: null,
    source: traceSource(item.ref, item.locator, null),
    reviewer_supplied: true,
  })).filter(item => item.id && item.statement);
}

function buildRequirements(regime, extra) {
  const requirements = regime.requirements.map(r => ({
    id: r.id,
    statement: r.statement,
    predicate: r.predicate,
    reviewer_supplied: false,
    source: traceSource(r.source.ref, r.source.locator,
      r.predicate.startsWith('policy_check_passed:') ? r.predicate.split(':')[1] : null),
  }));
  for (const item of extra) {
    requirements.push({
      id: item.id,
      statement: item.statement,
      predicate: item.predicate,
      reviewer_supplied: true,
      source: item.source,
    });
  }
  return requirements;
}

// ----- Status -----

function computeStatus(payload, ctx) {
  ctx = ctx || {};
  const reasons = [];
  const review = payload.review || {};
  const reviewer = review.reviewer || {};
  const facts = payload.applicability || {};
  const machine = payload.machine || {};

  if (!ctx.signed) return { value: FINAL.UNSIGNED, reasons: ['determination has no signature'] };
  if (!ctx.signatureValid) return { value: FINAL.TAMPERED, reasons: ['signature does not match the determination bytes'] };
  if (ctx.binding === 'mismatch') return { value: FINAL.WRONG_RECEIPT, reasons: ['determination is bound to a different receipt'] };
  if (ctx.binding === 'unchecked') reasons.push('receipt_binding_unchecked: pass --receipt');
  if (ctx.expired) return { value: FINAL.EXPIRED, reasons: ['determination expired at ' + payload.expires_at] };
  if (ctx.evidenceMismatch) return { value: FINAL.EVIDENCE_MISMATCH, reasons: ['stored machine evidence does not match a fresh check of the receipt'] };

  const jurisdiction = payload.jurisdiction || {};
  if (!jurisdiction.code) return { value: FINAL.UNDETERMINED, reasons: ['jurisdiction_undeclared'] };
  if (!jurisdiction.known) return { value: FINAL.UNDETERMINED, reasons: ['jurisdiction_unknown: ' + jurisdiction.code + ' is not indexed; no requirements can be checked'] };

  const regime = payload.regime || {};
  if (!regime.id) return { value: FINAL.UNDETERMINED, reasons: ['regime_undeclared'] };
  if (!regime.known) return { value: FINAL.UNDETERMINED, reasons: ['regime_unknown: ' + regime.id] };

  for (const id of facts.missing || []) reasons.push('applicability_fact_missing: ' + id);
  for (const id of facts.invalid || []) reasons.push('applicability_fact_invalid: ' + id);
  for (const id of facts.unresolved || []) reasons.push('applicability_unresolved: ' + id);

  const unverified = (machine.requirements || []).filter(r => r.source && r.source.verification === 'unverified');
  for (const r of unverified) reasons.push('source_unverified: ' + r.id + ' (' + (r.source.ref || 'no ref') + ')');

  if (reasons.length) return { value: FINAL.INCOMPLETE, reasons };

  if (machine.result === 'not_satisfied') {
    const failed = (machine.requirements || []).filter(r => r.status === 'not_satisfied').map(r => r.id);
    return { value: FINAL.NON_COMPLIANT, reasons: ['machine_requirement_not_satisfied: ' + failed.join(', ')] };
  }
  if (machine.result !== 'satisfied') {
    const outstanding = (machine.requirements || []).filter(r => r.status !== 'satisfied')
      .map(r => r.id + '=' + r.status);
    return {
      value: FINAL.INCOMPLETE,
      reasons: ['machine_evidence_incomplete' + (outstanding.length ? ': ' + outstanding.join(', ') : '')],
    };
  }

  if (!reviewer.name) return { value: FINAL.INCOMPLETE, reasons: ['reviewer_identity_missing'] };
  if (!reviewer.role) return { value: FINAL.INCOMPLETE, reasons: ['reviewer_role_missing'] };
  if (!review.reviewed_at) return { value: FINAL.INCOMPLETE, reasons: ['review_time_missing'] };
  if (ctx.futureReview) return { value: FINAL.INCOMPLETE, reasons: ['review_time_in_future'] };

  if (review.conclusion === 'non_compliant') return { value: FINAL.NON_COMPLIANT, reasons: ['reviewer_conclusion_non_compliant'] };
  if (review.conclusion === 'insufficient_evidence') return { value: FINAL.INCOMPLETE, reasons: ['reviewer_conclusion_insufficient_evidence'] };
  if (review.conclusion !== 'compliant') return { value: FINAL.INCOMPLETE, reasons: ['reviewer_conclusion_missing'] };
  if (ctx.binding === 'unchecked') return { value: FINAL.INCOMPLETE, reasons: ['receipt_binding_unchecked'] };

  return { value: FINAL.COMPLIANT, reasons: [] };
}

function isExpired(payload, now) {
  if (!payload.expires_at) return false;
  const at = Date.parse(payload.expires_at);
  if (Number.isNaN(at)) return true;
  return at <= (now || Date.now());
}

function reviewInFuture(payload, now) {
  const at = Date.parse((payload.review && payload.review.reviewed_at) || '');
  if (Number.isNaN(at)) return false;
  return at > (now || Date.now()) + 5 * 60 * 1000;
}

// ----- Build and sign -----

function build(envelope, opts) {
  opts = opts || {};
  if (!envelope || typeof envelope !== 'object' || !envelope.receipt) {
    const e = new Error('determination needs a signed document receipt');
    e.code = 'MALFORMED_RECEIPT';
    throw e;
  }

  const jurisdiction = resolveJurisdiction(opts.jurisdiction);
  const regime = resolveRegime(opts.jurisdiction, opts.regime);
  const extra = parseExtraRequirements(opts.requirements);
  const requirements = regime.known ? buildRequirements(regime, extra) : extra;
  const machine = machineCheck(envelope, requirements);
  const applicability = buildFacts(regime.required_facts || [], opts.facts || {});

  const reviewer = opts.reviewer || {};
  const review = {
    reviewer: {
      name: reviewer.name || null,
      role: reviewer.role || null,
      organization: reviewer.organization || null,
    },
    conclusion: opts.conclusion || null,
    rationale: opts.rationale || '',
    reviewed_at: opts.reviewedAt || new Date().toISOString(),
  };

  const payload = {
    valf_version: '1.0',
    artifact_type: ARTIFACT_TYPE,
    scheme: SCHEME,
    notice: NOTICE,
    receipt_digest: receiptDigest(envelope),
    receipt_id: envelope.receipt.receipt_id || null,
    document_sha256: envelope.document ? envelope.document.sha256 || null : null,
    jurisdiction,
    regime: {
      id: regime.id,
      known: regime.known,
      label: regime.label,
      jurisdiction: regime.jurisdiction,
      coverage_note: regime.coverage_note,
      note: regime.note,
    },
    applicability,
    machine,
    review,
    expires_at: opts.expiresAt || null,
  };

  payload.status = computeStatus(payload, { signed: true, signatureValid: true, binding: 'valid', expired: isExpired(payload) });
  return payload;
}

function create(envelope, opts) {
  opts = opts || {};
  if (!opts.dir) {
    const e = new Error('determination create needs a keyring dir for the reviewer key');
    e.code = 'NO_REVIEWER_KEYRING';
    throw e;
  }

  // The reviewer key and the receipt signer's key may live in different
  // keyrings. Verification of the receipt uses the receipt keyring when given.
  const receiptDir = opts.receiptKeyring ? path.resolve(opts.receiptKeyring) : opts.dir;
  const receiptCheck = Signing.open(envelope, { dir: receiptDir });
  if (!receiptCheck.ok) {
    const e = new Error('receipt does not verify (' + receiptCheck.code + '); refusing to determine over unverified bytes');
    e.code = 'RECEIPT_INVALID';
    throw e;
  }

  const payload = build(envelope, opts);
  const sealed = Signing.seal(payload, {
    dir: opts.dir,
    keyId: opts.keyId || undefined,
    domain: DOMAIN,
  });
  return sealed;
}

// ----- Verify -----

function verify(determination, opts) {
  opts = opts || {};
  const dir = opts.dir ? path.resolve(opts.dir) : null;
  const now = opts.now || Date.now();
  const result = {
    ok: false,
    status: null,
    reasons: [],
    signature: { present: false, valid: false, key_id: null, code: null },
    binding: 'unchecked',
    expired: false,
    stored_status: determination && determination.status ? determination.status.value || null : null,
    reviewer: null,
    machine: null,
  };

  if (!determination || typeof determination !== 'object') {
    result.status = FINAL.INCOMPLETE;
    result.reasons.push('determination is not a JSON object');
    return result;
  }
  if (determination.scheme !== SCHEME) {
    result.status = FINAL.INCOMPLETE;
    result.reasons.push('unsupported determination scheme: ' + determination.scheme);
    return result;
  }

  const signature = determination.signature;
  result.signature.present = !!(signature && signature.value);
  result.reviewer = determination.review ? determination.review.reviewer || null : null;

  if (!result.signature.present) {
    result.signature.code = 'UNSIGNED';
    result.status = FINAL.UNSIGNED;
    result.reasons.push('determination has no signature');
    return result;
  }

  if (!dir) {
    result.status = FINAL.INCOMPLETE;
    result.reasons.push('no reviewer keyring supplied (--reviewer-keyring or --keyring)');
    return result;
  }

  const opened = Signing.open(determination, { dir, domain: DOMAIN });
  result.signature.key_id = opened.key_id || null;
  result.signature.code = opened.code;
  result.signature.valid = !!opened.ok;
  if (!opened.ok) {
    result.status = opened.code === 'UNTRUSTED_KEY' || opened.code === 'PUBLIC_KEY_MISMATCH'
      ? FINAL.UNTRUSTED_KEY
      : FINAL.TAMPERED;
    result.reasons.push(opened.message);
    return result;
  }

  if (opts.receipt) {
    const expected = receiptDigest(opts.receipt);
    result.binding = expected === determination.receipt_digest ? 'valid' : 'mismatch';
    if (result.binding === 'mismatch') {
      result.status = FINAL.WRONG_RECEIPT;
      result.reasons.push('determination.receipt_digest does not match this receipt');
      return result;
    }

    const fresh = machineCheck(opts.receipt, determination.machine.requirements.map(r => ({
      id: r.id,
      statement: r.statement,
      predicate: r.predicate,
      source: r.source,
    })));
    result.machine = fresh;
    const stored = determination.machine.requirements || [];
    const mismatch = fresh.requirements.some((r, i) => {
      const old = stored[i];
      return !old || old.id !== r.id || old.status !== r.status;
    });
    if (mismatch || fresh.result !== determination.machine.result) {
      result.evidenceMismatch = true;
      result.reasons.push('stored machine evidence differs from a fresh check of the receipt');
    }
  } else {
    result.reasons.push('receipt not supplied; binding not checked');
  }

  result.expired = isExpired(determination, now);
  const computed = computeStatus(determination, {
    signed: true,
    signatureValid: true,
    binding: result.binding,
    expired: result.expired,
    futureReview: reviewInFuture(determination, now),
    evidenceMismatch: result.evidenceMismatch,
  });

  result.status = computed.value;
  result.reasons = result.reasons.concat(computed.reasons);
  result.ok = computed.value === FINAL.COMPLIANT && result.binding === 'valid';
  return result;
}

function describe(result) {
  const lines = [];
  lines.push('Status:       ' + String(result.status || 'incomplete').toUpperCase());
  if (result.reviewer) {
    lines.push('Reviewer:     ' + (result.reviewer.name || '(unnamed)') +
      (result.reviewer.role ? ' (' + result.reviewer.role + ')' : ' (no role recorded)'));
  }
  if (result.signature) {
    lines.push('Signature:    ' + (result.signature.valid ? 'VALID' : (result.signature.code || 'UNSIGNED')));
  }
  lines.push('Binding:      ' + result.binding.toUpperCase());
  lines.push('Expired:      ' + (result.expired ? 'YES' : 'NO'));
  if (result.machine) {
    lines.push('Machine:      ' + result.machine.result + ' (' + result.machine.summary.satisfied + '/' + result.machine.summary.total + ' satisfied)');
  }
  if (result.reasons.length) {
    lines.push('Reasons:');
    for (const reason of result.reasons) lines.push('  - ' + reason);
  }
  return lines.join('\n');
}

module.exports = {
  SCHEME,
  DOMAIN,
  ARTIFACT_TYPE,
  NOTICE,
  FINAL,
  REGISTRY,
  CITATIONS,
  validateRegistry,
  receiptDigest,
  traceSource,
  evaluateRequirement,
  machineCheck,
  resolveJurisdiction,
  resolveRegime,
  build,
  create,
  verify,
  describe,
  computeStatus,
  isExpired,
};

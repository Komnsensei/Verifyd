// Verifyd Policy Engine — VALF-1 Section 4
// Each compliance principle is grounded in citable authority (NIST AI RMF,
// EU AI Act, ISO/IEC 42001, FIPS 180-4, RFC 8785, etc.). See citations.json.

const fs = require('fs');
const path = require('path');

const CITATIONS = JSON.parse(fs.readFileSync(path.join(__dirname, 'citations.json'), 'utf8'));

function citationsFor(principleKey) {
  const entry = CITATIONS.policy_check_citations[principleKey];
  if (!entry) return [];
  return entry.grounds.map(g => ({
    standard: g.ref,
    title: (CITATIONS.standards[g.ref] && CITATIONS.standards[g.ref].title) || g.ref,
    id: (CITATIONS.standards[g.ref] && (CITATIONS.standards[g.ref].id || CITATIONS.standards[g.ref].doi)) || null,
    url: (CITATIONS.standards[g.ref] && CITATIONS.standards[g.ref].url) || null,
    locator: g.locator,
  }));
}

function principleStatement(principleKey) {
  return (CITATIONS.policy_check_citations[principleKey] || {}).principle || '';
}

function checkNoCoercion(session, output) {
  const c = (output.content_summary || '').toLowerCase();
  const pressure = ['you must','you have to','no choice','comply or','do this now','immediately or'];
  const disclosure = ['disclosed','for your awareness','you may decline','this is informational','advisory only'];
  const hasPressure = pressure.some(m => c.includes(m));
  const hasDisclosure = disclosure.some(m => c.includes(m));
  const result = (hasPressure && !hasDisclosure) ? 'warn' : 'pass';
  const detail = (hasPressure && !hasDisclosure)
    ? 'imperative-pressure pattern without disclosure framing'
    : 'no pressure pattern detected';
  return {
    principle: 'no_coercion',
    statement: principleStatement('no_coercion'),
    result, detail,
    citations: citationsFor('no_coercion'),
    checked_at: new Date().toISOString(),
  };
}

function checkTransparency(session, output) {
  const hasAnchors = Array.isArray(output.source_anchors) && output.source_anchors.length > 0;
  const hasConfidence = output.confidence && typeof output.confidence.value === 'number';
  let result = 'pass', detail = 'source anchors and confidence both declared';
  if (!hasAnchors && !hasConfidence) { result = 'fail'; detail = 'output declares neither source anchors nor confidence'; }
  else if (!hasAnchors) { result = 'warn'; detail = 'output declares confidence but no source anchors'; }
  else if (!hasConfidence) { result = 'warn'; detail = 'output has source anchors but no confidence score'; }
  return {
    principle: 'transparency',
    statement: principleStatement('transparency'),
    result, detail,
    citations: citationsFor('transparency'),
    checked_at: new Date().toISOString(),
  };
}

function checkAuditTrail(session, output) {
  const required = [
    [session && session.session_hash, 'session.session_hash'],
    [output && output.content_hash, 'output.content_hash'],
    [output && output.produced_at, 'output.produced_at'],
  ];
  const missing = required.filter(([v]) => !v).map(([,n]) => n);
  return {
    principle: 'audit_trail',
    statement: principleStatement('audit_trail'),
    result: missing.length ? 'fail' : 'pass',
    detail: missing.length ? 'missing required fields: ' + missing.join(', ') : 'all required ratification fields present',
    citations: citationsFor('audit_trail'),
    checked_at: new Date().toISOString(),
  };
}

function checkIndependentOversight(session, output, ratification) {
  if (!ratification) {
    return {
      principle: 'independent_oversight',
      statement: principleStatement('independent_oversight'),
      result: 'warn', detail: 'no ratification event provided',
      citations: citationsFor('independent_oversight'),
      checked_at: new Date().toISOString(),
    };
  }
  const human = ratification.ratified_by_human && ratification.ratified_by_human.human_id;
  const agent = ratification.ratified_by_agent && ratification.ratified_by_agent.agent_id;
  let result = 'pass', detail = 'two distinct parties ratified';
  if (!human || !agent) { result = 'fail'; detail = 'ratification missing one of the two required parties'; }
  else if (human === agent) { result = 'fail'; detail = 'self-ratification detected (human and agent identifiers match)'; }
  return {
    principle: 'independent_oversight',
    statement: principleStatement('independent_oversight'),
    result, detail,
    citations: citationsFor('independent_oversight'),
    checked_at: new Date().toISOString(),
  };
}

function run(session, output, ratification) {
  const checks = [
    checkNoCoercion(session, output),
    checkTransparency(session, output),
    checkAuditTrail(session, output),
  ];
  if (ratification !== undefined) checks.push(checkIndependentOversight(session, output, ratification));
  return checks;
}

function passed(checks) {
  return checks.every(c => c.result === 'pass' || c.result === 'warn');
}

module.exports = { run, passed, checkNoCoercion, checkTransparency, checkAuditTrail, checkIndependentOversight, CITATIONS };

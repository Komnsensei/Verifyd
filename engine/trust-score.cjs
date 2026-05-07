// Verifyd Trust Score Calculator - v1.1 calibrated
// Chain validity != content trust. Local receipt != external provenance.
// v1.1 fix: removed hardcoded constants. All components now vary per document.

function scoreSourceQuality(output) {
  const anchors = output.source_anchors || [];

  const external = anchors.filter(a =>
    a.uri &&
    !String(a.uri).startsWith('file://') &&
    a.span_hash
  );

  const resolved = external.filter(a =>
    a.resolved_metadata &&
    (a.resolved_metadata.title || a.resolved_metadata.publisher || a.resolved_metadata.source)
  );

  if (external.length === 0) return 4;       // local file only
  if (resolved.length === 0) return 12;      // external-looking but unresolved
  return Math.min(25, 15 + Math.round((resolved.length / external.length) * 10));
}

function scoreContentRichness(output) {
  // Replaces hardcoded calibration_freshness.
  // Measures actual document substance — varies per file.
  const e = output.evidence || {};
  let score = 0;

  // Word count tiers
  const words = e.word_count || 0;
  if (words >= 3000) score += 10;
  else if (words >= 1000) score += 7;
  else if (words >= 300) score += 4;
  else if (words >= 50) score += 2;
  else score += 0;

  // Has resolved external metadata (arXiv/DOI came back with real title)
  if (e.has_resolved_external_metadata) score += 8;

  // Has provenance language in the document
  if (e.has_provenance_language) score += 4;

  // Has proof/verification language
  if (e.has_proof_language) score += 3;

  return Math.min(25, score);
}

function scorePolicyCompliance(checks) {
  if (!checks || checks.length === 0) return 0;

  let total = 0;
  for (const c of checks) {
    if (c.result === 'pass') total += 25 / checks.length;
    else if (c.result === 'warn') total += 10 / checks.length;
    else if (c.result === 'fail') total += 0;
  }

  return Math.round(total);
}

function scoreDocumentStructure(output) {
  // Replaces hardcoded agent_history.
  // Measures document structure quality — varies per file.
  const e = output.evidence || {};
  let score = 0;

  // Has external anchor (arXiv or DOI found in text)
  if (e.has_external_anchor) score += 8;

  // Has both provenance AND proof language (well-structured academic doc)
  if (e.has_provenance_language && e.has_proof_language) score += 5;

  // Has source anchors array with entries
  const anchors = output.source_anchors || [];
  if (anchors.length >= 2) score += 4;
  else if (anchors.length === 1) score += 2;

  // Has content summary
  if (output.content_summary && output.content_summary.length > 50) score += 3;

  return Math.min(25, score);
}

function evidencePenalty(output) {
  const e = output.evidence || {};
  let penalty = 0;

  if (e.word_count && e.word_count < 20) penalty += 6;
  if (!e.has_external_anchor) penalty += 10;
  if (!e.has_provenance_language) penalty += 8;
  if (!e.has_proof_language) penalty += 6;
  if (e.has_adversarial_language) penalty += 25;
  if (e.has_self_ratification_language) penalty += 20;
  if (e.has_secret_pattern) penalty += 35;

  return penalty;
}

function compute(session, output, policy_checks) {
  const components = {
    source_quality:      scoreSourceQuality(output),
    content_richness:    scoreContentRichness(output),
    policy_compliance:   scorePolicyCompliance(policy_checks),
    document_structure:  scoreDocumentStructure(output),
  };

  const raw =
    components.source_quality +
    components.content_richness +
    components.policy_compliance +
    components.document_structure;

  const penalty = evidencePenalty(output);
  const value = Math.max(0, Math.min(100, raw - penalty));

  return {
    value,
    components,
    penalty,
    computed_at: new Date().toISOString(),
  };
}

module.exports = { compute };

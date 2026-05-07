// Verifyd Trust Score Calculator - calibrated patch
// Chain validity != content trust. Local receipt != external provenance.

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

function scoreCalibrationFreshness(output) {
  const conf = output.confidence;
  if (!conf || typeof conf.value !== 'number') return 3;

  // CLI-generated confidence is bookkeeping, not evidence calibration.
  if (conf.generated_by === 'verifyd-cli-default') return 6;

  const scoredAt = new Date(conf.scored_at).getTime();
  if (!Number.isFinite(scoredAt)) return 3;

  const ageDays = Math.max(0, (Date.now() - scoredAt) / 86400000);
  const halfLife = conf.decay_half_life_days || 30;
  const decay = Math.pow(0.5, ageDays / halfLife);
  return Math.round(25 * decay);
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

function scoreAgentHistory(session) {
  // No external reputation store wired yet. Do not grant 20 by default.
  if (!session || !session.agent_id) return 0;
  return 5;
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
    source_quality: scoreSourceQuality(output),
    calibration_freshness: scoreCalibrationFreshness(output),
    policy_compliance: scorePolicyCompliance(policy_checks),
    agent_history: scoreAgentHistory(session),
  };

  const raw =
    components.source_quality +
    components.calibration_freshness +
    components.policy_compliance +
    components.agent_history;

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

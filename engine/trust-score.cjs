// Verifyd Trust Score Calculator - VALF-1 Section 5
// 0-100 score across four 0-25 components.

function scoreSourceQuality(output) {
  const anchors = output.source_anchors || [];
  if (anchors.length === 0) return 5;
  const resolvable = anchors.filter(a => a.uri && a.span_hash).length;
  return Math.min(25, Math.round((resolvable / anchors.length) * 25));
}

function scoreCalibrationFreshness(output) {
  const conf = output.confidence;
  if (!conf || typeof conf.value !== 'number') return 5;
  const scoredAt = new Date(conf.scored_at).getTime();
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
    else if (c.result === 'warn') total += 12.5 / checks.length;
  }
  return Math.round(total);
}

function scoreAgentHistory() {
  return 20; // Placeholder. Production: lookup agent_id reputation store.
}

function compute(session, output, policy_checks) {
  const components = {
    source_quality: scoreSourceQuality(output),
    calibration_freshness: scoreCalibrationFreshness(output),
    policy_compliance: scorePolicyCompliance(policy_checks),
    agent_history: scoreAgentHistory(session, output),
  };
  return {
    value: components.source_quality + components.calibration_freshness + components.policy_compliance + components.agent_history,
    components,
    computed_at: new Date().toISOString(),
  };
}

module.exports = { compute };

'use strict';

const { loadConfig, secretEnvNames, secretPresence } = require('./config.cjs');
const { SentinelRunner } = require('./runner.cjs');
const { createHealthServer } = require('./health.cjs');
const { createLogger } = require('./logging.cjs');
const { VERSION } = require('./version.cjs');

// Builds a ready-to-run service. Config errors are returned (not thrown) so the
// CLI can print every problem at once and exit non-zero.
async function createService(opts) {
  opts = opts || {};
  const loaded = opts.config ? { config: opts.config, errors: [], warnings: [], path: opts.configPath || null } : loadConfig(opts.configPath, { baseDir: opts.baseDir });
  if (loaded.errors.length > 0) {
    return { ok: false, errors: loaded.errors, warnings: loaded.warnings, path: loaded.path };
  }
  const config = loaded.config;
  const logger = opts.logger || createLogger({ level: config.service.log_level });
  const runner = new SentinelRunner(Object.assign({ config, logger }, opts.runner || {}));
  await runner.init();

  let health = null;
  if (opts.withHealth !== false && config.diagnostics.port) {
    health = createHealthServer({
      snapshot: () => runner.snapshot(),
      bind: config.diagnostics.bind,
      port: config.diagnostics.port,
      tokenEnv: config.diagnostics.token_env,
      recentLimit: config.diagnostics.recent_alerts
    });
    try {
      await health.start();
    } catch (e) {
      const err = new Error('diagnostics endpoint failed to bind ' + config.diagnostics.bind + ':' + config.diagnostics.port + ' (' + (e.code || e.message) + ')');
      err.code = 'HEALTH_BIND_FAILED';
      await runner.stop('health bind failure');
      throw err;
    }
    runner.healthServer = health;
  }

  const envNames = secretEnvNames(config);
  const presence = secretPresence(process.env, envNames);

  return {
    ok: true,
    version: VERSION,
    config,
    configPath: loaded.path,
    warnings: loaded.warnings,
    runner,
    health,
    logger,
    secret_env_names: envNames,
    secret_env_present: presence,
    snapshot: () => runner.snapshot(),
    async stop(reason) {
      await runner.stop(reason);
    }
  };
}

module.exports = { createService, VERSION };

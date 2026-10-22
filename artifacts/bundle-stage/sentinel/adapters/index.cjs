'use strict';

const { HttpAccessAdapter } = require('./http-access.cjs');
const { HostListenersAdapter } = require('./host-listeners.cjs');
const { HostProcessAdapter } = require('./host-process.cjs');
const { HostSecurityAdapter } = require('./host-security.cjs');
const { HostDefenderAdapter } = require('./host-defender.cjs');
const { HostFilesAdapter } = require('./host-files.cjs');
const { DbAuditAdapter } = require('./db-audit.cjs');
const { ProxyLogAdapter } = require('./proxy-log.cjs');
const { WebflowAdapter } = require('./webflow.cjs');
const { SelfHealthAdapter } = require('./self-health.cjs');

const ADAPTER_CLASSES = [
  HttpAccessAdapter,
  HostListenersAdapter,
  HostProcessAdapter,
  HostSecurityAdapter,
  HostDefenderAdapter,
  HostFilesAdapter,
  DbAuditAdapter,
  ProxyLogAdapter,
  WebflowAdapter,
  SelfHealthAdapter
];

const CONFIG_KEY = {
  'http.access': 'http_access',
  'host.listeners': 'host_listeners',
  'host.process': 'host_process',
  'host.security': 'host_security',
  'host.defender': 'host_defender',
  'host.files': 'host_files',
  'db.audit': 'db_audit',
  'proxy.access': 'proxy_log',
  'webflow.logs': 'webflow',
  'self.health': 'self_health'
};

function createAdapters(config, deps) {
  return ADAPTER_CLASSES.map((Cls) => {
    const probe = new Cls({ config: {}, deps: deps || {} });
    const key = CONFIG_KEY[probe.id];
    return new Cls({ config: config.adapters[key] || {}, deps: deps || {} });
  });
}

module.exports = { createAdapters, ADAPTER_CLASSES, CONFIG_KEY };

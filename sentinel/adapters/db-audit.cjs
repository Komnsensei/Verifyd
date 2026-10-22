'use strict';

const fs = require('fs');
const { BaseAdapter } = require('./base.cjs');
const { JsonlTailer } = require('../tailer.cjs');
const { outcomeForStatus } = require('../event.cjs');

// Database coverage is log-based only. This adapter reads an operator-exported
// audit log (JSONL) written by the database or a managed provider. There is no
// live driver connection, because connecting to production databases would need
// credentials this service deliberately does not hold.
class DbAuditAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'db.audit',
      name: 'Database audit log (exported)',
      category: 'C: Data stores and external services',
      capabilities: [
        'bulk reads measured by rows_returned / rows_read',
        'privilege changes (GRANT/REVOKE/role changes) when exported',
        'database authentication failures when exported',
        'principal, source host, statement type and target table'
      ],
      limitations: [
        'no live database connection: requires pgAudit / MySQL audit / provider audit log exported to JSONL',
        'if database auditing is not enabled upstream, this adapter sees nothing and must report NOT CONFIGURED',
        'does not inspect query result contents'
      ],
      source: { type: 'file', format: 'jsonl' }
    }, opts));
    this.tailer = null;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (!this.config.path) {
      return this.markNotConfigured('adapters.db_audit.path is empty; export database audit logs to JSONL and set the path');
    }
    try {
      const st = fs.statSync(this.config.path);
      if (!st.isFile()) return this.markUnavailable('configured db audit path is not a regular file');
      this.source = { path: this.config.path, bytes: st.size };
      this.tailer = new JsonlTailer({ file: this.config.path, maxLines: 1000, cursor: this.cursor });
      return this.markActive('tailing exported database audit log', { path: this.config.path });
    } catch (e) {
      return this.markUnavailable('db audit log not readable: ' + (e.code || e.message));
    }
  }

  async poll() {
    if (this.status !== 'ACTIVE') {
      if (this.config.path && fs.existsSync(this.config.path)) await this.init();
      if (this.status !== 'ACTIVE') return { events: [] };
    }
    const res = this.tailer.poll();
    this.cursor = res.cursor;
    const events = [];
    for (const line of res.lines) {
      if (!line.parsed) continue;
      const raw = line.parsed;
      const status = raw.status != null ? Number(raw.status) : null;
      const ts = raw.ts || raw.timestamp || new Date().toISOString();
      events.push({
        adapter: this.id,
        kind: 'db.audit',
        ts,
        hint: 'db:' + (raw.database || raw.db || '') + ':' + (raw.event_id || '') + ':' + ts + ':' + (raw.user || ''),
        outcome: raw.outcome || (status != null ? outcomeForStatus(status) : (raw.error ? 'failure' : 'success')),
        source: {
          principal: raw.user || raw.principal || raw.db_user || null,
          ip: raw.ip || raw.client_addr || raw.source_ip || null,
          principal_type: 'database'
        },
        host: { hostname: raw.host || raw.server || null },
        facts: {
          database: raw.database || raw.db || null,
          action: raw.action || raw.command || null,
          statement_type: raw.statement_type || raw.statement || null,
          table: raw.table || raw.object || null,
          rows_read: raw.rows_read != null ? Number(raw.rows_read) : (raw.rows != null ? Number(raw.rows) : null),
          rows_affected: raw.rows_affected != null ? Number(raw.rows_affected) : null,
          privilege_change: raw.privilege_change === true || raw.action === 'GRANT' || raw.action === 'REVOKE',
          privilege: raw.privilege || null,
          target: raw.target || null,
          query_hash: raw.query_hash || null,
          provider: raw.provider || null,
          source: 'exported-audit-log'
        }
      });
    }
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { DbAuditAdapter };

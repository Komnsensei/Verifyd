'use strict';

const fs = require('fs');
const { BaseAdapter } = require('./base.cjs');
const { JsonlTailer } = require('../tailer.cjs');

const PRIVILEGE_RE = /(CreateUser|CreateLogin|CreateRole|AttachUserPolicy|AttachRolePolicy|AttachGroupPolicy|PutUserPolicy|PutRolePolicy|PutGroupPolicy|AddUserToGroup|CreateAccessKey|UpdateAssumeRolePolicy|SetIamPolicy|SetIAMPolicy|roles\/iam|CreateServiceAccount|CreateServiceAccountKey|AddMember|SetIamPolicy)/i;

function first() {
  for (let i = 0; i < arguments.length; i++) {
    const v = arguments[i];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return null;
}

function mapAws(raw) {
  const identity = raw.userIdentity || {};
  const action = raw.eventName || raw.eventType || null;
  const ip = raw.sourceIPAddress || null;
  const failed = Boolean(raw.errorCode || raw.errorMessage);
  return {
    ts: raw.eventTime || raw.eventVersion || null,
    principal: identity.arn || identity.userName || identity.principalId || identity.sessionContext?.sessionIssuer?.userName || null,
    ip,
    action,
    outcome: failed ? 'failure' : 'success',
    resource: first(raw.requestParameters?.bucketName, raw.requestParameters?.functionName, raw.requestParameters?.roleName, raw.resources?.[0]?.ARN, raw.resources?.[0]?.ARN),
    facts: {
      provider: 'aws-cloudtrail',
      event_source: raw.eventSource || null,
      event_name: action,
      region: raw.awsRegion || null,
      account: identity.accountId || null,
      error_code: raw.errorCode || null,
      read_only: raw.readOnly === true,
      request_id: raw.requestID || null,
      user_agent: raw.userAgent || null,
      mfa: identity.sessionContext?.attributes?.mfaAuthenticated || null,
      privilege_change: PRIVILEGE_RE.test(String(action || ''))
    }
  };
}

function mapAzure(raw) {
  const props = raw.properties || {};
  const action = raw.operationName || raw.operationNameValue || null;
  const status = raw.resultType || props.statusCode || null;
  const failed = status && !/succeeded|accepted|started/i.test(String(status));
  return {
    ts: raw.time || raw.eventTimestamp || null,
    principal: raw.caller || props.caller || null,
    ip: raw.httpRequest?.clientIpAddress || props.clientIpAddress || raw.callerIpAddress || null,
    action,
    outcome: failed ? 'failure' : 'success',
    resource: raw.resourceId || props.resourceId || null,
    facts: {
      provider: 'azure-activity',
      category: raw.category?.value || raw.category || null,
      result_type: status,
      correlation_id: raw.correlationId || props.correlationId || null,
      tenant: raw.tenantId || null,
      subscription: raw.subscriptionId || null,
      privilege_change: PRIVILEGE_RE.test(String(action || '')) || /roleAssignments\/write|roleDefinitions\/write/i.test(String(action || ''))
    }
  };
}

function mapGcp(raw) {
  const payload = raw.protoPayload || {};
  const auth = payload.authenticationInfo || {};
  const meta = payload.requestMetadata || {};
  const action = payload.methodName || raw.methodName || null;
  const status = payload.status || {};
  const failed = status.code != null && Number(status.code) !== 0;
  const resource = raw.resource || {};
  return {
    ts: raw.timestamp || null,
    principal: auth.principalEmail || auth.principalSubject || null,
    ip: meta.callerIp || meta.callerSuppliedUserAgent ? meta.callerIp || null : null,
    action,
    outcome: failed ? 'failure' : 'success',
    resource: resource.name || payload.resourceName || null,
    facts: {
      provider: 'gcp-audit',
      service: payload.serviceName || null,
      method: action,
      resource_type: resource.type || null,
      project: resource.labels?.project_id || null,
      status_code: status.code != null ? Number(status.code) : null,
      status_message: status.message || null,
      caller_supplied_user_agent: meta.callerSuppliedUserAgent || null,
      privilege_change: PRIVILEGE_RE.test(String(action || '')) || /SetIamPolicy|setIamPolicy/i.test(String(action || ''))
    }
  };
}

function mapGeneric(raw) {
  return {
    ts: raw.ts || raw.timestamp || raw.time || null,
    principal: raw.principal || raw.user || raw.actor || null,
    ip: raw.ip || raw.source_ip || raw.client_ip || null,
    action: raw.action || raw.event || raw.operation || null,
    outcome: raw.outcome || (raw.error ? 'failure' : 'success'),
    resource: raw.resource || raw.target || null,
    facts: Object.assign({ provider: 'generic-cloud-audit' }, raw.facts || {}, {
      privilege_change: raw.privilege_change === true || PRIVILEGE_RE.test(String(raw.action || raw.event || ''))
    })
  };
}

function mapCloudRecord(raw, provider) {
  if (provider === 'aws-cloudtrail') return mapAws(raw);
  if (provider === 'azure-activity') return mapAzure(raw);
  if (provider === 'gcp-audit') return mapGcp(raw);
  return mapGeneric(raw);
}

class CloudAuditAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'cloud.audit',
      name: 'Cloud control-plane audit log (exported)',
      category: 'C: Data stores and external services',
      capabilities: [
        'AWS CloudTrail, Azure Activity and GCP Audit Log records exported to JSONL',
        'principal, source address, action, resource and error outcome',
        'privilege and IAM policy changes are scored'
      ],
      limitations: [
        'requires the provider audit export to be delivered to a readable file; this adapter holds no cloud credentials',
        'export latency and retention are controlled by the provider',
        'JSONL only: one audit record per line, or a single CloudTrail Records object per line'
      ],
      source: { type: 'file', format: 'jsonl' }
    }, opts));
    this.provider = this.config.provider || 'generic';
    this.tailer = null;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (!this.config.path) {
      return this.markNotConfigured('adapters.cloud_audit.path is empty; export CloudTrail/Azure/GCP audit logs to JSONL');
    }
    try {
      const st = fs.statSync(this.config.path);
      if (!st.isFile()) return this.markUnavailable('configured cloud audit path is not a regular file');
      this.source = { path: this.config.path, provider: this.provider, bytes: st.size };
      this.tailer = new JsonlTailer({ file: this.config.path, maxLines: 1000, maxLineBytes: 1024 * 1024, cursor: this.cursor });
      return this.markActive('tailing ' + this.provider + ' audit log', { path: this.config.path, provider: this.provider });
    } catch (e) {
      return this.markUnavailable('cloud audit log not readable: ' + (e.code || e.message));
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
      const records = Array.isArray(line.parsed.Records) ? line.parsed.Records
        : Array.isArray(line.parsed.records) ? line.parsed.records
          : [line.parsed];
      for (const raw of records) {
        try {
          const item = mapCloudRecord(raw, this.provider);
          if (!item.action && !item.principal) continue;
          events.push({
            adapter: this.id,
            kind: 'cloud.audit',
            ts: item.ts || new Date().toISOString(),
            hint: 'cloud:' + this.provider + ':' + (item.action || '') + ':' + (item.principal || '') + ':' + (item.ts || ''),
            outcome: item.outcome === 'failure' ? 'failure' : 'success',
            source: { principal: item.principal, ip: item.ip, principal_type: 'cloud' },
            host: { hostname: this.deps.hostname || null },
            facts: Object.assign({}, item.facts, { action: item.action, resource: item.resource })
          });
        } catch (e) { /* skip malformed record */ }
      }
    }
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { CloudAuditAdapter, mapCloudRecord, mapAws, mapAzure, mapGcp, PRIVILEGE_RE };

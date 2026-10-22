'use strict';

const fs = require('fs');
const { BaseAdapter } = require('./base.cjs');
const { JsonlTailer } = require('../tailer.cjs');

// Network visibility comes from a sensor that already wrote flow/DNS/TLS
// metadata to JSONL. This adapter deliberately does not open a raw socket or
// a driver: that would need kernel code and would still not see TLS plaintext.
function asInt(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function first() {
  for (let i = 0; i < arguments.length; i++) {
    const v = arguments[i];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return null;
}

function zeekType(raw, fallback) {
  return raw._path || raw.path || raw.log_type || fallback || null;
}

function mapZeek(raw, fallbackType) {
  const type = zeekType(raw, fallbackType);
  const orig = first(raw['id.orig_h'], raw.id_orig_h, raw.src_ip, raw.src);
  const resp = first(raw['id.resp_h'], raw.id_resp_h, raw.dest_ip, raw.dst);
  const origPort = asInt(first(raw['id.orig_p'], raw.id_orig_p, raw.src_port));
  const respPort = asInt(first(raw['id.resp_p'], raw.id_resp_p, raw.dest_port));
  const baseFacts = {
    source: 'zeek-' + (type || 'unknown'),
    log_type: type,
    orig_h: orig,
    resp_h: resp,
    orig_p: origPort,
    resp_p: respPort,
    proto: raw.proto || null,
    uid: raw.uid || null
  };

  if (type === 'dns') {
    return {
      ts: raw.ts,
      kind: 'network.dns',
      outcome: 'observed',
      hint: 'zeek:dns:' + (raw.uid || raw.ts) + ':' + (raw.query || ''),
      source: { ip: orig, port: origPort, principal: null, principal_type: 'network' },
      host: { hostname: raw.host || null },
      facts: Object.assign(baseFacts, {
        query_name: raw.query || null,
        query_type: raw.qtype || raw.qtype_name || null,
        rcode: raw.rcode || raw.rcode_name || null,
        answers: raw.answers || null,
        authoritative: raw.AA === true || raw.aa === true,
        rejected: raw.rejected === true
      })
    };
  }

  if (type === 'ssl' || type === 'tls') {
    return {
      ts: raw.ts,
      kind: 'network.tls',
      outcome: 'observed',
      hint: 'zeek:tls:' + (raw.uid || raw.ts) + ':' + (raw.server_name || ''),
      source: { ip: orig, port: origPort, principal: null, principal_type: 'network' },
      host: { hostname: raw.server_name || null },
      facts: Object.assign(baseFacts, {
        server_name: raw.server_name || raw.sni || null,
        version: raw.version || null,
        cipher: raw.cipher || null,
        curve: raw.curve || null,
        server_cert_subject: raw.subject || null,
        server_cert_issuer: raw.issuer || null,
        validation_status: raw.validation_status || null,
        established: raw.established === true,
        resumed: raw.resumed === true,
        encrypted_bytes: asInt(first(raw.resp_bytes, raw.orig_bytes))
      })
    };
  }

  if (type === 'http') {
    return {
      ts: raw.ts,
      kind: 'network.http',
      outcome: 'observed',
      hint: 'zeek:http:' + (raw.uid || raw.ts) + ':' + (raw.method || '') + ':' + (raw.host || '') + (raw.uri || ''),
      source: { ip: orig, port: origPort, principal: raw.user || null, principal_type: 'network' },
      host: { hostname: raw.host || null },
      request: { method: raw.method || null, path: raw.uri || null, bytes_in: asInt(raw.request_body_len) },
      response: { status: asInt(raw.status_code), bytes_out: asInt(raw.response_body_len) },
      facts: Object.assign(baseFacts, {
        host: raw.host || null,
        uri: raw.uri || null,
        referrer: raw.referrer || null,
        user_agent: raw.user_agent || null,
        mime_type: raw.mime_type || null,
        request_body_len: asInt(raw.request_body_len),
        response_body_len: asInt(raw.response_body_len),
        transparent: raw.trans_depth != null
      })
    };
  }

  if (type === 'conn') {
    return {
      ts: raw.ts,
      kind: 'network.flow',
      outcome: 'observed',
      hint: 'zeek:conn:' + (raw.uid || raw.ts) + ':' + (orig || '') + ':' + (respPort || ''),
      source: { ip: orig, port: origPort, principal: null, principal_type: 'network' },
      host: { hostname: raw.host || null, port: respPort, address: resp },
      facts: Object.assign(baseFacts, {
        service: raw.service || null,
        duration_ms: raw.duration != null ? Math.round(Number(raw.duration) * 1000) : null,
        bytes_out: asInt(raw.orig_bytes),
        bytes_in: asInt(raw.resp_bytes),
        orig_packets: asInt(raw.orig_pkts),
        resp_packets: asInt(raw.resp_pkts),
        conn_state: raw.conn_state || null,
        history: raw.history || null,
        missed_bytes: asInt(raw.missed_bytes),
        tunnel: raw.tunnel_parents && String(raw.tunnel_parents).length ? String(raw.tunnel_parents).slice(0, 512) : null
      })
    };
  }

  return null;
}

function mapSuricata(raw) {
  const type = raw.event_type || 'flow';
  const src = raw.src_ip || (raw.flow && raw.flow.src_ip) || null;
  const dst = raw.dest_ip || (raw.flow && raw.flow.dest_ip) || null;
  const srcPort = asInt(raw.src_port);
  const dstPort = asInt(raw.dest_port);
  const baseFacts = {
    source: 'suricata-' + type,
    log_type: type,
    src_ip: src,
    dest_ip: dst,
    src_port: srcPort,
    dest_port: dstPort,
    proto: raw.proto || null,
    flow_id: raw.flow_id != null ? String(raw.flow_id) : null,
    app_proto: raw.app_proto || null
  };

  if (type === 'dns') {
    const dns = raw.dns || {};
    return {
      ts: raw.timestamp,
      kind: 'network.dns',
      outcome: 'observed',
      hint: 'suricata:dns:' + (raw.flow_id || raw.timestamp) + ':' + (dns.rrname || ''),
      source: { ip: src, port: srcPort, principal: null, principal_type: 'network' },
      host: { hostname: null },
      facts: Object.assign(baseFacts, {
        query_name: dns.rrname || null,
        query_type: dns.rrtype || null,
        rcode: dns.rcode || null,
        answers: dns.answers || null
      })
    };
  }

  if (type === 'tls') {
    const tls = raw.tls || {};
    return {
      ts: raw.timestamp,
      kind: 'network.tls',
      outcome: 'observed',
      hint: 'suricata:tls:' + (raw.flow_id || raw.timestamp) + ':' + (tls.sni || ''),
      source: { ip: src, port: srcPort, principal: null, principal_type: 'network' },
      host: { hostname: tls.sni || null },
      facts: Object.assign(baseFacts, {
        server_name: tls.sni || null,
        version: tls.version || null,
        cipher: tls.cipher || null,
        subject: tls.subject || null,
        issuer: tls.issuerdn || tls.issuer || null,
        fingerprint: tls.fingerprint || null,
        validation_status: tls.status || null,
        encrypted_bytes: asInt(first(raw.flow && raw.flow.bytes_toserver, null))
      })
    };
  }

  if (type === 'http') {
    const http = raw.http || {};
    return {
      ts: raw.timestamp,
      kind: 'network.http',
      outcome: 'observed',
      hint: 'suricata:http:' + (raw.flow_id || raw.timestamp) + ':' + (http.http_method || '') + ':' + (http.hostname || '') + (http.url || ''),
      source: { ip: src, port: srcPort, principal: http.http_user || null, principal_type: 'network' },
      host: { hostname: http.hostname || null },
      request: { method: http.http_method || null, path: http.url || null, bytes_in: asInt(http.request_body_len) },
      response: { status: asInt(http.status), bytes_out: asInt(http.length) },
      facts: Object.assign(baseFacts, {
        host: http.hostname || null,
        uri: http.url || null,
        user_agent: http.http_user_agent || null,
        referrer: http.http_refer || null,
        mime_type: http.http_content_type || null,
        request_body_len: asInt(http.request_body_len),
        response_body_len: asInt(http.length)
      })
    };
  }

  if (type === 'alert') {
    const alert = raw.alert || {};
    return {
      ts: raw.timestamp,
      kind: 'network.alert',
      outcome: 'observed',
      hint: 'suricata:alert:' + (raw.flow_id || raw.timestamp) + ':' + (alert.signature_id || ''),
      source: { ip: src, port: srcPort, principal: null, principal_type: 'network' },
      host: { hostname: null, address: dst, port: dstPort },
      facts: Object.assign(baseFacts, {
        signature: alert.signature || null,
        signature_id: alert.signature_id != null ? Number(alert.signature_id) : null,
        category: alert.category || null,
        severity: alert.severity != null ? Number(alert.severity) : null,
        action: alert.action || null,
        payload_printable: alert.payload_printable || null
      })
    };
  }

  if (type === 'flow') {
    const flow = raw.flow || {};
    return {
      ts: raw.timestamp,
      kind: 'network.flow',
      outcome: 'observed',
      hint: 'suricata:flow:' + (raw.flow_id || raw.timestamp),
      source: { ip: src, port: srcPort, principal: null, principal_type: 'network' },
      host: { hostname: null, port: dstPort, address: dst },
      facts: Object.assign(baseFacts, {
        bytes_out: asInt(flow.bytes_toserver),
        bytes_in: asInt(flow.bytes_toclient),
        packets_out: asInt(flow.pkts_toserver),
        packets_in: asInt(flow.pkts_toclient),
        start: flow.start || null,
        end: flow.end || null,
        age: asInt(flow.age),
        state: flow.state || null,
        alerted: flow.alerted === true
      })
    };
  }

  return null;
}

function mapRecord(raw, provider, fallbackType) {
  if (!raw || typeof raw !== 'object') return null;
  if (provider === 'suricata-eve') return mapSuricata(raw);
  if (provider === 'zeek-json') return mapZeek(raw, fallbackType);
  if (raw.event_type) return mapSuricata(raw);
  return mapZeek(raw, fallbackType);
}

class NetworkSensorAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'network.sensor',
      name: 'Network sensor flow, DNS and TLS metadata',
      category: 'C: Data stores and external services',
      capabilities: [
        'per-flow byte counts and connection state (Zeek conn / Suricata flow)',
        'DNS query names, types, answers and response codes',
        'TLS SNI, negotiated version/cipher and certificate subject/issuer (not plaintext)',
        'HTTP metadata and IDS alerts when the sensor emits them'
      ],
      limitations: [
        'requires a sensor (Zeek or Suricata) writing JSONL; this build is not a packet-capture driver',
        'TLS is metadata only: payloads are not decrypted and no TLS interception is performed',
        'encrypted traffic volume is visible, but content and intent are not',
        'sensor placement determines whether east-west or only perimeter traffic is visible'
      ],
      source: { type: 'file', format: 'jsonl', sensors: ['zeek', 'suricata'] }
    }, opts));
    this.provider = this.config.provider || 'auto';
    this.logType = this.config.log_type || null;
    this.tailer = null;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (!this.config.path) return this.markNotConfigured('adapters.network_sensor.path is empty; point it at Zeek or Suricata JSONL');
    try {
      const st = fs.statSync(this.config.path);
      if (!st.isFile()) return this.markUnavailable('configured network sensor path is not a regular file');
      this.source = { path: this.config.path, provider: this.provider, log_type: this.logType, bytes: st.size };
      this.tailer = new JsonlTailer({ file: this.config.path, maxLines: 2000, maxLineBytes: 1024 * 1024, cursor: this.cursor });
      return this.markActive('tailing ' + this.provider + ' sensor log', { path: this.config.path, provider: this.provider, log_type: this.logType });
    } catch (e) {
      return this.markUnavailable('network sensor log not readable: ' + (e.code || e.message));
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
      let item;
      try {
        item = mapRecord(line.parsed, this.provider, this.logType);
      } catch (e) {
        item = null;
      }
      if (!item) continue;
      item.adapter = this.id;
      item.adapter_version = '0.1.0';
      if (!item.ts) item.ts = new Date().toISOString();
      events.push(item);
    }
    this.detail.bad_lines = res.bad_lines;
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { NetworkSensorAdapter, mapRecord, mapZeek, mapSuricata };

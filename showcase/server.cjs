'use strict';

// Verifyd Campus - zero-dependency showcase server.
// Serves the dashboard, its API, and live receipt verification.

const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const ROOT = path.resolve(__dirname, '..');
const PUBLIC = path.join(__dirname, 'public');
const DATA_FILE = path.join(__dirname, 'data', 'cases.json');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

const v = require(path.join(ROOT, 'engine', 'verifyd.cjs'));
const campus = require('./lib/campus.cjs');

function loadCampus() {
  if (fs.existsSync(DATA_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    } catch (e) {
      console.warn('Seed file unreadable, rebuilding: ' + e.message);
    }
  }
  const fresh = campus.buildCampus();
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(fresh, null, 2) + '\n');
  return fresh;
}

const initial = loadCampus();
const store = {
  institution: initial.institution,
  board: initial.board,
  agents: initial.agents,
  citations: initial.citations,
  cases: initial.cases.slice(),
  chain: initial.cases.filter(c => c.receipt).map(c => ({
    receipt: c.receipt,
    case_id: c.id,
    case_no: c.case_no,
    title: c.title,
    status: c.status,
    sealed_at: c.session.started_at,
  })),
  tampered: new Map(),
  intakes: 0,
  started_at: new Date().toISOString(),
};

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function elapsed(start) {
  return Math.round((nowMs() - start) * 100) / 100;
}

function deepClone(o) {
  return JSON.parse(JSON.stringify(o));
}

function currentCase(id) {
  if (store.tampered.has(id)) return store.tampered.get(id);
  return store.cases.find(c => c.id === id) || null;
}

function publicCase(c) {
  const verification = campus.verifyCase(c);
  const copy = deepClone(c);
  copy.verification = verification;
  copy.status = c.status;
  return copy;
}

function caseSummary(c) {
  return {
    id: c.id,
    case_no: c.case_no,
    type: c.type,
    title: c.title,
    status: c.status,
    materiality: c.materiality,
    date: c.date,
    term: c.term,
    student: c.student,
    agent: { name: c.agent.name, agent_id: c.agent.agent_id, vendor: c.agent.vendor },
    decision: { summary: c.decision.summary, recommendation: c.decision.recommendation, outcome: c.decision.outcome },
    trust: c.trust_score.value,
    lattice: c.lattice.status,
    quorum: c.lattice.quorum,
    verified: campus.verifyCase(c).valid,
    sealed: !!c.receipt,
    tags: c.tags,
  };
}

function summarize() {
  const cases = store.cases;
  const counts = {};
  cases.forEach(c => { counts[c.status] = (counts[c.status] || 0) + 1; });
  const sealed = cases.filter(c => c.receipt);
  const tampered = cases.filter(c => c.receipt && !campus.verifyCase(c).valid);
  const chainReceipts = store.chain.map(x => x.receipt);
  const chainCheck = v.verifyChain(chainReceipts);
  const standards = new Set();
  cases.forEach(c => c.policy_checks.forEach(p => (p.citations || []).forEach(cit => standards.add(cit.standard))));
  return {
    total: cases.length,
    sealed: sealed.length,
    ratified: counts.RATIFIED || 0,
    awaiting: counts.AWAITING || 0,
    provisional: counts.PROVISIONAL || 0,
    blocked: counts.BLOCKED || 0,
    tamper_detected: tampered.length,
    avg_trust: sealed.length ? Math.round(sealed.reduce((s, c) => s + c.trust_score.value, 0) / sealed.length) : 0,
    standards_cited: standards.size,
    chain_valid: chainCheck.valid,
    chain_length: chainReceipts.length,
    intakes: store.intakes,
    demo_tampered: store.tampered.size,
  };
}

function chainView() {
  const receipts = store.chain.map(x => x.receipt);
  const check = v.verifyChain(receipts);
  return {
    valid: check.valid,
    errors: check.errors,
    receipts: store.chain.map((x, i) => ({
      index: i,
      case_id: x.case_id,
      case_no: x.case_no,
      title: x.title,
      status: x.status,
      receipt_id: x.receipt.receipt_id,
      prev_hash: x.receipt.prev_hash,
      this_hash: x.receipt.this_hash,
      sealed_at: x.sealed_at,
    })),
  };
}

function statePayload() {
  return {
    institution: store.institution,
    board: store.board,
    agents: store.agents,
    templates: campus.TEMPLATES.map(t => ({ id: t.id, label: t.label, type: t.type })),
    summary: summarize(),
    cases: store.cases.map(caseSummary),
    chain: chainView(),
    standards: store.citations.standards,
    generated_at: initial.generated_at,
    served_at: new Date().toISOString(),
  };
}

function sendJson(res, code, body, extraHeaders) {
  const text = JSON.stringify(body);
  res.writeHead(code, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  }, extraHeaders || {}));
  res.end(text);
}

function sendText(res, code, text, type) {
  res.writeHead(code, {
    'Content-Type': (type || 'text/plain') + '; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(text);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error('request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); } catch (e) { reject(new Error('invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

function mimeFor(file) {
  const ext = path.extname(file).toLowerCase();
  return {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.txt': 'text/plain; charset=utf-8',
  }[ext] || 'application/octet-stream';
}

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.replace(/^\/+/, ''));
  const file = path.resolve(PUBLIC, rel);
  if (!file.startsWith(PUBLIC + path.sep) && file !== PUBLIC) {
    return sendText(res, 403, 'forbidden');
  }
  fs.readFile(file, (err, buf) => {
    if (err) return sendText(res, 404, 'not found');
    res.writeHead(200, {
      'Content-Type': mimeFor(file),
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(buf);
  });
}

async function handleApi(req, res, url) {
  const pathname = url.pathname;
  const parts = pathname.split('/').filter(Boolean);

  if (pathname === '/api/health') {
    return sendJson(res, 200, { ok: true, uptime_seconds: Math.round(process.uptime()), engine: 'verifyd/1.0', valf: '1.0' });
  }

  if (pathname === '/api/state' && req.method === 'GET') {
    return sendJson(res, 200, statePayload());
  }

  if (pathname === '/api/chain' && req.method === 'GET') {
    return sendJson(res, 200, chainView());
  }

  if (pathname === '/api/intake' && req.method === 'POST') {
    let body;
    try { body = await readBody(req); } catch (e) { return sendJson(res, 400, { error: e.message }); }
    const witnesses = Array.isArray(body.witnesses) ? body.witnesses.filter(w => store.board.some(b => b.witness_id === w)) : [];
    if (body.unilateral && witnesses.length < 4) {
      // Seeded board never has fewer than four seats; keep the demo honest.
      for (const seat of store.board) {
        if (witnesses.length >= 4) break;
        if (!witnesses.includes(seat.witness_id)) witnesses.push(seat.witness_id);
      }
    }
    const t0 = nowMs();
    store.intakes += 1;
    const prevHash = store.chain.length ? store.chain[store.chain.length - 1].receipt.this_hash : 'GENESIS';
    let record;
    try {
      record = campus.buildIntakeCase({
        template: body.template,
        student: body.student,
        course: body.course,
        score: body.score,
        confidence: body.confidence,
        witnesses: witnesses.length ? witnesses : ['W-01', 'W-02', 'W-03', 'W-06'],
        unilateral: !!body.unilateral,
        seq: store.intakes,
      }, prevHash, store.chain.length);
    } catch (e) {
      return sendJson(res, 500, { error: 'intake failed: ' + e.message });
    }
    store.cases.unshift(record);
    if (record.receipt) {
      store.chain.push({
        receipt: record.receipt,
        case_id: record.id,
        case_no: record.case_no,
        title: record.title,
        status: record.status,
        sealed_at: record.session.started_at,
      });
    }
    const payload = publicCase(record);
    return sendJson(res, record.receipt ? 201 : 200, {
      case: payload,
      sealed: !!record.receipt,
      refusal: record.attempt ? record.attempt.error : null,
      duration_ms: elapsed(t0),
      summary: summarize(),
    });
  }

  if (parts[0] === 'api' && parts[1] === 'cases' && parts[2]) {
    const c = currentCase(parts[2]);
    if (!c) return sendJson(res, 404, { error: 'case not found' });

    if (parts.length === 3 && req.method === 'GET') {
      return sendJson(res, 200, { case: publicCase(c), demo_tampered: store.tampered.has(c.id) });
    }

    if (parts[3] === 'verify' && req.method === 'POST') {
      const t0 = nowMs();
      const verification = campus.verifyCase(c);
      return sendJson(res, 200, {
        verification,
        status: c.status,
        duration_ms: elapsed(t0),
        tampered_demo: store.tampered.has(c.id),
      });
    }

    if (parts[3] === 'tamper' && req.method === 'POST') {
      if (!c.receipt) return sendJson(res, 400, { error: 'no sealed receipt: refusal is already the evidence' });
      const base = store.cases.find(x => x.id === c.id);
      if (store.tampered.has(c.id)) {
        return sendJson(res, 200, { already: true, verification: campus.verifyCase(store.tampered.get(c.id)), tampered_demo: true });
      }
      const clone = deepClone(base);
      const original = clone.receipt.trust_score.value;
      const altered = Math.max(0, Math.min(100, original - 11));
      clone.receipt.trust_score.value = altered;
      clone.receipt.this_hash = base.receipt.this_hash; // hash is left untouched: that is the point
      clone.status = 'TAMPERED';
      clone.tamper_demo = {
        field: 'receipt.trust_score.value',
        original,
        altered,
        how: 'A sealed field was edited after the receipt was signed. The stored this_hash was left in place.',
      };
      store.tampered.set(c.id, clone);
      const verification = campus.verifyCase(clone);
      return sendJson(res, 200, { tamper: clone.tamper_demo, verification, status: 'TAMPERED', tampered_demo: true });
    }

    if (parts[3] === 'restore' && (req.method === 'POST' || req.method === 'DELETE')) {
      store.tampered.delete(c.id);
      const restored = currentCase(c.id);
      return sendJson(res, 200, { restored: true, verification: campus.verifyCase(restored), status: restored.status });
    }

    if (parts[3] === 'certificate' && req.method === 'GET') {
      return sendText(res, 200, campus.renderCertificate(c));
    }
  }

  return sendJson(res, 404, { error: 'unknown API route' });
}

const server = http.createServer(async (req, res) => {
  const started = nowMs();
  let url;
  try {
    url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  } catch (e) {
    return sendText(res, 400, 'bad request');
  }

  res.on('finish', () => {
    if (url.pathname.startsWith('/api/')) {
      console.log(req.method + ' ' + url.pathname + ' -> ' + res.statusCode + ' (' + elapsed(started) + 'ms)');
    }
  });

  const docs = {
    '/docs/SYSTEM-REPORT.md': path.join(ROOT, 'docs', 'SYSTEM-REPORT.md'),
    '/docs/UNIVERSITY-PLAYBOOK.md': path.join(ROOT, 'docs', 'UNIVERSITY-PLAYBOOK.md'),
  };
  if (docs[url.pathname] && req.method === 'GET') {
    try {
      return sendText(res, 200, fs.readFileSync(docs[url.pathname], 'utf8'), 'text/plain');
    } catch (e) {
      return sendText(res, 404, 'document not found');
    }
  }

  try {
    if (url.pathname.startsWith('/api/')) {
      return await handleApi(req, res, url);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return sendText(res, 405, 'method not allowed');
    }
    return serveStatic(req, res, url.pathname);
  } catch (e) {
    console.error('request error:', e && e.stack || e);
    if (!res.headersSent) sendJson(res, 500, { error: 'internal error' });
    else res.end();
  }
});

server.listen(PORT, HOST, () => {
  const s = summarize();
  console.log('');
  console.log('Verifyd Campus');
  console.log('  url:      http://' + HOST + ':' + PORT);
  console.log('  cases:    ' + s.total + ' (' + s.sealed + ' receipts, chain ' + (s.chain_valid ? 'valid' : 'BROKEN') + ')');
  console.log('  engine:   Verifyd v1.0 / VALF-1');
  console.log('  data:     ' + DATA_FILE);
  console.log('');
});

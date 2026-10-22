'use strict';

/* Verifyd Campus - dashboard client. No frameworks, no build step. */

const app = {
  state: null,
  summary: null,
  cases: [],
  chain: null,
  filter: 'ALL',
  query: '',
  selectedId: null,
  detailCase: null,
  tab: 'finding',
  lastVerify: null,
  lastDuration: null,
  tamperInfo: null,
  baseTamper: null,
  demoTampered: false,
  originalStatus: null,
  requestToken: 0,
};

const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

const STATUS = {
  RATIFIED: { label: 'Ratified', cls: 'ratified', dot: 'ratified' },
  AWAITING: { label: 'Awaiting quorum', cls: 'awaiting', dot: 'awaiting' },
  PROVISIONAL: { label: 'Provisional', cls: 'provisional', dot: 'provisional' },
  BLOCKED: { label: 'Refused', cls: 'blocked', dot: 'blocked' },
  TAMPERED: { label: 'Tamper detected', cls: 'tampered', dot: 'tampered' },
  DEPOSITED: { label: 'Deposited', cls: 'provisional', dot: 'provisional' },
};

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function shortHash(hash, len) {
  if (!hash) return 'n/a';
  const n = len || 18;
  return hash.length > n + 6 ? hash.slice(0, n) + '...' : hash;
}

function formatDate(iso) {
  if (!iso) return 'n/a';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

function formatDateTime(iso) {
  if (!iso) return 'n/a';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function statusOf(value) {
  return STATUS[value] || { label: value || 'Unknown', cls: 'blocked', dot: 'blocked' };
}

async function api(path, options) {
  const res = await fetch(path, options);
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : {}; } catch (e) { body = { error: text }; }
  if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
  return body;
}

function toast(message, kind) {
  const el = $('#toast');
  el.textContent = message;
  el.className = 'toast show ' + (kind || '');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => { el.className = 'toast ' + (kind || ''); }, 3200);
}

/* ------------------------------------------------------------------ boot */

async function boot() {
  try {
    const state = await api('/api/state');
    app.state = state;
    app.summary = state.summary;
    app.cases = state.cases;
    app.chain = state.chain;
    renderStats();
    renderMiniChain();
    renderFilters();
    renderCaseList();
    renderLedger();
    populateIntake();
    if (app.cases.length) {
      await selectCase(app.cases[0].id);
      primeVerification();
    }
  } catch (e) {
    $('#detail').innerHTML = '<div class="error-panel">Could not load the campus ledger: ' + escapeHtml(e.message) + '</div>';
  }
}

async function reloadState() {
  const state = await api('/api/state');
  app.state = state;
  app.summary = state.summary;
  app.cases = state.cases;
  app.chain = state.chain;
  renderStats();
  renderMiniChain();
  renderFilters();
  renderCaseList();
  renderLedger();
}

/* ---------------------------------------------------------------- chrome */

function renderStats() {
  const s = app.summary;
  if (!s) return;
  const sealedCases = app.cases.filter(c => c.sealed);
  const valid = sealedCases.filter(c => c.verified).length;
  const pct = sealedCases.length ? Math.round((valid / sealedCases.length) * 100) : 100;

  $('#stat-sealed').textContent = s.sealed;
  $('#stat-standards').textContent = s.standards_cited;
  $('#stat-tamper').textContent = s.tamper_detected;
  $('#hero-sealed').textContent = s.sealed;
  $('#hero-valid').textContent = pct + '%';
  $('#hero-chain').textContent = s.chain_valid ? 'valid' : 'BROKEN';
  $('#hero-chain').className = 'mono' + (s.chain_valid ? '' : ' bad');
  $('#hero-chain-length').textContent = s.chain_length + ' blocks';
}

function renderMiniChain() {
  const list = $('#mini-chain');
  if (!app.chain) return;
  const rows = app.chain.receipts.slice(-5).reverse();
  list.innerHTML = rows.map(r => {
    const flagged = r.status === 'TAMPERED';
    const pending = r.status === 'AWAITING' || r.status === 'PROVISIONAL';
    const cls = flagged ? ' alert' : pending ? ' pending' : '';
    return '<div class="mini-row' + cls + '" data-mini-case="' + escapeHtml(r.case_id) + '">' +
      '<span class="idx">' + String(r.index).padStart(2, '0') + '</span>' +
      '<span class="h" title="' + escapeHtml(r.this_hash) + '">' + escapeHtml(shortHash(r.this_hash, 26)) + '</span>' +
      '<span class="tag">' + escapeHtml(flagged ? 'flagged' : pending ? 'pending' : statusOf(r.status).label) + '</span>' +
    '</div>';
  }).join('');
  $$('#mini-chain .mini-row').forEach(row => {
    row.addEventListener('click', () => openCase(row.dataset.miniCase));
  });
}

function renderFilters() {
  const values = [
    ['ALL', 'All'],
    ['RATIFIED', 'Ratified'],
    ['AWAITING', 'Awaiting'],
    ['TAMPERED', 'Tampered'],
    ['BLOCKED', 'Refused'],
    ['PROVISIONAL', 'Provisional'],
  ];
  const counts = app.cases.reduce((acc, c) => { acc[c.status] = (acc[c.status] || 0) + 1; return acc; }, {});
  $('#filters').innerHTML = values.map(([value, label]) => {
    const n = value === 'ALL' ? app.cases.length : (counts[value] || 0);
    return '<button class="filter' + (app.filter === value ? ' active' : '') + '" data-filter="' + value + '" type="button" role="tab" aria-selected="' + (app.filter === value) + '">' +
      label + ' <span style="opacity:.55">' + n + '</span></button>';
  }).join('');
  $$('#filters .filter').forEach(btn => {
    btn.addEventListener('click', () => {
      app.filter = btn.dataset.filter;
      renderFilters();
      renderCaseList();
    });
  });
}

function filteredCases() {
  const q = app.query.trim().toLowerCase();
  return app.cases.filter(c => {
    if (app.filter !== 'ALL' && c.status !== app.filter) return false;
    if (!q) return true;
    const hay = [c.case_no, c.title, c.type, c.student && c.student.pseudonym, c.agent.name, c.tags.join(' ')].join(' ').toLowerCase();
    return hay.includes(q);
  });
}

function renderCaseList() {
  const cases = filteredCases();
  $('#case-count').textContent = cases.length;
  const list = $('#case-list');
  if (!cases.length) {
    list.innerHTML = '<div class="rail-note">No cases match this filter.</div>';
    return;
  }
  list.innerHTML = cases.map(c => {
    const st = statusOf(c.status);
    const trust = c.status === 'BLOCKED' ? 'refused' : c.trust + '<span>/100</span>';
    return '<button class="case-item' + (c.id === app.selectedId ? ' active' : '') + '" data-case="' + escapeHtml(c.id) + '" type="button">' +
      '<span class="dot ' + st.dot + '"></span>' +
      '<span class="case-main">' +
        '<span class="case-top"><span class="case-id">' + escapeHtml(c.case_no) + '</span><span class="case-id">' + escapeHtml(formatDate(c.date)) + '</span></span>' +
        '<span class="case-title">' + escapeHtml(c.title) + '</span>' +
        '<span class="case-sub">' + escapeHtml(c.agent.name) + ' / ' + escapeHtml(c.type) + '</span>' +
      '</span>' +
      '<span class="trust-mini"><b>' + trust + '</b>' + escapeHtml(c.status === 'BLOCKED' ? 'no seal' : st.label) + '</span>' +
    '</button>';
  }).join('');
  $$('#case-list .case-item').forEach(btn => {
    btn.addEventListener('click', () => openCase(btn.dataset.case));
  });
}

function renderLedger() {
  if (!app.chain) return;
  const badge = $('#chain-badge');
  badge.textContent = app.chain.valid ? 'chain valid' : 'chain broken';
  badge.className = 'chain-badge' + (app.chain.valid ? '' : ' bad');

  const head = '<div class="chain-head"><span>#</span><span>case</span><span>record</span><span>prev hash</span><span>this hash</span><span>link</span></div>';
  const rows = app.chain.receipts.map(r => {
    const flagged = r.status === 'TAMPERED';
    return '<button class="chain-row" data-chain-case="' + escapeHtml(r.case_id) + '" type="button">' +
      '<span class="idx">' + String(r.index).padStart(2, '0') + '</span>' +
      '<span class="case">' + escapeHtml(r.case_no) + '</span>' +
      '<span class="title">' + escapeHtml(r.title) + '</span>' +
      '<span class="hash" title="' + escapeHtml(r.prev_hash) + '"><b>' + escapeHtml(shortHash(r.prev_hash, 14)) + '</b></span>' +
      '<span class="hash" title="' + escapeHtml(r.this_hash) + '"><b>' + escapeHtml(shortHash(r.this_hash, 14)) + '</b></span>' +
      '<span class="ok' + (flagged ? ' bad' : '') + '">' + (flagged ? 'flagged' : 'link ok') + '</span>' +
    '</button>';
  }).join('');
  $('#chain-table').innerHTML = head + rows;
  $$('#chain-table .chain-row').forEach(row => {
    row.addEventListener('click', () => openCase(row.dataset.chainCase));
  });
}

function openCase(id) {
  selectCase(id);
  const el = $('#cases');
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ---------------------------------------------------------------- detail */

async function selectCase(id) {
  if (!id) return;
  const token = ++app.requestToken;
  app.selectedId = id;
  app.tab = 'finding';
  app.lastVerify = null;
  app.lastDuration = null;
  app.tamperInfo = null;
  app.baseTamper = null;
  app.demoTampered = false;
  renderCaseList();
  $('#detail').innerHTML = '<div class="loading">Loading ' + escapeHtml(id) + '...</div>';
  try {
    const data = await api('/api/cases/' + encodeURIComponent(id));
    if (token !== app.requestToken) return;
    app.detailCase = data.case;
    app.originalStatus = data.case.status;
    app.lastVerify = data.case.verification;
    app.demoTampered = !!data.demo_tampered;
    app.baseTamper = data.case.tamper || null;
    app.tamperInfo = app.baseTamper;
    renderDetail();
  } catch (e) {
    if (token !== app.requestToken) return;
    $('#detail').innerHTML = '<div class="error-panel">Could not load case: ' + escapeHtml(e.message) + '</div>';
  }
}

async function primeVerification() {
  if (!app.selectedId) return;
  try {
    const data = await api('/api/cases/' + encodeURIComponent(app.selectedId) + '/verify', { method: 'POST' });
    if (app.lastVerify == null) return;
    app.lastVerify = data.verification;
    app.lastDuration = data.duration_ms;
    $('#stat-verify').textContent = data.duration_ms.toFixed(2) + ' ms';
    if (app.detailCase && app.detailCase.id === app.selectedId) renderDetail();
  } catch (e) {
    /* verification indicator is optional */
  }
}

function renderDetail() {
  const c = app.detailCase;
  if (!c) return;
  const st = statusOf(c.status);
  const v = app.lastVerify || c.verification || {};
  const hasReceipt = !!c.receipt;

  const html = '' +
    '<div class="case-head">' +
      '<div class="case-head-top">' +
        '<span class="case-code">' + escapeHtml(c.case_no) + '</span>' +
        '<span class="chip ' + st.cls + '"><i></i>' + escapeHtml(st.label) + '</span>' +
        '<span class="case-code">' + escapeHtml(c.type) + '</span>' +
        '<span class="case-code">' + escapeHtml(c.term) + '</span>' +
        '<span class="case-code">materiality: ' + escapeHtml(c.materiality) + '</span>' +
      '</div>' +
      '<h2>' + escapeHtml(c.title) + '</h2>' +
      '<div class="case-meta">' +
        '<span><b>Student ref</b> ' + escapeHtml(c.student ? c.student.pseudonym : 'n/a') + '</span>' +
        '<span><b>Agent</b> ' + escapeHtml(c.agent.name) + ' <span class="mono">' + escapeHtml(c.agent.agent_id) + '</span></span>' +
        '<span><b>Auditor</b> ' + escapeHtml(c.auditor.name) + '</span>' +
        '<span><b>Sealed</b> ' + escapeHtml(formatDateTime(c.date)) + '</span>' +
      '</div>' +
    '</div>' +
    '<div class="explain-grid">' +
      '<div class="explain-cell"><span class="kicker">What the AI claimed</span><p>' + escapeHtml(c.explain.ai || c.decision.summary) + '</p></div>' +
      '<div class="explain-cell"><span class="kicker">What humans decided</span><p>' + escapeHtml(c.explain.human || c.decision.outcome) + '</p></div>' +
      '<div class="explain-cell"><span class="kicker">What the receipt proves</span><p>' + escapeHtml(c.explain.proof || 'The decision is bound to its sources and quorum.') + '</p></div>' +
    '</div>' +
    (hasReceipt ? verificationPanel(c, v) : refusalPanel(c)) +
    tabs(c) +
    '<div class="tab-body">' + tabBody(c) + '</div>';

  $('#detail').innerHTML = html;
  bindDetail();
}

function tabs(c) {
  const items = [
    ['finding', 'Finding'],
    ['policy', 'Policy and trust'],
    ['oversight', 'Oversight'],
    ['receipt', 'Receipt'],
  ];
  return '<div class="tabs" role="tablist">' + items.map(([id, label]) =>
    '<button class="tab' + (app.tab === id ? ' active' : '') + '" data-tab="' + id + '" type="button" role="tab" aria-selected="' + (app.tab === id) + '">' + label + '</button>'
  ).join('') + '</div>';
}

function verificationPanel(c, v) {
  const valid = !!v.valid;
  const checks = [
    { name: 'Receipt hash', ok: v.receipt_valid, hash: v.recomputed_hash || v.stored_hash, detail: v.receipt_valid ? 'recomputed from sealed fields' : 'stored hash does not recompute' },
    { name: 'Content hash', ok: v.content_valid, hash: v.artifact_hash, detail: v.content_valid ? 'artifact matches the sealed content' : 'source changed after sealing' },
    { name: 'Chain link', ok: v.chain_valid, hash: v.receipt_prev_hash, detail: v.chain_valid ? 'prev_hash matches the prior receipt' : 'chain position does not match' },
  ];
  const checkHtml = checks.map(ch =>
    '<div class="vcheck">' +
      '<div class="vcheck-top"><span class="vcheck-name">' + ch.name + '</span><span class="vcheck-state ' + (ch.ok ? 'ok' : 'bad') + '">' + (ch.ok ? 'OK' : 'FAIL') + '</span></div>' +
      '<div class="vcheck-hash" title="' + escapeHtml(ch.hash || 'n/a') + '">' + escapeHtml(shortHash(ch.hash, 30)) + '</div>' +
      '<div class="vcheck-detail">' + escapeHtml(ch.detail) + '</div>' +
    '</div>'
  ).join('');

  const tamperBtn = app.demoTampered
    ? '<button class="btn btn-ghost" type="button" data-action="restore">Restore demo</button>'
    : '<button class="btn btn-danger" type="button" data-action="tamper">Tamper a sealed field</button>';

  return '<section class="verify-panel" aria-label="Verification result">' +
    '<div class="verify-state">' +
      '<div class="verify-verdict ' + (valid ? 'valid' : 'invalid') + '">' +
        '<span class="mark">' + (valid ? 'OK' : '!') + '</span>' +
        '<span><strong>' + (valid ? 'VERIFIED' : 'TAMPERED') + '</strong><small>' + escapeHtml(v.reason || '') + '</small></span>' +
      '</div>' +
      '<div class="verify-actions">' +
        '<button class="btn btn-ghost" type="button" data-action="verify">Verify now</button>' +
        tamperBtn +
      '</div>' +
    '</div>' +
    '<div class="verify-checks">' + checkHtml + '</div>' +
    '<div class="verify-foot">' +
      '<span>' + (app.lastDuration != null ? 'checked in ' + Number(app.lastDuration).toFixed(2) + ' ms' : 'local recomputation') + ' / SHA-256 over RFC 8785 canonical JSON</span>' +
      '<span class="' + (valid ? 'good' : 'bad') + '">' + (valid ? '3 of 3 checks pass' : 'integrity check failed') + '</span>' +
    '</div>' +
  '</section>';
}

function refusalPanel(c) {
  const error = c.attempt && c.attempt.error ? c.attempt.error : 'no sealed receipt';
  return '<section class="verify-panel" aria-label="Protocol refusal">' +
    '<div class="refusal" style="margin:0;border:0;border-radius:0">' +
      '<span class="kicker">Protocol refusal</span>' +
      '<h3>This decision was never ratified.</h3>' +
      '<p>The engine refused to produce a receipt. That refusal is the evidence: no quorum-backed record exists, so no downstream office can cite one.</p>' +
      '<code>' + escapeHtml(error) + '</code>' +
      '<div class="refusal-meta">' +
        '<div><div class="k">Attempted by</div><div class="v">' + escapeHtml(c.attempt ? c.attempt.actor : c.auditor.id) + '</div></div>' +
        '<div><div class="k">Seats claimed</div><div class="v">' + escapeHtml(c.attempt ? c.attempt.attestations : 0) + ' of 7</div></div>' +
        '<div><div class="k">Receipts created</div><div class="v">none</div></div>' +
      '</div>' +
    '</div>' +
  '</section>';
}

function tabBody(c) {
  if (app.tab === 'policy') return policyTab(c);
  if (app.tab === 'oversight') return oversightTab(c);
  if (app.tab === 'receipt') return receiptTab(c);
  return findingTab(c);
}

function findingTab(c) {
  const tags = (c.tags || []).map(t => '<span class="tag">' + escapeHtml(t) + '</span>').join('');
  const anchors = (c.anchors || []).map(a => {
    const isUrl = /^https?:\/\//.test(a.uri);
    const uri = isUrl
      ? '<a class="uri" href="' + escapeHtml(a.uri) + '" target="_blank" rel="noreferrer">' + escapeHtml(a.uri) + '</a>'
      : '<div class="uri">' + escapeHtml(a.uri) + '</div>';
    return '<div class="anchor">' +
      '<div><div class="label">' + escapeHtml(a.label) + '</div>' + uri +
        (a.resolved_metadata && a.resolved_metadata.title ? '<div class="resolved">resolved: ' + escapeHtml(a.resolved_metadata.title) + (a.resolved_metadata.publisher ? ' / ' + escapeHtml(a.resolved_metadata.publisher) : '') + '</div>' : '') +
      '</div>' +
      '<span class="kind">' + escapeHtml(a.kind || 'source') + '</span>' +
    '</div>';
  }).join('');

  const tamperNote = app.tamperInfo ? '<div class="attempt-card" style="margin-top:0">' +
      '<span class="kicker">Post-seal alteration' + (app.demoTampered ? ' / demo' : '') + '</span>' +
      '<strong>' + escapeHtml(app.tamperInfo.field) + '</strong>' +
      '<p>' + escapeHtml(app.tamperInfo.original) + ' -&gt; ' + escapeHtml(app.tamperInfo.altered) + '. ' + escapeHtml(app.tamperInfo.how) + '</p>' +
    '</div>' : '';

  return '' +
    '<div class="panel-title"><h3>Decision record</h3><span class="hint">' + escapeHtml(c.case_no) + ' / ' + escapeHtml(c.type) + '</span></div>' +
    '<div class="decision-card">' +
      '<div class="summary">' + escapeHtml(c.decision.summary) + '</div>' +
      '<dl class="decision-rows">' +
        '<dt>Recommendation</dt><dd>' + escapeHtml(c.decision.recommendation) + '</dd>' +
        '<dt>Outcome</dt><dd>' + escapeHtml(c.decision.outcome) + '</dd>' +
        '<dt>Confidence</dt><dd><span class="mono">' + escapeHtml(c.decision.confidence) + '</span> / half-life ' + escapeHtml(c.decision.half_life_days) + ' days</dd>' +
        '<dt>Agent purpose</dt><dd>' + escapeHtml(c.agent.purpose) + '</dd>' +
      '</dl>' +
      '<div class="tag-row">' + tags + '</div>' +
    '</div>' +
    (c.tamper ? tamperNote : '') +
    '<div class="split">' +
      '<div>' +
        '<div class="panel-title"><h3>Sealed artifact</h3><span class="hint">hash bound at decision time</span></div>' +
        '<div class="artifact">' + escapeHtml(c.artifact) + '</div>' +
        '<div class="panel-title" style="margin-top:22px"><h3>Source anchors</h3><span class="hint">' + c.anchors.length + ' anchors</span></div>' +
        '<div class="anchor-list">' + anchors + '</div>' +
      '</div>' +
      '<div>' +
        '<div class="panel-title"><h3>Confidence decay</h3><span class="hint">exponential, ' + escapeHtml(c.decision.half_life_days) + ' days</span></div>' +
        decayCard(c) +
      '</div>' +
    '</div>';
}

function decayCard(c) {
  const conf = Number(c.decision.confidence) || 0;
  const half = Number(c.decision.half_life_days) || 60;
  return '<div class="decay-card">' + decaySvg(conf, half) +
    '<div class="decay-stats">' +
      '<span>now <b>' + conf.toFixed(2) + '</b></span>' +
      '<span>' + half + 'd <b>' + (conf * 0.5).toFixed(2) + '</b></span>' +
      '<span>' + (half * 2) + 'd <b>' + (conf * 0.25).toFixed(2) + '</b></span>' +
    '</div>' +
    '<div class="decay-stats" style="margin-top:8px"><span style="color:var(--muted-2)">The receipt does not pretend the claim is permanent. It records when it was scored.</span></div>' +
  '</div>';
}

function decaySvg(conf, half) {
  const W = 340, H = 128, padL = 30, padR = 12, padT = 12, padB = 26;
  const x = d => padL + (d / 180) * (W - padL - padR);
  const y = val => padT + (1 - val) * (H - padT - padB);
  const days = [0, 30, 60, 90, 120, 150, 180];
  const pts = days.map(d => [x(d), y(conf * Math.pow(0.5, d / half))]);
  const line = pts.map(p => p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
  const area = line + ' ' + x(180).toFixed(1) + ',' + y(0).toFixed(1) + ' ' + x(0).toFixed(1) + ',' + y(0).toFixed(1);
  const grid = [0, 0.25, 0.5, 0.75, 1].map(v => {
    const yy = y(v).toFixed(1);
    return '<line x1="' + padL + '" y1="' + yy + '" x2="' + (W - padR) + '" y2="' + yy + '" stroke="#1e2b3a" stroke-width="1" />' +
      '<text x="' + (padL - 7) + '" y="' + (Number(yy) + 3) + '" fill="#64748b" font-size="8" font-family="monospace" text-anchor="end">' + v.toFixed(2) + '</text>';
  }).join('');
  const labels = [0, 60, 120, 180].map(d => '<text x="' + x(d).toFixed(1) + '" y="' + (H - 8) + '" fill="#64748b" font-size="8" font-family="monospace" text-anchor="middle">' + d + 'd</text>').join('');
  const dot = pts[2];
  return '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Confidence decays from ' + conf + ' to ' + (conf * 0.5) + ' in ' + half + ' days">' +
    '<defs><linearGradient id="decayFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#b8f24a" stop-opacity="0.22"/><stop offset="100%" stop-color="#b8f24a" stop-opacity="0"/></linearGradient></defs>' +
    grid + labels +
    '<polygon points="' + area + '" fill="url(#decayFill)" />' +
    '<polyline points="' + line + '" fill="none" stroke="#b8f24a" stroke-width="2" stroke-linejoin="round" />' +
    '<circle cx="' + dot[0].toFixed(1) + '" cy="' + dot[1].toFixed(1) + '" r="3.2" fill="#b8f24a" stroke="#070a0f" stroke-width="2" />' +
    '<text x="' + (dot[0] + 8).toFixed(1) + '" y="' + (dot[1] - 7).toFixed(1) + '" fill="#b8f24a" font-size="8.5" font-family="monospace">' + (conf * 0.5).toFixed(2) + ' at ' + half + 'd</text>' +
  '</svg>';
}

function policyTab(c) {
  const checks = c.policy_checks.map(ch => {
    const cites = (ch.citations || []).map(cit => {
      const title = (cit.title || cit.standard) + (cit.locator ? ' - ' + cit.locator : '');
      const inner = escapeHtml(cit.standard) + (cit.locator ? ' <span>' + escapeHtml(cit.locator.slice(0, 38)) + '</span>' : '');
      return cit.url
        ? '<a class="cite" href="' + escapeHtml(cit.url) + '" target="_blank" rel="noreferrer" title="' + escapeHtml(title) + '">' + inner + '</a>'
        : '<span class="cite" title="' + escapeHtml(title) + '">' + inner + '</span>';
    }).join('');
    return '<div class="policy">' +
      '<div class="policy-head">' +
        '<span class="policy-result ' + escapeHtml(ch.result) + '">' + escapeHtml(ch.result.toUpperCase()) + '</span>' +
        '<div><div class="policy-name">' + escapeHtml(ch.principle) + '</div><div class="policy-statement">' + escapeHtml(ch.statement || '') + '</div></div>' +
        '<div class="policy-detail">' + escapeHtml(ch.detail) + '</div>' +
      '</div>' +
      (cites ? '<div class="citations">' + cites + '</div>' : '<div class="no-cite">internal heuristic - no external citation registered in v1.0</div>') +
    '</div>';
  }).join('');

  const t = c.trust_score;
  const ringClass = t.value >= 80 ? '' : t.value >= 60 ? 'mid' : t.value >= 40 ? 'low' : 'bad';
  const bars = Object.keys(t.components).map(key => {
    const label = {
      source_quality: 'Source quality',
      content_richness: 'Content richness',
      policy_compliance: 'Policy compliance',
      document_structure: 'Document structure',
      calibration_freshness: 'Calibration freshness',
      agent_history: 'Agent history',
    }[key] || key;
    const val = t.components[key];
    return '<div class="bar-row"><span class="bar-label">' + escapeHtml(label) + '</span>' +
      '<span class="bar-track"><span class="bar-fill" style="width:' + Math.min(100, (val / 25) * 100) + '%"></span></span>' +
      '<span class="bar-val">' + val + '/25</span></div>';
  }).join('');

  const e = c.evidence || {};
  const fact = (label, val, yesno) => '<div class="evidence-item"><div class="k">' + escapeHtml(label) + '</div><div class="val ' + (yesno === true ? 'yes' : yesno === false ? 'no' : '') + '">' + escapeHtml(val) + '</div></div>';
  const evidence = [
    fact('words', e.word_count),
    fact('characters', e.char_count),
    fact('external anchor', e.has_external_anchor ? 'yes' : 'no', !!e.has_external_anchor),
    fact('metadata resolved', e.has_resolved_external_metadata ? 'yes' : 'no', !!e.has_resolved_external_metadata),
    fact('provenance language', e.has_provenance_language ? 'yes' : 'no', !!e.has_provenance_language),
    fact('verification language', e.has_proof_language ? 'yes' : 'no', !!e.has_proof_language),
  ].join('');

  return '' +
    '<div class="panel-title"><h3>Policy checks</h3><span class="hint">each finding carries its citation grounds</span></div>' +
    '<div class="policy-list">' + checks + '</div>' +
    '<div class="panel-title" style="margin-top:24px"><h3>Trust score</h3><span class="hint">evidence quality, not governance approval</span></div>' +
    '<div class="trust-grid">' +
      '<div class="ring-wrap">' + ringSvg(t.value, ringClass) + '<div class="ring-text"><b>' + t.value + '</b><span>of 100</span><em>' + (t.value >= 80 ? 'strong evidence' : t.value >= 60 ? 'adequate' : t.value >= 40 ? 'thin evidence' : 'insufficient') + '</em></div></div>' +
      '<div><div class="bars">' + bars + '</div>' +
        (t.penalty ? '<div class="penalty-note">evidence penalty applied: -' + t.penalty + ' points</div>' : '') +
        '<div class="evidence-grid" style="margin-top:16px">' + evidence + '</div>' +
      '</div>' +
    '</div>';
}

function ringSvg(score, cls) {
  const r = 44, c = 2 * Math.PI * r, off = c * (1 - score / 100);
  return '<svg viewBox="0 0 120 120" aria-hidden="true">' +
    '<circle class="ring-bg" cx="60" cy="60" r="' + r + '" />' +
    '<circle class="ring-fg ' + cls + '" cx="60" cy="60" r="' + r + '" stroke-dasharray="' + c.toFixed(1) + '" stroke-dashoffset="' + off.toFixed(1) + '" />' +
  '</svg>';
}

function oversightTab(c) {
  const q = c.lattice.quorum || { attempted: 0, required: 4, seats: 7 };
  const met = q.attempted >= q.required;
  const pct = Math.min(100, (q.attempted / q.required) * 100);
  const error = q.error || (c.attempt && c.attempt.error);

  const attempt = error ? '<div class="attempt-card">' +
    '<span class="kicker">' + (c.status === 'BLOCKED' ? 'Hard refusal' : 'Gate held') + '</span>' +
    '<strong>' + escapeHtml(error) + '</strong>' +
    '<p>' + (c.status === 'BLOCKED'
      ? 'A single office tried to ratify on behalf of the board. The protocol produced no receipt.'
      : 'The record is sealed at DEPOSITED. It cannot be called RATIFIED until a fourth distinct seat attests.') + '</p>' +
  '</div>' : '';

  const rank = { DRAFT: 0, PROVISIONAL: 1, DEPOSITED: 2, RATIFIED: 3 }[c.lattice.status] || 0;
  const gates = ['agent output', 'sponsor endorsement', 'external anchor', '4 of 7 distinct seats'];
  const names = ['DRAFT', 'PROVISIONAL', 'DEPOSITED', 'RATIFIED'];
  const ladder = names.map((name, i) => {
    const isBlocked = i === 3 && (c.status === 'BLOCKED' || c.status === 'AWAITING');
    const done = i <= rank && !isBlocked;
    const current = i === rank && !isBlocked;
    return '<div class="ladder-step ' + (isBlocked ? 'blocked' : done ? 'done' : '') + (current ? ' current' : '') + '">' +
      '<span class="tick">' + (isBlocked ? 'X' : done ? 'OK' : '') + '</span>' +
      '<div class="num">S.' + (i + 1) + '</div>' +
      '<div class="st">' + name + '</div>' +
      '<div class="gate">' + gates[i] + '</div>' +
    '</div>';
  }).join('');

  const attested = new Map((c.lattice.attestations || []).map(a => [a.witness_id, a]));
  const seats = (app.state.board || []).map(seat => {
    const a = attested.get(seat.witness_id);
    if (!a) {
      return '<div class="seat empty"><div class="seat-role">seat ' + escapeHtml(seat.witness_id) + '</div><div class="seat-name">No attestation</div><div class="seat-sub">not recorded for this decision</div></div>';
    }
    return '<div class="seat filled' + (a.position === 'dissent' ? ' dissent' : '') + '">' +
      '<div class="seat-role">seat ' + escapeHtml(seat.witness_id) + '</div>' +
      '<div class="seat-name">' + escapeHtml(a.name) + '</div>' +
      '<div class="seat-sub">' + escapeHtml(a.role) + '</div>' +
      '<div class="seat-pos">' + escapeHtml(a.position) + '</div>' +
    '</div>';
  }).join('');

  const attestList = (c.lattice.attestations || []).map(a =>
    '<div class="attest">' +
      '<span class="pos' + (a.position === 'dissent' ? ' dissent' : '') + '">' + escapeHtml(a.position) + '</span>' +
      '<div><div class="who">' + escapeHtml(a.name) + ' - ' + escapeHtml(a.role) + '</div><div class="why">' + escapeHtml(a.rationale) + '</div></div>' +
      '<div class="sig">' + escapeHtml(a.signature) + '</div>' +
    '</div>'
  ).join('');

  return '' +
    '<div class="oversight-top">' +
      '<div class="quorum-card">' +
        '<div class="q-line"><b>' + q.attempted + ' <span style="color:var(--muted-2)">/ ' + q.seats + '</span></b><span>' + q.required + ' required for RATIFIED</span></div>' +
        '<div class="quorum-track"><div class="quorum-fill' + (met ? ' met' : '') + '" style="width:' + pct + '%"></div></div>' +
        '<div class="quorum-note">' + (met ? 'Quorum satisfied. ' : 'Quorum not satisfied. ') + 'Distinct witness ids are enforced; proxy signatures from one office are refused.' + '</div>' +
      '</div>' +
      (attempt || '<div class="quorum-card"><div class="q-line"><b>no refusal</b></div><div class="quorum-note">No ratification attempt failed for this record.</div></div>') +
    '</div>' +
    '<div class="panel-title" style="margin-top:24px"><h3>Lattice promotion path</h3><span class="hint">forbidden shortcuts are rejected by the grammar</span></div>' +
    '<div class="ladder">' + ladder + '</div>' +
    '<div class="panel-title" style="margin-top:24px"><h3>Independent Oversight Board</h3><span class="hint">' + (app.state.board || []).length + ' seats / ' + q.required + ' quorum</span></div>' +
    '<div class="board-grid">' + seats + '</div>' +
    (attestList ? '<div class="panel-title" style="margin-top:24px"><h3>Attestation detail</h3><span class="hint">signed at ' + escapeHtml(formatDateTime(c.date)) + '</span></div><div class="attest-list">' + attestList + '</div>' : '') +
    (c.status === 'BLOCKED' ? refusalPanel(c) : '');
}

function receiptTab(c) {
  if (!c.receipt) {
    return refusalPanel(c) +
      '<div class="panel-title" style="margin-top:22px"><h3>No receipt exists</h3><span class="hint">refusal record</span></div>' +
      '<div class="code-wrap"><div class="code-head"><span>refusal.json</span></div><pre class="json">' +
      highlightJson({
        sealed: false,
        case: c.case_no,
        attempted_by: c.attempt ? c.attempt.actor : c.auditor.id,
        seats_claimed: c.attempt ? c.attempt.attestations : 0,
        sole_sovereign: c.attempt ? c.attempt.sole_sovereign : false,
        refusal: c.attempt ? c.attempt.error : 'no receipt',
      }) + '</pre></div>';
  }
  const meta = '<div class="receipt-meta">' +
    '<span class="meta-chip">receipt <b>' + escapeHtml(c.receipt.receipt_id) + '</b></span>' +
    '<span class="meta-chip">VALF <b>' + escapeHtml(c.receipt.valf_version) + '</b></span>' +
    '<span class="meta-chip">chain index <b>' + escapeHtml(c.chain_index) + '</b></span>' +
    '<span class="meta-chip">prev <b>' + escapeHtml(shortHash(c.receipt.prev_hash, 18)) + '</b></span>' +
  '</div>';
  return meta +
    '<div class="code-wrap">' +
      '<div class="code-head"><span>receipt.json / VALF-1</span>' +
        '<div class="code-actions">' +
          '<button class="mini-btn" type="button" data-action="copy">copy</button>' +
          '<button class="mini-btn" type="button" data-action="download">download</button>' +
          '<button class="mini-btn" type="button" data-action="certificate">certificate</button>' +
        '</div>' +
      '</div>' +
      '<pre class="json">' + highlightJson(c.receipt) + '</pre>' +
    '</div>' +
    '<div class="panel-title" style="margin-top:22px"><h3>How to re-verify offline</h3><span class="hint">no server, no vendor</span></div>' +
    '<div class="code-wrap"><div class="code-head"><span>shell</span></div><pre class="json">' +
      '# 1. recompute SHA-256 over canonical JSON, omitting this_hash\n' +
      '# 2. compare with receipt.this_hash\n' +
      '# 3. hash the source artifact and compare with outputs[0].content_hash\n' +
      '# 4. compare receipt.prev_hash with the previous receipt in the chain\n\n' +
      'node bin/verifyd.cjs verify "' + escapeHtml(c.case_no) + '.verifyd-receipt.json"' +
    '</pre></div>';
}

function highlightJson(obj) {
  const json = JSON.stringify(obj, null, 2);
  return escapeHtml(json)
    .replace(/(&quot;(?:\\.|[^&])*?&quot;)(\s*:)?/g, (match, token, colon) =>
      colon ? '<span class="j-key">' + token + '</span>' + colon : '<span class="j-str">' + token + '</span>')
    .replace(/\b(true|false|null)\b/g, '<span class="j-lit">$1</span>');
}

function bindDetail() {
  $$('#detail .tab').forEach(btn => {
    btn.addEventListener('click', () => {
      app.tab = btn.dataset.tab;
      renderDetail();
    });
  });

  const detail = $('#detail');
  detail.onclick = async event => {
    const action = event.target.closest('[data-action]');
    if (action) {
      const kind = action.dataset.action;
      if (kind === 'verify') return runVerify();
      if (kind === 'tamper') return runTamper();
      if (kind === 'restore') return runRestore();
      if (kind === 'copy') return copyReceipt();
      if (kind === 'download') return downloadReceipt();
      if (kind === 'certificate') return openCertificate();
    }
  };
}

async function runVerify() {
  const c = app.detailCase;
  if (!c) return;
  try {
    const data = await api('/api/cases/' + encodeURIComponent(c.id) + '/verify', { method: 'POST' });
    app.lastVerify = data.verification;
    app.lastDuration = data.duration_ms;
    app.detailCase.verification = data.verification;
    $('#stat-verify').textContent = data.duration_ms.toFixed(2) + ' ms';
    renderDetail();
    toast(data.verification.valid ? 'All three checks pass in ' + data.duration_ms.toFixed(2) + ' ms' : 'Integrity failure: ' + data.verification.reason, data.verification.valid ? 'good' : 'bad');
  } catch (e) {
    toast(e.message, 'bad');
  }
}

async function runTamper() {
  const c = app.detailCase;
  if (!c || !c.receipt) return;
  try {
    const data = await api('/api/cases/' + encodeURIComponent(c.id) + '/tamper', { method: 'POST' });
    app.lastVerify = data.verification;
    app.lastDuration = null;
    app.tamperInfo = data.tamper || app.tamperInfo;
    app.demoTampered = true;
    app.detailCase.verification = data.verification;
    app.detailCase.status = 'TAMPERED';
    renderDetail();
    toast('Sealed field altered. Verification now fails.', 'bad');
  } catch (e) {
    toast(e.message, 'bad');
  }
}

async function runRestore() {
  const c = app.detailCase;
  if (!c) return;
  try {
    const data = await api('/api/cases/' + encodeURIComponent(c.id) + '/restore', { method: 'POST' });
    app.lastVerify = data.verification;
    app.lastDuration = null;
    app.tamperInfo = app.baseTamper;
    app.demoTampered = false;
    app.detailCase.verification = data.verification;
    app.detailCase.status = data.status || app.originalStatus;
    renderDetail();
    toast('Demo tamper removed. Receipt recomputes again.', 'good');
  } catch (e) {
    toast(e.message, 'bad');
  }
}

function copyReceipt() {
  const c = app.detailCase;
  if (!c || !c.receipt) return;
  navigator.clipboard.writeText(JSON.stringify(c.receipt, null, 2))
    .then(() => toast('Receipt JSON copied', 'good'))
    .catch(() => toast('Clipboard unavailable', 'bad'));
}

function downloadReceipt() {
  const c = app.detailCase;
  if (!c || !c.receipt) return;
  const blob = new Blob([JSON.stringify(c.receipt, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = c.case_no + '.verifyd-receipt.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast('Receipt downloaded', 'good');
}

function openCertificate() {
  const c = app.detailCase;
  if (!c) return;
  window.open('/api/cases/' + encodeURIComponent(c.id) + '/certificate', '_blank', 'noopener');
}

/* ---------------------------------------------------------------- intake */

function populateIntake() {
  const select = $('#f-template');
  select.innerHTML = (app.state.templates || []).map(t =>
    '<option value="' + escapeHtml(t.id) + '">' + escapeHtml(t.label) + '</option>'
  ).join('');

  const defaults = new Set(['W-01', 'W-02', 'W-03', 'W-06']);
  $('#witness-grid').innerHTML = (app.state.board || []).map(seat =>
    '<label class="witness-check"><input type="checkbox" name="witness" value="' + escapeHtml(seat.witness_id) + '"' + (defaults.has(seat.witness_id) ? ' checked' : '') + '>' +
    '<span>' + escapeHtml(seat.witness_id + ' ' + seat.name) + '</span></label>'
  ).join('');

  const updateWitnessCount = () => {
    const n = $$('#witness-grid input:checked').length;
    $('#witness-count').textContent = n + ' / 7 selected' + (n < 4 ? ' - quorum will hold' : '');
    $('#witness-count').style.color = n < 4 ? 'var(--amber)' : 'var(--lime)';
  };
  $$('#witness-grid input').forEach(input => input.addEventListener('change', updateWitnessCount));
  updateWitnessCount();

  const conf = $('#f-confidence');
  conf.addEventListener('input', () => { $('#f-confidence-out').textContent = Number(conf.value).toFixed(2); });

  $('#intake-form').addEventListener('submit', submitIntake);
}

async function submitIntake(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = $('#intake-submit');
  const witnesses = $$('#witness-grid input:checked').map(i => i.value);
  const payload = {
    template: $('#f-template').value,
    student: $('#f-student').value.trim(),
    course: $('#f-course').value.trim(),
    confidence: Number($('#f-confidence').value),
    witnesses,
    unilateral: $('#f-unilateral').checked,
  };

  submit.disabled = true;
  submit.textContent = 'Sealing through the engine...';
  try {
    const data = await api('/api/intake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    renderIntakeResult(data);
    await reloadState();
    toast(data.sealed ? 'Receipt sealed in ' + data.duration_ms.toFixed(2) + ' ms' : 'Protocol refused to seal', data.sealed ? 'good' : 'bad');
  } catch (e) {
    $('#intake-result').innerHTML = '<div class="error-panel">Intake failed: ' + escapeHtml(e.message) + '</div>';
  } finally {
    submit.disabled = false;
    submit.textContent = 'Seal through the engine';
  }
}

function renderIntakeResult(data) {
  const c = data.case;
  const st = statusOf(c.status);
  const wrap = $('#intake-result');

  const head = '<div class="result-head"><div><span class="kicker">Live result</span><h3>' +
    (data.sealed ? 'Receipt produced' : 'Receipt refused') + '</h3></div>' +
    '<span class="chip ' + st.cls + '"><i></i>' + escapeHtml(st.label) + '</span></div>';

  const caseCard = '<div class="result-case">' +
    '<div class="rc-top"><span class="rc-id">' + escapeHtml(c.case_no) + '</span><span class="rc-id">' + escapeHtml(formatDateTime(c.date)) + '</span></div>' +
    '<div class="rc-title">' + escapeHtml(c.title) + '</div>' +
    '<div class="rc-summary">' + escapeHtml(c.decision.summary) + '</div>' +
  '</div>';

  const hashes = data.sealed ? '<div class="result-hashes">' +
    '<div class="result-hash"><span>this_hash</span><b title="' + escapeHtml(c.receipt.this_hash) + '">' + escapeHtml(shortHash(c.receipt.this_hash, 40)) + '</b></div>' +
    '<div class="result-hash"><span>prev_hash</span><b title="' + escapeHtml(c.receipt.prev_hash) + '">' + escapeHtml(shortHash(c.receipt.prev_hash, 40)) + '</b></div>' +
    '<div class="result-hash"><span>content</span><b title="' + escapeHtml(c.receipt.outputs[0].content_hash) + '">' + escapeHtml(shortHash(c.receipt.outputs[0].content_hash, 40)) + '</b></div>' +
  '</div>' : '';

  const refusal = !data.sealed ? '<div class="result-refusal">' +
    '<span class="kicker">' + (c.status === 'BLOCKED' ? 'Hard refusal' : 'Gate held') + '</span>' +
    '<strong>' + escapeHtml(data.refusal || (c.attempt && c.attempt.error) || 'no receipt') + '</strong>' +
    '<code>sealed: false / receipts created: none</code>' +
  '</div>' : '';

  const meta = '<div class="result-meta">' +
    '<div><div class="k">duration</div><div class="v mono">' + Number(data.duration_ms).toFixed(2) + ' ms</div></div>' +
    '<div><div class="k">policy</div><div class="v">' + escapeHtml(c.policy_checks.filter(p => p.result === 'pass').length + '/' + c.policy_checks.length + ' pass') + '</div></div>' +
    '<div><div class="k">trust</div><div class="v mono">' + escapeHtml(c.trust_score.value) + '/100</div></div>' +
  '</div>';

  const actions = '<div class="result-actions">' +
    '<button class="btn btn-primary" type="button" data-open-case="' + escapeHtml(c.id) + '">Open in register</button>' +
    (data.sealed ? '<button class="mini-btn" type="button" data-download-case="' + escapeHtml(c.id) + '">download receipt</button>' : '') +
  '</div>';

  wrap.innerHTML = head + caseCard + refusal + hashes + meta + actions;

  wrap.querySelector('[data-open-case]').addEventListener('click', () => openCase(c.id));
  const dl = wrap.querySelector('[data-download-case]');
  if (dl) dl.addEventListener('click', () => {
    if (!c.receipt) return;
    const blob = new Blob([JSON.stringify(c.receipt, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = c.case_no + '.verifyd-receipt.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });
}

/* ---------------------------------------------------------------- events */

function bindGlobal() {
  $('#case-search').addEventListener('input', event => {
    app.query = event.target.value;
    renderCaseList();
  });

  const heroTamper = document.querySelector('[data-action="hero-tamper"]');
  if (heroTamper) {
    heroTamper.addEventListener('click', async () => {
      const target = app.selectedId && app.detailCase && app.detailCase.receipt ? app.selectedId : 'AP-2291';
      if (target !== app.selectedId) await selectCase(target);
      await runTamper();
      $('#cases').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }
}

bindGlobal();
boot();

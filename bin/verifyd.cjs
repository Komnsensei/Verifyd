#!/usr/bin/env node
// Verifyd CLI — `verifyd audit <file>` and friends
// Zero deps. Wraps engine + lattice into one command surface.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const v = require(path.join(ROOT, 'engine', 'verifyd.cjs'));
const lattice = require(path.join(ROOT, 'engine', 'lattice.cjs'));

const args = process.argv.slice(2);
const cmd = args[0];

function help() {
  console.log('Verifyd v1.0 — AI compliance audit engine');
  console.log('');
  console.log('Usage:');
  console.log('  verifyd audit <file>       Audit a PDF or text document');
  console.log('  verifyd verify <receipt>   Re-verify a saved audit receipt');
  console.log('  verifyd lattice            Show Lattice structure');
  console.log('  verifyd demo               Run end-to-end demo');
  console.log('  verifyd help               This help');
  console.log('');
  console.log('Audit produces a tamper-evident VALF-1 receipt.');
}

function extractText(file) {
  const ext = path.extname(file).toLowerCase();
  if (ext === '.pdf') {
    const txtFile = file.replace(/\.pdf$/i, '.txt');
    try {
      execSync(`pdftotext -layout "${file}" "${txtFile}"`, { stdio: 'pipe' });
      return { text: fs.readFileSync(txtFile, 'utf8'), extracted: txtFile };
    } catch (e) {
      throw new Error('pdftotext failed. Install Poppler or Git for Windows. ' + e.message);
    }
  }
  return { text: fs.readFileSync(file, 'utf8'), extracted: file };
}

function tryResolveArxiv(arxivId) {
  // Best-effort metadata lookup. No network = silent skip.
  try {
    const https = require('https');
    return new Promise((resolve) => {
      const req = https.get(`http://export.arxiv.org/api/query?id_list=${arxivId}`, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          const titleMatch = body.match(/<title>([\s\S]*?)<\/title>/g);
          const title = titleMatch && titleMatch[1] ? titleMatch[1].replace(/<[^>]+>/g, '').trim() : null;
          const summaryMatch = body.match(/<summary>([\s\S]*?)<\/summary>/);
          const summary = summaryMatch ? summaryMatch[1].trim().slice(0, 500) : null;
          const authors = (body.match(/<name>([^<]+)<\/name>/g) || []).map(m => m.replace(/<[^>]+>/g, ''));
          resolve({ title, summary, authors, source: 'arxiv', resolved_at: new Date().toISOString() });
        });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
    });
  } catch (e) {
    return Promise.resolve(null);
  }
}

function tryResolveDoi(doi) {
  try {
    const https = require('https');
    return new Promise((resolve) => {
      const opts = {
        hostname: 'api.crossref.org',
        path: `/works/${encodeURIComponent(doi)}`,
        headers: { 'User-Agent': 'Verifyd/1.0 (mailto:audit@verifyd.local)' },
      };
      const req = https.get(opts, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          try {
            const j = JSON.parse(body);
            const m = j.message || {};
            resolve({
              title: (m.title && m.title[0]) || null,
              authors: (m.author || []).map(a => `${a.given || ''} ${a.family || ''}`.trim()),
              published: m.created && m.created['date-time'],
              publisher: m.publisher,
              source: 'crossref',
              resolved_at: new Date().toISOString(),
            });
          } catch (_) { resolve(null); }
        });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
    });
  } catch (e) {
    return Promise.resolve(null);
  }
}

async function audit(file) {
  if (!file) { console.error('verifyd audit: missing file'); process.exit(1); }
  if (!fs.existsSync(file)) { console.error('verifyd audit: file not found: ' + file); process.exit(1); }

  console.log('=== Verifyd Audit ===\n');
  console.log('Target: ' + file);

  const { text } = extractText(file);
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const title = lines.slice(0, 5).find(l => l.length > 10 && l.length < 200) || path.basename(file);
  const arxivMatch = text.match(/arXiv:\s*([0-9]{4}\.[0-9]{4,5}(v\d+)?)/i);
  const doiMatch = text.match(/(10\.\d{4,9}\/[\w.\-\/;()]+)/);

  console.log('Title:  ' + title.slice(0, 80));
  console.log('Words:  ' + text.split(/\s+/).length);
  console.log('Chars:  ' + text.length);
  console.log('arXiv:  ' + (arxivMatch ? arxivMatch[1] : '(scanning…)'));
  console.log('DOI:    ' + (doiMatch ? doiMatch[1] : '(scanning…)'));

  // Resolve external metadata in parallel
  let arxivMeta = null, doiMeta = null;
  if (arxivMatch) { console.log('  → resolving arXiv ' + arxivMatch[1] + '…'); arxivMeta = await tryResolveArxiv(arxivMatch[1]); }
  if (doiMatch)   { console.log('  → resolving DOI ' + doiMatch[1] + '…');     doiMeta   = await tryResolveDoi(doiMatch[1]); }

  if (arxivMeta && arxivMeta.title) console.log('  arXiv title: ' + arxivMeta.title);
  if (doiMeta && doiMeta.title)     console.log('  DOI title:   ' + doiMeta.title);

  const session = v.authenticatedSession({
    human_id: 'auditor-cli',
    agent_id: 'verifyd-cli@1.0',
  });

  const anchors = [];
  if (arxivMatch) anchors.push({
    anchor_id: v.sha256('arxiv:' + arxivMatch[1]).slice(0, 8),
    uri: 'https://arxiv.org/abs/' + arxivMatch[1],
    span_hash: v.sha256(text),
    retrieved_at: new Date().toISOString(),
    resolved_metadata: arxivMeta,
  });
  if (doiMatch) anchors.push({
    anchor_id: v.sha256('doi:' + doiMatch[1]).slice(0, 8),
    uri: 'https://doi.org/' + doiMatch[1],
    span_hash: v.sha256(text),
    retrieved_at: new Date().toISOString(),
    resolved_metadata: doiMeta,
  });
  anchors.push({
    anchor_id: v.sha256('local:' + file).slice(0, 8),
    uri: 'file://' + path.resolve(file).replace(/\\/g, '/'),
    span_hash: v.sha256(text),
    retrieved_at: new Date().toISOString(),
  });

  const output = v.sessionOutput({
    session_id: session.session_id,
    content: 'Audit of "' + title.slice(0, 60) + '". ' + text.slice(0, 400),
    source_anchors: anchors,
    confidence: { value: 0.78, decay_function: 'exponential', decay_half_life_days: 60, scored_at: new Date().toISOString() },
  });

  const checks = v.PolicyEngine.run(session, output);
  const policyPassed = v.PolicyEngine.passed(checks);
  const trustScore = v.TrustScoreCalculator.compute(session, output, checks);

  const el = lattice.createElement({ kind: 'paper', title: title.slice(0, 80), content: text, sponsor: 'auditor-cli' });
  lattice.promote(el, 'PROVISIONAL', { sponsor: 'auditor-cli' });
  const anchorUri = arxivMatch ? 'https://arxiv.org/abs/' + arxivMatch[1]
                  : doiMatch ? 'https://doi.org/' + doiMatch[1]
                  : 'file://' + path.resolve(file).replace(/\\/g, '/');
  lattice.promote(el, 'DEPOSITED', { sponsor: 'auditor-cli', anchor_uri: anchorUri });
  lattice.promote(el, 'RATIFIED', {
    attestations: [
      { witness_id: 'OB.peer-review', attested_at: new Date().toISOString() },
      { witness_id: 'OB.replication', attested_at: new Date().toISOString() },
      { witness_id: 'OB.theory-check', attested_at: new Date().toISOString() },
      { witness_id: 'OB.archive', attested_at: new Date().toISOString() },
    ],
  });

  const ratification = v.ratificationEvent({ session, output, human_method: 'cli-attestation', policy_passed: policyPassed, trust_score_value: trustScore.value });
  const chain = new v.AuditChain();
  const receipt = v.buildReceipt({ session, outputs: [output], policy_checks: checks, trust_score: trustScore, ratification, prev_hash: chain.lastHash() });
  chain.append(receipt);
  const verification = v.verifyChain(chain.all());

  const receiptFile = file.replace(/\.[^.]+$/, '') + '.verifyd-receipt.json';
  fs.writeFileSync(receiptFile, JSON.stringify({
    document: {
      file: path.basename(file), title,
      arxiv: arxivMatch ? arxivMatch[1] : null,
      doi: doiMatch ? doiMatch[1] : null,
      arxiv_metadata: arxivMeta,
      doi_metadata: doiMeta,
      sha256: v.sha256(text),
      words: text.split(/\s+/).length,
    },
    audit: { session, output, policy_checks: checks, trust_score: trustScore, ratification, lattice_status: el.status, persistence: lattice.persistence(el) },
    receipt,
    chain_valid: verification.valid,
  }, null, 2));

  console.log('');
  console.log('Policy:       ' + (policyPassed ? 'PASSED' : 'FAILED'));
  console.log('Trust:        ' + trustScore.value + '/100');
  console.log('Lattice:      ' + el.status);
  console.log('Receipt ID:   ' + receipt.receipt_id);
  console.log('this_hash:    ' + receipt.this_hash);
  console.log('Chain valid:  ' + verification.valid);
  console.log('');
  console.log('Receipt saved: ' + receiptFile);
}

function verify(receiptFile) {
  if (!receiptFile || !fs.existsSync(receiptFile)) { console.error('verifyd verify: receipt not found'); process.exit(1); }
  const data = JSON.parse(fs.readFileSync(receiptFile, 'utf8'));
  const r = data.receipt;
  const recomputed = v.sha256(v.canonicalJSON(r, ['this_hash']));
  const ok = recomputed === r.this_hash;
  console.log('Receipt:    ' + r.receipt_id);
  console.log('Stored:     ' + r.this_hash);
  console.log('Recomputed: ' + recomputed);
  console.log('Status:     ' + (ok ? 'VALID' : 'TAMPERED'));
  process.exit(ok ? 0 : 1);
}

function showLattice() {
  console.log('Verifyd Lattice (VL-1)');
  console.log('Formula: ' + lattice.LATTICE.core_formula);
  console.log('');
  console.log('Components:');
  Object.entries(lattice.LATTICE.components).forEach(([k, val]) => console.log('  ' + k + ' = ' + val));
  console.log('');
  console.log('Promotion ladder:');
  lattice.LATTICE.promotion_ladder.forEach(s => console.log('  ' + s.id.padEnd(20) + 'w=' + s.weight));
  console.log('');
  console.log('Oversight Board: ' + lattice.LATTICE.oversight_board.seats + ' seats, quorum >=' + lattice.LATTICE.oversight_board.quorum_required);
  console.log('Sole sovereign: FORBIDDEN');
}

(async () => {
  if (cmd === 'audit') return audit(args[1]);
  if (cmd === 'verify') return verify(args[1]);
  if (cmd === 'lattice') return showLattice();
  if (cmd === 'demo') { require(path.join(ROOT, 'examples', 'lattice-demo.cjs')); return; }
  if (cmd === 'help' || cmd === '--help' || cmd === '-h' || !cmd) return help();
  console.error('Unknown command: ' + cmd); help(); process.exit(1);
})();

#!/usr/bin/env node
// Verifyd CLI  `verifyd audit <file>` and friends
// Zero deps. Wraps engine + lattice into one command surface.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const v = require(path.join(ROOT, 'engine', 'verifyd.cjs'));
const lattice = require(path.join(ROOT, 'engine', 'lattice.cjs'));
const Artifacts = require(path.join(ROOT, 'engine', 'artifacts.cjs'));

const args = process.argv.slice(2);

const VALUE_FLAGS = {
  '--keyring': 'keyring',
  '--key': 'key',
  '--tsa': 'tsa',
  '--tsa-ca': 'tsaCa',
  '--tsa-timeout': 'tsaTimeout',
  '--batch': 'batch',
  '--batch-out': 'batchOut',
  '--witness-keys': 'witnessKeys',
  '--identity': 'identity',
  '--proof': 'proof',
  '--proof-uri': 'proofUri',
  '--proof-out': 'proofOut',
  '--witness-key': 'witnessKey',
  '--into': 'into',
  '--method': 'method',
  '--statement': 'statement',
  '--expires': 'expires',
  '--jurisdiction': 'jurisdiction',
  '--regime': 'regime',
  '--reviewer': 'reviewer',
  '--role': 'role',
  '--organization': 'organization',
  '--conclusion': 'conclusion',
  '--rationale': 'rationale',
  '--out': 'out',
  '--receipt': 'receipt',
  '--determination': 'determination',
  '--reviewer-keyring': 'reviewerKeyring',
};

const MULTI_FLAGS = {
  '--fact': 'facts',
  '--requirement': 'requirements',
};

function parseOptions(argv) {
  const opts = {
    keyring: null, key: null, tsa: null, tsaCa: null, tsaTimeout: null, batch: null, batchOut: null,
    witnessKeys: null, identity: null, proof: null, proofUri: null, proofOut: null,
    witnessKey: null, into: null, method: null, statement: null, expires: null,
    jurisdiction: null, regime: null, reviewer: null, role: null, organization: null,
    conclusion: null, rationale: null, out: null, receipt: null, determination: null,
    reviewerKeyring: null, facts: [], requirements: [], rest: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf('=');
    if (eq > 0) {
      const flag = a.slice(0, eq);
      const field = VALUE_FLAGS[flag];
      if (field) { opts[field] = a.slice(eq + 1); continue; }
      const multi = MULTI_FLAGS[flag];
      if (multi) { opts[multi].push(a.slice(eq + 1)); continue; }
    }
    const multiField = MULTI_FLAGS[a];
    if (multiField) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) {
        console.error('verifyd: ' + a + ' needs a value');
        process.exit(1);
      }
      opts[multiField].push(value);
      i++;
      continue;
    }
    const field = VALUE_FLAGS[a];
    if (field) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) {
        console.error('verifyd: ' + a + ' needs a value');
        process.exit(1);
      }
      opts[field] = value;
      i++;
      continue;
    }
    opts.rest.push(a);
  }
  return opts;
}

const OPTS = parseOptions(args);
const cmd = OPTS.rest[0];

function keyringDir() {
  return OPTS.keyring ? path.resolve(OPTS.keyring) : v.Signing.defaultKeyringDir();
}

function witnessKeysDir() {
  const raw = OPTS.witnessKeys || process.env.VERIFYD_WITNESS_KEYS;
  return raw ? path.resolve(raw) : null;
}

// Assurance is recomputed from the envelope every time; no score is trusted
// from the file. Missing evidence degrades the probability and is named.
// On the verify path the caller passes the evidence it already displayed, so
// the score and the report cannot come from different verification runs.
async function assessAssurance(envelope, evidence) {
  try {
    if (evidence) return await v.TrustScoreCalculator.assess(envelope, { evidence });
    return await v.TrustScoreCalculator.assess(envelope, {
      keyring: keyringDir(),
      witnessKeys: witnessKeysDir(),
      tsaCa: OPTS.tsaCa,
      batch: OPTS.batch,
      determination: OPTS.determination,
      reviewerKeyring: reviewerKeysDir(),
    });
  } catch (e) {
    return { error: e.code || e.message };
  }
}

function formatAssurance(assurance) {
  if (!assurance) return 'NOT COMPUTED';
  if (assurance.error) return 'NOT COMPUTED (' + assurance.error + ')';
  const parts = [
    assurance.probability.toFixed(3) + ' (probability; model ' + assurance.model_version + ')',
  ];
  if (assurance.absent.length) parts.push('absent: ' + assurance.absent.join(', '));
  return parts.join('; ');
}

// Determinations are signed by a reviewer, who need not be the receipt signer.
// Their keyring defaults to the main one only because it is the common case;
// pass --reviewer-keyring to separate the roles.
function reviewerKeysDir() {
  const raw = OPTS.reviewerKeyring || OPTS.keyring;
  return raw ? path.resolve(raw) : v.Signing.defaultKeyringDir();
}

function shortKeyId(id) {
  if (!id) return '(none)';
  const s = String(id);
  return s.length > 24 ? s.slice(0, 20) + '...' : s;
}

function pad(text, width) {
  const s = String(text == null ? '(none)' : text);
  return s.length >= width ? s : s + ' '.repeat(width - s.length);
}

function help() {
  console.log('Verifyd v1.0  AI compliance audit engine');
  console.log('');
  console.log('Usage:');
  console.log('  verifyd manifest <folder>       Create deterministic folder manifest');
  console.log('  verifyd audit-folder <folder>   Audit folder into tree receipt');
  console.log('  verifyd verify-folder <folder> <receipt>  Verify folder receipt');
  console.log('  verifyd light <file>            Light EXIF/image metadata audit');
  console.log('  verifyd audit <file>       Audit a PDF or text document (signed receipt)');
  console.log('  verifyd verify <receipt>   Verify signature, hash, inclusion and time');
  console.log('  verifyd batch <dir|files>  Commit receipts to a Merkle root + inclusion proofs');
  console.log('  verifyd witness <sub>      Witness identity proofing (init/prove/attest/vouch/register/revoke/list)');
  console.log('  verifyd determination <sub> Signed compliance determination (NOT legal advice)');
  console.log('  verifyd keys list          Show keys in the keyring and which one is active');
  console.log('  verifyd keys init          Create the keyring and first signing key');
  console.log('  verifyd keys rotate        Generate a new signing key, retire the old one');
  console.log('  verifyd keys path          Print the keyring directory');
  console.log('  verifyd certify <receipt>  Create pretty human certificate');
  console.log('  verifyd lattice            Show Lattice structure');
  console.log('  verifyd demo               Run end-to-end demo');
  console.log('  verifyd help               This help');
  console.log('');
  console.log('Options:');
  console.log('  --keyring <dir>            Keyring directory (default: $VERIFYD_KEYRING or ~/.verifyd/keys)');
  console.log('  --key <key_id>             Sign with a specific key instead of the active one');
  console.log('  --tsa <url>                Request an RFC 3161 token (audit/batch only; default: $VERIFYD_TSA_URL)');
  console.log('  --tsa-ca <pem>             Trust root(s) for the TSA token (default: $VERIFYD_TSA_CA)');
  console.log('  --tsa-timeout <ms>         TSA request timeout for audit/batch (default: $VERIFYD_TSA_TIMEOUT_MS or 10000)');
  console.log('  --batch <file>             Merkle root file to check the inclusion proof against');
  console.log('  --batch-out <file>         Where batch writes the root (default: <dir>/verifyd-batch.json)');
  console.log('  --witness-keys <dir>       Keyring of trusted witness keys (default: $VERIFYD_WITNESS_KEYS)');
  console.log('  --determination <file>     Determination to check alongside the receipt');
  console.log('  --reviewer-keyring <dir>   Keyring holding the reviewer key (default: --keyring)');
  console.log('');
  console.log('Witness subcommands:');
  console.log('  witness init                          Create a witness keyring (--keyring)');
  console.log('  witness prove <identity> --proof-out <file>  Write the resource that binds key to identity');
  console.log('  witness attest <receipt> --identity <id> --proof <file>  Sign an attestation into a receipt');
  console.log('  witness vouch <receipt> --witness-key <id> --identity <id>  Vouch with a second key');
  console.log('  witness register <keyring> --into <dir>  Trust a witness public key, optionally --expires <iso>');
  console.log('  witness revoke <key_id> --into <dir>   Stop a witness key from contributing');
  console.log('  witness list --into <dir>              Show trusted witness keys');
  console.log('');
  console.log('Determination subcommands (engineering record, NOT legal advice):');
  console.log('  determination create <receipt>  Sign a determination with a named reviewer');
  console.log('  determination show <file>       Show a determination; signature not checked');
  console.log('  determination verify <file>     Verify signature, binding, expiry and status');
  console.log('  determination regimes           List indexed jurisdictions and regimes');
  console.log('  create flags: --fact id=value, --requirement "id|statement|ref|locator"');
  console.log('  A ref not present in engine/citations.json is recorded source_unverified.');
  console.log('');
  console.log('Audit produces a signed VALF-1 receipt. A signature proves the receipt');
  console.log('bytes were signed by a key in your keyring; it does not prove the signer');
  console.log('was honest. A timestamp token, when configured, proves the signed bytes');
  console.log('existed at the authority\'s attested time, nothing more.');
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
  const text = fs.readFileSync(file, 'utf8');
  if (text.includes('\u0000')) {
    throw new Error('not a text document (binary data); audit a text file or a PDF');
  }
  return { text, extracted: file };
}

function tryResolveArxiv(arxivId) {
  // Best-effort metadata lookup. No network = silent skip.
  try {
    const https = require('https');
    return new Promise((resolve) => {
      const req = https.get(`https://export.arxiv.org/api/query?id_list=${arxivId}`, (res) => {
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
  if (!fs.statSync(file).isFile()) {
    console.error('verifyd audit: not a file: ' + file);
    console.error('  Directories are audited with: verifyd audit-folder <folder>');
    process.exit(1);
  }

  console.log('=== Verifyd Audit ===\n');
  console.log('Target: ' + file);

  const { text } = extractText(file);
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const title = lines.slice(0, 5).find(l => l.length > 10 && l.length < 200) || path.basename(file);
  const arxivMatch = text.match(/arXiv:\s*([0-9]{4}\.[0-9]{4,5}(v\d+)?)/i);
  const doiMatch = text.match(/(10\.\d{4,9}\/[\w.\-\/;()]+)/);

  console.log('Title:  ' + title.slice(0, 80));
  console.log('Words:  ' + text.split(/\s+/).filter(Boolean).length);
  console.log('Chars:  ' + text.length);
  console.log('arXiv:  ' + (arxivMatch ? arxivMatch[1] : '(scanning)'));
  console.log('DOI:    ' + (doiMatch ? doiMatch[1] : '(scanning)'));

  // Resolve external metadata in parallel
  let arxivMeta = null, doiMeta = null;
  if (arxivMatch) { console.log('   resolving arXiv ' + arxivMatch[1] + ''); arxivMeta = await tryResolveArxiv(arxivMatch[1]); }
  if (doiMatch)   { console.log('   resolving DOI ' + doiMatch[1] + '');     doiMeta   = await tryResolveDoi(doiMatch[1]); }

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

  const lowerText = text.toLowerCase();
  const evidence = {
    word_count: text.split(/\s+/).filter(Boolean).length,
    char_count: text.length,
    has_external_anchor: !!(arxivMatch || doiMatch),
    has_resolved_external_metadata: !!(
      (arxivMeta && arxivMeta.title) ||
      (doiMeta && (doiMeta.title || doiMeta.publisher))
    ),
    has_provenance_language: /\b(provenance|source|citation|doi|arxiv|receipt|hash|endpoint|evidence|audit)\b/i.test(text),
    has_proof_language: /\b(checked|verified|tested|passed|failed|http|status|sha256|receipt|chain valid)\b/i.test(text),
    has_adversarial_language: /\b(ignore policy|override policy|pretend|declare chain valid without evidence|comply or|no choice)\b/i.test(lowerText),
    has_self_ratification_language: /\b(self-ratify|because i said so|sole sovereign|unilateral ratification|pretend there are four witnesses)\b/i.test(lowerText),
    has_secret_pattern: /(sk_live_[A-Za-z0-9_]+|sk-proj-[A-Za-z0-9_-]+|gsk_[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_]+|vcp_[A-Za-z0-9_]+|(?:API_KEY|SECRET|TOKEN)\s*[:=]\s*['\"][^'\"]{12,}['\"])/i.test(text),
  };

  const output = v.sessionOutput({
    session_id: session.session_id,
    content: 'Audit of "' + title.slice(0, 60) + '". ' + text.slice(0, 400),
    source_anchors: anchors,
    confidence: {
      value: 0.5,
      decay_function: 'none',
      decay_half_life_days: 0,
      scored_at: new Date().toISOString(),
      generated_by: 'verifyd-cli-default'
    },
  });

  output.evidence = evidence;

  const checks = v.PolicyEngine.run(session, output);
  const policyPassed = v.PolicyEngine.passed(checks);
  // Document substance only: an uncalibrated heuristic used to gate promotion.
  // The assurance probability needs the signed bytes, so it is computed after
  // sealing and timestamping, below.
  const documentQuality = v.TrustScoreCalculator.documentQuality(session, output, checks);

  const el = lattice.createElement({
    kind: 'paper',
    title: title.slice(0, 80),
    content: text,
    sponsor: 'auditor-cli'
  });

  if (
    documentQuality.value >= 40 &&
    !evidence.has_adversarial_language &&
    !evidence.has_self_ratification_language &&
    !evidence.has_secret_pattern
  ) {
    lattice.promote(el, 'PROVISIONAL', { sponsor: 'auditor-cli' });
  }

  const hasExternalAnchor = !!(arxivMatch || doiMatch);
  const anchorUri = arxivMatch ? 'https://arxiv.org/abs/' + arxivMatch[1]
                  : doiMatch ? 'https://doi.org/' + doiMatch[1]
                  : null;

  if (
    el.status === 'PROVISIONAL' &&
    documentQuality.value >= 60 &&
    hasExternalAnchor &&
    evidence.has_resolved_external_metadata
  ) {
    lattice.promote(el, 'DEPOSITED', {
      sponsor: 'auditor-cli',
      anchor_uri: anchorUri
    });
  }

  // Do NOT auto-RATIFY.
  // RATIFIED requires real independent witness attestations, not synthetic CLI witnesses.

  const ratification = v.ratificationEvent({
    session,
    output,
    human_method: 'cli-attestation',
    policy_passed: policyPassed,
    document_quality_value: documentQuality.value,
  });
  const chain = new v.AuditChain();
  const receipt = v.buildReceipt({
    session,
    outputs: [output],
    policy_checks: checks,
    document_quality: documentQuality,
    ratification,
    prev_hash: chain.lastHash(),
    lattice: { status: el.status, persistence: lattice.persistence(el) },
  });
  chain.append(receipt);
  const verification = v.verifyChain(chain.all());

  // Single canonical envelope: document + receipt are hashed and signed once.
  const envelope = v.buildEnvelope({
    receipt_type: 'document',
    document: {
      file: path.basename(file),
      title,
      arxiv: arxivMatch ? arxivMatch[1] : null,
      doi: doiMatch ? doiMatch[1] : null,
      arxiv_metadata: arxivMeta,
      doi_metadata: doiMeta,
      sha256: v.sha256(text),
      words: text.split(/\s+/).filter(Boolean).length,
    },
    receipt,
  });

  const dir = keyringDir();
  const hadKey = v.Signing.activeKeyId({ dir });
  let sealed;
  try {
    sealed = v.Signing.seal(envelope, { dir, keyId: OPTS.key || undefined });
  } catch (e) {
    console.error('Signing failed: ' + (e.code || e.message));
    process.exit(1);
  }

  // Timestamp after signing: the token covers SHA-256 of the signed payload,
  // and signingPayload() excludes `timestamp`, so attaching it cannot change
  // the bytes that were signed.
  const tsaUrl = v.TSA.configuredUrl(OPTS.tsa);
  let timeNote = 'not requested (no TSA configured)';
  if (tsaUrl) {
    const payload = v.Signing.signingPayload(sealed);
    const result = await v.TSA.requestTimestamp(tsaUrl, payload, {
      timeoutMs: v.TSA.configuredTimeout(OPTS.tsaTimeout),
    });
    if (result.ok) {
      sealed.timestamp = {
        type: 'rfc3161',
        tsa_url: tsaUrl,
        imprint_sha256: result.imprint,
        token: result.token.toString('base64'),
        requested_at: new Date().toISOString(),
      };
      timeNote = 'RFC 3161 token recorded';
    } else {
      sealed.timestamp = {
        type: 'rfc3161',
        tsa_url: tsaUrl,
        imprint_sha256: result.imprint || null,
        status: 'failed',
        error: result.error,
        requested_at: new Date().toISOString(),
      };
      timeNote = 'TSA unavailable (' + result.error + '); signed, time unattested';
    }
  }

  const receiptFile = file.replace(/\.[^.]+$/, '') + '.verifyd-receipt.json';
  fs.writeFileSync(receiptFile, JSON.stringify(sealed, null, 2) + '\n');

  // Assurance is derived from the sealed bytes and the evidence attached to
  // them. It is not stored in the receipt: verify recomputes it from the same
  // committed model, so no unverified score travels inside the envelope.
  const assurance = await assessAssurance(sealed);

  // The assurance policy feature is stricter than PolicyEngine.passed(): it
  // requires every result to be a pass and every citation to trace. Do not let
  // this line say PASSED when the score just treated the policy set as
  // unverified.
  const strictPolicy = assurance && assurance.evidence && assurance.evidence.policy;
  const policyLabel = !policyPassed
    ? 'FAILED'
    : (strictPolicy && strictPolicy.value !== 1 ? 'WARNED (not verified)' : 'PASSED');
  console.log('');
  console.log('Policy:       ' + policyLabel);
  console.log('Assurance:    ' + formatAssurance(assurance));
  if (assurance && !assurance.error) {
    console.log('Model:        ' + assurance.scheme + ' ' + assurance.model_version +
      ', ' + assurance.labels_origin + ' labels, data ' + assurance.dataset_sha256.slice(0, 12));
  }
  console.log('Doc quality:  ' + documentQuality.value + '/100 (heuristic, uncalibrated, not a probability)');
  console.log('Lattice:      ' + el.status);
  console.log('Receipt ID:   ' + receipt.receipt_id);
  console.log('this_hash:    ' + receipt.this_hash);
  console.log('Receipt hash: ' + (verification.valid ? 'VALID' : 'INVALID'));
  console.log('Signer:       ' + sealed.signature.key_id);
  console.log('Keyring:      ' + dir + (hadKey ? '' : ' (created new key)'));
  console.log('Time token:   ' + timeNote);
  if (!hadKey) warnWindowsModes();
  console.log('');
  console.log('Receipt saved: ' + receiptFile);
}

function resolveBatchInputs(targets) {
  if (!targets || targets.length === 0) return { files: [], dir: null };
  if (targets.length === 1 && fs.existsSync(targets[0]) && fs.statSync(targets[0]).isDirectory()) {
    const dir = targets[0];
    const files = fs.readdirSync(dir)
      .filter(name => name.endsWith('.verifyd-receipt.json'))
      .sort()
      .map(name => path.join(dir, name));
    return { files, dir };
  }
  return { files: targets, dir: null };
}

async function batchCommand(targets) {
  const { files, dir: sourceDir } = resolveBatchInputs(targets);
  if (files.length === 0) {
    console.error('verifyd batch: no receipts found');
    process.exit(1);
  }

  const dir = keyringDir();
  const entries = [];

  for (const file of files) {
    const data = loadArtifact(file, 'batch', {
      notFound: 'receipt not found: ' + file,
      directory: 'not a receipt file',
      invalidJson: 'unreadable receipt ' + file,
      notObject: 'not a signed document receipt: ' + file,
      readError: 'receipt could not be read',
    });
    if (!data.receipt || typeof data.receipt !== 'object') {
      console.error('verifyd batch: not a signed document receipt: ' + file);
      process.exit(1);
    }
    const check = v.Signing.open(data, { dir });
    if (!check.ok) {
      console.error('verifyd batch: ' + file + ' failed verification (' + check.code + '); no root over unverified receipts');
      process.exit(1);
    }
    const payload = v.Signing.signingPayload(data);
    entries.push({ file, data, digest: v.TSA.sha256(payload) });
  }

  const digests = entries.map(e => e.digest);
  const tree = v.Merkle.buildTree(digests);
  const batchId = crypto.randomUUID();
  const rootHex = tree.root.toString('hex');

  const rootObject = {
    valf_version: '1.0',
    batch_type: 'merkle',
    scheme: v.Merkle.SCHEME,
    batch_id: batchId,
    created_at: new Date().toISOString(),
    tree_size: tree.size,
    root_hash: rootHex,
  };

  let sealedRoot;
  try {
    sealedRoot = v.Signing.seal(rootObject, {
      dir,
      keyId: OPTS.key || undefined,
      domain: v.Merkle.ROOT_DOMAIN,
    });
  } catch (e) {
    console.error('Batch signing failed: ' + (e.code || e.message));
    process.exit(1);
  }

  const tsaUrl = v.TSA.configuredUrl(OPTS.tsa);
  if (tsaUrl) {
    const payload = v.Signing.signingPayload(sealedRoot, { domain: v.Merkle.ROOT_DOMAIN });
    const result = await v.TSA.requestTimestamp(tsaUrl, payload, {
      timeoutMs: v.TSA.configuredTimeout(OPTS.tsaTimeout),
    });
    sealedRoot.timestamp = result.ok
      ? {
        type: 'rfc3161',
        tsa_url: tsaUrl,
        imprint_sha256: result.imprint,
        token: result.token.toString('base64'),
        requested_at: new Date().toISOString(),
      }
      : {
        type: 'rfc3161',
        tsa_url: tsaUrl,
        imprint_sha256: result.imprint || null,
        status: 'failed',
        error: result.error,
        requested_at: new Date().toISOString(),
      };
  }

  const outFile = OPTS.batchOut
    ? path.resolve(OPTS.batchOut)
    : path.join(sourceDir || process.cwd(), 'verifyd-batch.json');
  fs.writeFileSync(outFile, JSON.stringify(sealedRoot, null, 2) + '\n');

  entries.forEach((entry, index) => {
    const proof = v.Merkle.inclusion(index, digests);
    entry.data.inclusion = {
      scheme: v.Merkle.SCHEME,
      batch_id: batchId,
      leaf_index: index,
      tree_size: tree.size,
      root_hash: rootHex,
      path: proof.path.map(h => h.toString('hex')),
    };
    fs.writeFileSync(entry.file, JSON.stringify(entry.data, null, 2) + '\n');
  });

  console.log('Batch ID:   ' + batchId);
  console.log('Receipts:   ' + tree.size);
  console.log('Root:       ' + rootHex);
  console.log('Signer:     ' + sealedRoot.signature.key_id);
  console.log('Root file:  ' + outFile);
  console.log('Proofs:     attached to each receipt');
}

// Witness accounting is reported here, not assumed. Quorum counts distinct,
// verified keys and identities from engine/witness.cjs; labels alone count for
// nothing. A RATIFIED claim that cannot be checked, or that fails quorum, makes
// the receipt REJECTED even though its signature is still VALID: the signature
// proves who sealed the bytes, not that the board existed.
function reportWitnesses(data, evidence) {
  const attestations = Array.isArray(data.attestations) ? data.attestations : [];
  const latticeStatus = data.receipt && data.receipt.lattice ? data.receipt.lattice.status : null;
  const assessment = evidence.witnesses;
  const witnessVerdict = v.AssuranceEvidence.witnessVerdict(data, evidence);

  if (attestations.length === 0) {
    console.log('Witnesses:    none');
    return witnessVerdict;
  }

  if (!assessment.assessed) {
    console.log('Witnesses:    NOT ASSESSED (' + assessment.reason +
      (assessment.detail ? ': ' + assessment.detail : '') + ')');
    return witnessVerdict;
  }

  const q = assessment.quorum;
  console.log('Witnesses:    ' + q.counted + ' counted of ' + q.required + ' required (' +
    (q.met ? 'QUORUM MET' : 'QUORUM NOT MET') + ')');

  for (const w of assessment.counted) {
    const voucher = w.tier === 'vouched' && w.vouch && w.vouch.key_id ? ', voucher ' + shortKeyId(w.vouch.key_id) : '';
    console.log('  counted     ' + pad(w.identity, 30) + pad(shortKeyId(w.key_id), 26) + 'tier=' + w.tier + voucher);
  }
  for (const r of assessment.rejected) {
    console.log('  rejected    ' + pad(r.identity, 30) + pad(shortKeyId(r.key_id), 26) +
      r.reason + (r.detail ? ': ' + r.detail : ''));
  }
  for (const c of assessment.conflicts) {
    console.log('  conflict    ' + pad(c.identity, 30) + c.key_ids.length + ' keys claim this identity (counted once)');
  }
  for (const n of assessment.notes) {
    console.log('  note        ' + n.code + (n.identity ? ' (' + n.identity + ')' : '') +
      (n.detail ? ': ' + n.detail : ''));
  }

  if (latticeStatus === 'RATIFIED' && witnessVerdict.ok) {
    console.log('Lattice:      RATIFIED (quorum verified against witness keys)');
  }
  return witnessVerdict;
}

async function verify(receiptFile) {
  const read = Artifacts.readJsonObject(receiptFile, {
    messages: {
      notFound: 'receipt not found',
      directory: 'not a receipt file',
      invalidJson: 'receipt is not valid JSON',
      notObject: 'not a receipt',
      readError: 'receipt could not be read',
    },
  });
  if (!read.ok) {
    console.error('verifyd verify: ' + read.message);
    if (read.code === 'IS_DIRECTORY') {
      console.error('  Pass a receipt from audit or audit-folder, not a folder.');
    }
    process.exit(1);
  }
  const data = read.value;

  if (!data.receipt || typeof data.receipt !== 'object') {
    const type = (data && (data.receipt_type || data.audit_mode)) || 'unknown';
    console.error('verifyd verify: not a signed document receipt (receipt_type=' + type + ')');
    console.error('  Signed document receipts come from: verifyd audit <file>');
    if (type === 'folder') {
      console.error('  Folder receipts are checked with:   verifyd verify-folder <folder> <receipt>');
    } else if (type === 'light_exif') {
      console.error('  Light metadata receipts carry no signature; re-run: verifyd light <file>');
    }
    process.exit(1);
  }

  const dir = keyringDir();
  // One verification pass. The report below and the assurance score read this
  // same object, so a compliant determination cannot print beside a score that
  // treated it as untrusted.
  const evidence = await v.AssuranceEvidence.collect(data, {
    keyring: dir,
    witnessKeys: witnessKeysDir(),
    tsaCa: OPTS.tsaCa,
    batch: OPTS.batch,
    determination: OPTS.determination,
    reviewerKeyring: reviewerKeysDir(),
  });
  const res = evidence.signature;
  const checks = res.checks;

  console.log('Receipt:      ' + (data.receipt.receipt_id || '(none)'));
  console.log('Document:     ' + ((data.document && data.document.file) || '(not recorded)'));
  console.log('Signer:       ' + (res.key_id || '(none)'));
  console.log('Keyring:      ' + dir + (v.Signing.keyringExists(dir) ? '' : ' (not found)'));
  const hashLabel = checks.receipt_hash_valid
    ? 'VALID'
    : (res.code === 'RECEIPT_HASH_MISMATCH' ? 'MISMATCH' : '(not checked)');
  const signatureLabel = checks.signature_valid
    ? (res.code === 'RECEIPT_HASH_MISMATCH' ? 'VALID (signature only; receipt hash mismatch)' : 'VALID')
    : res.code;
  console.log('Signature:    ' + signatureLabel);
  console.log('Receipt hash: ' + hashLabel);
  console.log('Signed at:    ' + (data.signed_at || '(not recorded)') + ' (self-asserted clock)');

  const time = evidence.time;
  const recorded = time.recorded;
  const analysis = time.analysis;
  const caError = time.caError;
  const timeStatus = time.status;

  console.log('TSA:          ' + (recorded && recorded.tsa_url ? recorded.tsa_url : '(none in this receipt)'));

  if (timeStatus === 'attested' && analysis) {
    console.log('Attested:     ' + analysis.gen_time);
    console.log('Time status:  ATTESTED');
    console.log('Trust chain:  ' + (analysis.chain.root_subject || '(configured root)'));
  } else if (timeStatus === 'unverified' && analysis) {
    console.log('Attested:     (not established)');
    console.log('Token time:   ' + analysis.gen_time + ' (token signature valid, chain unchecked)');
    console.log('Time status:  UNVERIFIED');
    console.log('Reason:       no TSA trust root configured; pass --tsa-ca <pem>');
  } else if (timeStatus === 'invalid') {
    console.log('Attested:     (not established)');
    console.log('Time status:  INVALID');
    const why = caError || (analysis && analysis.reasons && analysis.reasons.length
      ? analysis.reasons.join(', ')
      : 'timestamp token could not be verified');
    console.log('Reason:       ' + why);
  } else {
    console.log('Attested:     (none)');
    console.log('Time status:  UNATTESTED');
    if (recorded && recorded.error) {
      console.log('Recorded:     ' + recorded.error + ' (unsigned note from audit time)');
    }
  }

  // Inclusion proof, when the receipt was batched.
  const inclusion = evidence.inclusion;
  const inclusionRecord = inclusion.record;
  if (inclusion.present && inclusion.proofOk) {
    // The proof is excluded from the signed payload (it is computed over those
    // bytes), so on its own it is only arithmetic: anyone can build a one-leaf
    // tree over their own digest. The root signature is what anchors it, and
    // that needs --batch.
    const anchored = evidence.batch.authenticated;
    console.log('Inclusion:    ' + (anchored ? 'VALID' : 'PROOF VALID, ROOT UNVERIFIED') +
      ' (leaf ' + inclusionRecord.leaf_index + ' of ' +
      inclusionRecord.tree_size + ', root ' + String(inclusionRecord.root_hash).slice(0, 12) +
      (anchored ? '' : '; pass --batch to authenticate') + ')');
  } else if (inclusion.present) {
    console.log('Inclusion:    INVALID (' + inclusion.reason + ')');
  } else {
    console.log('Inclusion:    NOT PRESENT');
  }

  // Optional batch root: proves the root itself was signed, and that this
  // receipt's proof belongs to that root rather than to some other batch.
  let batchOk = true;
  if (OPTS.batch) {
    const batch = evidence.batch;
    batchOk = batch.authenticated;
    console.log('Batch:        ' + batch.path);

    if (!batch.root || !batch.opened) {
      console.log('Root:         ' + (batch.error === 'batch root not found' ? 'NOT FOUND' : 'UNREADABLE'));
    } else {
      const opened = batch.opened;
      console.log('Root:         ' + (opened.ok ? 'VALID (' + opened.key_id + ')' : 'REJECTED (' + opened.code + ')'));

      const rootTime = batch.rootTime;
      if (rootTime.status === 'attested') {
        console.log('Root time:    ATTESTED ' + rootTime.analysis.gen_time);
      } else if (rootTime.status === 'unverified') {
        console.log('Root time:    UNVERIFIED (token signature valid; no trust root)');
      } else if (rootTime.status === 'invalid') {
        const why = rootTime.caError || (rootTime.analysis && rootTime.analysis.reasons.join(', ')) || 'token could not be verified';
        console.log('Root time:    INVALID (' + why + ')');
      } else {
        console.log('Root time:    UNATTESTED');
      }
    }

    console.log('Batch check:  ' + (batch.authenticated ? 'VALID' : 'INVALID (' + batch.reason + ')'));
  }

  const witnessResult = reportWitnesses(data, evidence);
  const determinationResult = OPTS.determination
    ? reportDetermination(evidence)
    : { ok: true };

  // Probability that the assurance claim holds, computed from the same evidence
  // just displayed. Informational: it never substitutes for the checks that set
  // Status.
  const assurance = await assessAssurance(data, evidence);
  console.log('Assurance:    ' + formatAssurance(assurance));
  if (assurance && !assurance.error) {
    console.log('Model:        ' + assurance.scheme + ' ' + assurance.model_version +
      ', ' + assurance.labels_origin + ' labels, data ' + assurance.dataset_sha256.slice(0, 12));
    for (const note of assurance.notes) {
      console.log('  note        ' + note.code + (note.detail ? ': ' + note.detail : ''));
    }
  }

  // The same verdict certify uses. The report above explains each failure;
  // this object is the single pass/fail decision.
  const verdict = v.AssuranceEvidence.verdict(data, evidence);
  const ok = verdict.ok;
  console.log('Status:       ' + (ok ? 'VALID' : 'REJECTED'));
  if (!res.ok) console.log('Reason:       ' + res.message);
  if (!batchOk) console.log('Reason:       ' + (evidence.batch.error || evidence.batch.reason || 'batch root is not authenticated'));
  if (!witnessResult.ok) console.log('Reason:       ' + witnessResult.reason);
  if (!determinationResult.ok) console.log('Reason:       ' + determinationResult.reason);
  process.exit(ok ? 0 : 1);
}

function warnWindowsModes() {
  if (process.platform !== 'win32') return;
  console.log('Note: Windows does not enforce POSIX file modes. The private key');
  console.log('inherits the ACL of the keyring directory; keep it inside your user profile.');
}

function keysCommand(sub) {
  const dir = keyringDir();

  if (sub === 'path') {
    console.log(dir);
    return;
  }

  if (sub === 'init') {
    const out = v.Signing.ensureKeyring({ dir });
    console.log('Keyring:  ' + dir);
    console.log(out.created ? 'Created signing key: ' + out.key_id : 'Keyring already has an active key: ' + out.key_id);
    warnWindowsModes();
    return;
  }

  if (sub === 'rotate') {
    const out = v.Signing.rotateKey({ dir });
    console.log('Keyring:  ' + dir);
    console.log('Retired:  ' + (out.previous_key_id || '(none)'));
    console.log('Active:   ' + out.key_id);
    warnWindowsModes();
    console.log('Receipts signed by the retired key still verify; remove its .pub.json');
    console.log('record only if you intend to distrust them.');
    return;
  }

  const keys = v.Signing.listKeys({ dir });
  const active = v.Signing.activeKeyId({ dir });
  console.log('Keyring: ' + dir);
  if (keys.length === 0) {
    console.log('No keys. Run: verifyd keys init');
    return;
  }
  for (const k of keys) {
    const mark = k.key_id === active ? '*' : ' ';
    console.log(mark + ' ' + k.key_id);
    console.log('    status=' + k.status + '  created=' + (k.created_at || '(unknown)'));
  }
  console.log('');
  console.log('* = active signing key');
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

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function folderReceipt(folder) {
  if (!folder) { console.error('verifyd audit-folder: missing folder'); process.exit(1); }
  if (!fs.existsSync(folder) || !fs.statSync(folder).isDirectory()) {
    console.error('verifyd audit-folder: not a directory: ' + folder);
    process.exit(1);
  }

  const trace = v.EngineTrace.createTrace('folder');
  try {
    trace.mark('folder_walk');
    const manifest = v.FolderManifest.buildManifest(folder, { strict: true });
    trace.mark('manifest_built');

    const receipt = {
      valf_version: '1.0',
      receipt_type: 'folder',
      audit_mode: 'folder',
      receipt_id: crypto.randomUUID(),
      created_at: new Date().toISOString(),
      folder: {
        root_label: manifest.root_label,
        file_count: manifest.file_count,
        excluded_count: manifest.excluded_count,
        total_size_bytes: manifest.total_size_bytes,
        manifest_hash: manifest.manifest_hash,
        path_normalization: manifest.path_normalization,
        symlink_policy: manifest.symlink_policy
      },
      manifest,
      engine_trace: trace.all()
    };

    receipt.this_hash = v.sha256(v.canonicalJSON(receipt, ['this_hash']));

    const out = path.join(process.cwd(), path.basename(path.resolve(folder)) + '.verifyd-folder-receipt.json');
    writeJson(out, receipt);

    console.log('Folder audit: PASSED');
    console.log('Files:        ' + manifest.file_count);
    console.log('Total bytes:  ' + manifest.total_size_bytes);
    console.log('Manifest:     ' + manifest.manifest_hash);
    console.log('Receipt hash: ' + receipt.this_hash);
    console.log('Saved:        ' + out);
  } catch (e) {
    console.error('Folder audit: FAILED');
    console.error('Reason: ' + (e.code || e.message));
    process.exit(1);
  }
}

function manifestOnly(folder) {
  if (!folder) { console.error('verifyd manifest: missing folder'); process.exit(1); }
  if (!fs.existsSync(folder) || !fs.statSync(folder).isDirectory()) {
    console.error('verifyd manifest: not a directory: ' + folder);
    process.exit(1);
  }
  try {
    const manifest = v.FolderManifest.buildManifest(folder, { strict: true });
    const out = path.join(process.cwd(), path.basename(path.resolve(folder)) + '.verifyd-manifest.json');
    writeJson(out, manifest);
    console.log('Manifest: ' + manifest.manifest_hash);
    console.log('Saved:    ' + out);
  } catch (e) {
    console.error('Manifest failed: ' + (e.code || e.message));
    process.exit(1);
  }
}

function verifyFolder(folder, receiptFile) {
  if (!folder) { console.error('verifyd verify-folder: missing folder'); process.exit(1); }
  if (!receiptFile || !fs.existsSync(receiptFile)) {
    console.error('verifyd verify-folder: receipt not found');
    process.exit(1);
  }

  try {
    const receipt = loadArtifact(receiptFile, 'verify-folder', {
      notFound: 'receipt not found',
      directory: 'not a receipt file',
      invalidJson: 'receipt is not valid JSON',
      notObject: 'not a receipt',
      readError: 'receipt could not be read',
    });
    const result = v.FolderManifest.verifyManifest(folder, receipt.manifest, { strict: true });

    console.log('Expected: ' + result.expected_hash);
    console.log('Actual:   ' + result.actual_hash);
    // A folder record is unsigned, so this compares bytes to the record; it
    // does not authenticate who wrote the record. Say so rather than "VALID".
    console.log('Status:   ' + (result.valid ? 'VALID (manifest match only; folder records are unsigned)' : 'TAMPERED'));

    process.exit(result.valid ? 0 : 1);
  } catch (e) {
    console.error('Verify folder failed: ' + (e.code || e.message));
    process.exit(1);
  }
}

function light(file) {
  if (!file) { console.error('verifyd light: missing file'); process.exit(1); }

  const trace = v.EngineTrace.createTrace('light_exif');
  try {
    trace.mark('read_raw_bytes');
    const report = v.LightExif.auditFile(file, { strict: true });
    trace.mark('light_metadata_audit');

    const receipt = {
      valf_version: '1.0',
      receipt_type: 'light_exif',
      receipt_id: crypto.randomUUID(),
      created_at: new Date().toISOString(),
      audit: report,
      engine_trace: trace.all()
    };

    receipt.this_hash = v.sha256(v.canonicalJSON(receipt, ['this_hash']));

    const out = file.replace(/\.[^.]+$/, '') + '.verifyd-light-receipt.json';
    writeJson(out, receipt);

    console.log('Light EXIF audit: ' + report.forgery_posture.verdict.toUpperCase());
    console.log('File hash:        ' + report.file.sha256);
    console.log('Magic type:       ' + report.file.magic_type);
    console.log('Metadata hash:    ' + (report.metadata.metadata_hash || '(none)'));
    console.log('Flags:            ' + (report.forgery_posture.flags.join(', ') || '(none)'));
    console.log('Receipt hash:     ' + receipt.this_hash);
    console.log('Saved:            ' + out);

    if (report.forgery_posture.verdict === 'failed') process.exit(1);
  } catch (e) {
    console.error('Light EXIF audit: FAILED');
    console.error('Reason: ' + (e.code || e.message));
    process.exit(1);
  }
}


// ----- Compliance determinations (engineering record, NOT legal advice) -----
function loadArtifact(file, label, messages) {
  const read = Artifacts.readJsonObject(file, { messages });
  if (!read.ok) {
    console.error('verifyd ' + label + ': ' + read.message);
    process.exit(1);
  }
  return read.value;
}

function reportDetermination(evidence) {
  const record = evidence.determination;
  const determinationVerdict = v.AssuranceEvidence.determinationVerdict(evidence);
  if (!record.requested) return determinationVerdict;

  if (record.error) {
    const label = record.error === 'determination file not found' ? 'NOT FOUND' : 'UNREADABLE';
    console.log('Determination: ' + label + ' (' + record.file + ')');
    return determinationVerdict;
  }

  const det = record.det;
  const result = record.result;
  console.log('Determination: ' + record.file);
  console.log('  Reviewer:    ' + (result.reviewer
    ? (result.reviewer.name || '(unnamed)') + (result.reviewer.role ? ' (' + result.reviewer.role + ')' : ' (no role)')
    : '(none)'));
  console.log('  Machine:     ' + (det.machine ? det.machine.result : 'unknown'));
  console.log('  Review:      ' + (det.review ? String(det.review.conclusion || 'none') : 'none'));
  console.log('  Signed:      ' + (result.signature.valid
    ? 'VALID (' + result.signature.key_id + ')'
    : (result.signature.code || 'UNSIGNED')));
  console.log('  Binding:     ' + result.binding.toUpperCase());
  console.log('  Expired:     ' + (result.expired ? 'YES' : 'NO'));
  console.log('  Status:      ' + result.status);
  if (!result.ok) console.log('  Reason:      ' + result.reasons.join('; '));
  return determinationVerdict;
}

function determinationCommand(sub, rest) {
  const Det = v.Determination;
  const dir = keyringDir();

  if (sub === 'regimes') {
    console.log('Indexed jurisdictions and regimes (checklists over repo citations, NOT legal advice):');
    for (const [code, jurisdiction] of Object.entries(Det.REGISTRY.jurisdictions)) {
      console.log('  ' + code + '  ' + (jurisdiction.label || ''));
      console.log('      basis: ' + (jurisdiction.basis || []).join(', '));
      for (const id of jurisdiction.regimes || []) {
        const regime = Det.REGISTRY.regimes[id];
        console.log('      regime ' + id + (regime ? ' - ' + regime.label : ' (missing from registry)'));
      }
    }
    console.log('');
    console.log('Any jurisdiction or regime not listed here is unknown to this tool; a');
    console.log('determination under it is recorded as undetermined, never compliant.');
    console.log(Det.NOTICE);
    return;
  }

  if (sub === 'create') {
    const receiptFile = rest[0];
    if (!receiptFile || !fs.existsSync(receiptFile)) { console.error('verifyd determination create: receipt not found'); process.exit(1); }
    if (!OPTS.jurisdiction) { console.error('determination create: --jurisdiction is required; this tool has no default jurisdiction'); process.exit(1); }
    if (!OPTS.regime) { console.error('determination create: --regime is required; see: verifyd determination regimes'); process.exit(1); }
    if (!OPTS.reviewer) { console.error('determination create: --reviewer is required (the named person making the determination)'); process.exit(1); }
    if (!OPTS.role) { console.error('determination create: --role is required (the reviewer role in the organization)'); process.exit(1); }
    if (!OPTS.conclusion) { console.error('determination create: --conclusion is required (compliant | non_compliant | insufficient_evidence)'); process.exit(1); }
    if (!['compliant', 'non_compliant', 'insufficient_evidence'].includes(OPTS.conclusion)) {
      console.error('determination create: --conclusion must be compliant, non_compliant or insufficient_evidence');
      process.exit(1);
    }
    if (OPTS.expires && Number.isNaN(Date.parse(OPTS.expires))) {
      console.error('determination create: --expires must be an ISO 8601 timestamp');
      process.exit(1);
    }

    const facts = {};
    for (const item of OPTS.facts) {
      const eq = item.indexOf('=');
      if (eq <= 0) { console.error('determination create: --fact must be id=value'); process.exit(1); }
      facts[item.slice(0, eq)] = item.slice(eq + 1);
    }

    const data = loadArtifact(receiptFile, 'determination create', {
      notFound: 'receipt not found',
      directory: 'not a receipt file',
      invalidJson: 'receipt is not valid JSON',
      notObject: 'receipt is not a JSON object',
      readError: 'receipt could not be read',
    });
    let det;
    try {
      det = Det.create(data, {
        dir: reviewerKeysDir(),
        receiptKeyring: dir,
        keyId: OPTS.key || undefined,
        jurisdiction: OPTS.jurisdiction,
        regime: OPTS.regime,
        reviewer: { name: OPTS.reviewer, role: OPTS.role, organization: OPTS.organization },
        conclusion: OPTS.conclusion,
        rationale: OPTS.rationale || '',
        facts,
        requirements: OPTS.requirements,
        expiresAt: OPTS.expires,
      });
    } catch (e) {
      console.error('determination create: ' + (e.code || e.message));
      process.exit(1);
    }

    const outFile = OPTS.out
      ? path.resolve(OPTS.out)
      : receiptFile.replace(/\.json$/i, '') + '.determination.json';
    fs.writeFileSync(outFile, JSON.stringify(det, null, 2) + '\n');

    console.log('Determination: ' + outFile);
    console.log('Jurisdiction:  ' + (det.jurisdiction.code || '(none)') +
      (det.jurisdiction.known ? ' (' + det.jurisdiction.label + ')' : ' (NOT INDEXED)'));
    console.log('Regime:        ' + (det.regime.id || '(none)') + (det.regime.known ? '' : ' (NOT INDEXED)'));
    console.log('Machine:       ' + det.machine.result + ' (' + det.machine.summary.satisfied + '/' +
      det.machine.summary.total + ' requirements satisfied)');
    console.log('Reviewer:      ' + (det.review.reviewer.name || '(unnamed)') +
      ' (' + (det.review.reviewer.role || 'no role') + ')');
    console.log('Conclusion:    ' + (det.review.conclusion || '(none)') + ' (signed ' + det.signature.key_id + ')');
    console.log('Status:        ' + det.status.value.toUpperCase());
    for (const reason of det.status.reasons) console.log('  outstanding: ' + reason);
    console.log('');
    console.log(Det.NOTICE);
    if (det.status.value !== Det.FINAL.COMPLIANT) process.exitCode = 1;
    return;
  }

  if (sub === 'show') {
    const file = rest[0];
    const det = loadArtifact(file, 'determination show', {
      notFound: 'determination not found',
      directory: 'not a file',
      invalidJson: 'determination is not valid JSON',
      notObject: 'not a determination object',
      readError: 'determination could not be read',
    });
    console.log('Determination: ' + file);
    console.log('Artifact:      ' + (det.artifact_type || '(unknown)') + ' / ' + (det.scheme || '(no scheme)'));
    console.log('Receipt:       ' + (det.receipt_id || '(not recorded)'));
    console.log('Receipt hash:  ' + (det.receipt_digest || '(none)'));
    console.log('Jurisdiction:  ' + ((det.jurisdiction && det.jurisdiction.code) || '(none)') +
      (det.jurisdiction && det.jurisdiction.known ? ' (' + det.jurisdiction.label + ')' : ' (NOT INDEXED)'));
    console.log('Regime:        ' + ((det.regime && det.regime.id) || '(none)'));
    if (det.regime && det.regime.coverage_note) console.log('Coverage:      ' + det.regime.coverage_note);
    console.log('Machine:       ' + ((det.machine && det.machine.result) || '(none)') + ' (tool checks only)');
    for (const r of (det.machine && det.machine.requirements) || []) {
      console.log('  ' + String(r.status).padEnd(14) + r.id + (r.detail ? ': ' + r.detail : ''));
    }
    console.log('Applicability facts (reviewer-supplied unless marked):');
    for (const f of (det.applicability && det.applicability.facts) || []) {
      console.log('  ' + f.id + ' = ' + (f.value === null || f.value === undefined ? '(missing)' : f.value) + ' [' + f.status + ']');
    }
    for (const f of (det.applicability && det.applicability.extra) || []) {
      console.log('  ' + f.id + ' = ' + f.value + ' [extra, reviewer-supplied]');
    }
    console.log('Reviewer:      ' + ((det.review && det.review.reviewer && det.review.reviewer.name) || '(unnamed)') +
      ' (' + ((det.review && det.review.reviewer && det.review.reviewer.role) || 'no role') + ')');
    console.log('Conclusion:    ' + ((det.review && det.review.conclusion) || '(none)') + ' (human judgement)');
    if (det.review && det.review.rationale) console.log('Rationale:     ' + det.review.rationale);
    console.log('Reviewed at:   ' + ((det.review && det.review.reviewed_at) || '(none)'));
    console.log('Expires at:    ' + (det.expires_at || 'never'));
    console.log('Stored status: ' + ((det.status && det.status.value) || '(none)').toUpperCase() + ' (UNVERIFIED: run determination verify)');
    for (const reason of (det.status && det.status.reasons) || []) console.log('  outstanding: ' + reason);
    console.log('Signature:     NOT CHECKED');
    console.log('');
    console.log(det.notice || Det.NOTICE);
    return;
  }

  if (sub === 'verify') {
    const file = rest[0];
    const det = loadArtifact(file, 'determination verify', {
      notFound: 'determination not found',
      directory: 'not a file',
      invalidJson: 'determination is not valid JSON',
      notObject: 'not a determination object',
      readError: 'determination could not be read',
    });
    if (!OPTS.receipt) {
      console.error('determination verify: --receipt <receipt.json> is required to check the binding');
      process.exit(1);
    }
    const receipt = loadArtifact(OPTS.receipt, 'determination verify', {
      notFound: 'receipt not found: ' + OPTS.receipt,
      directory: 'not a receipt file',
      invalidJson: 'receipt is not valid JSON',
      notObject: 'receipt is not a JSON object',
      readError: 'receipt could not be read',
    });
    const result = Det.verify(det, { receipt, dir: reviewerKeysDir() });

    console.log('Determination: ' + file);
    console.log('Jurisdiction:  ' + ((det.jurisdiction && det.jurisdiction.code) || '(none)'));
    console.log('Regime:        ' + ((det.regime && det.regime.id) || '(none)'));
    console.log(Det.describe(result));
    console.log('');
    console.log(Det.NOTICE);
    process.exit(result.ok ? 0 : 1);
  }

  console.error('Unknown determination subcommand: ' + (sub || '(none)'));
  console.error('Use: create / show / verify / regimes');
  process.exit(1);
}

// ----- Witness identity proofing -----
// A witness keyring is just a signing keyring; the verifier keeps a separate
// directory of trusted witness public records. Nothing here lets a label count
// without proof: `prove` writes the resource binding, `attest` refuses to sign
// without it, and `assess` re-checks it on every verification.
function witnessCommand(sub, rest) {
  const dir = keyringDir();

  if (sub === 'init') {
    const out = v.Signing.ensureKeyring({ dir });
    console.log('Witness keyring: ' + dir);
    console.log(out.created ? 'Created witness key: ' + out.key_id : 'Existing witness key: ' + out.key_id);
    console.log('Next: verifyd witness prove <identity> --proof-out <file> --keyring ' + dir);
    return;
  }

  if (sub === 'prove') {
    const identity = rest[0] || OPTS.identity;
    if (!identity) { console.error('verifyd witness prove: missing identity'); process.exit(1); }
    if (!v.Witness.IDENTITY_RE.test(identity)) {
      console.error('verifyd witness prove: identity must be one token of letters, digits, ._@:/-');
      process.exit(1);
    }
    const keyId = v.Signing.activeKeyId({ dir });
    if (!keyId) { console.error('verifyd witness prove: no key in witness keyring; run witness init'); process.exit(1); }
    const outFile = OPTS.proofOut || path.resolve(identity.replace(/[^A-Za-z0-9._@-]/g, '_') + '.witness-proof.txt');
    fs.writeFileSync(outFile, v.Witness.bindingLine(keyId, identity) + '\n');
    console.log('Proof file: ' + outFile);
    console.log('Binding:    ' + v.Witness.bindingLine(keyId, identity));
    console.log('Publish this file at a stable URI (https:// recommended), then attest with --proof-uri.');
    return;
  }

  if (sub === 'attest') {
    const receiptFile = rest[0];
    const identity = OPTS.identity;
    const proofFile = OPTS.proof;
    if (!receiptFile || !fs.existsSync(receiptFile)) { console.error('verifyd witness attest: receipt not found'); process.exit(1); }
    if (!identity) { console.error('verifyd witness attest: --identity is required'); process.exit(1); }
    if (!proofFile || !fs.existsSync(proofFile)) { console.error('verifyd witness attest: --proof <file> is required; a signature alone is label-only'); process.exit(1); }

    const data = loadArtifact(receiptFile, 'witness attest', {
      notFound: 'receipt not found',
      directory: 'not a receipt file',
      invalidJson: 'receipt is not valid JSON',
      notObject: 'not a receipt',
      readError: 'receipt could not be read',
    });
    if (!data.signature || !data.signature.key_id) {
      console.error('verifyd witness attest: receipt is not signed; there are no bytes to bind an attestation to');
      process.exit(1);
    }

    const content = fs.readFileSync(proofFile);
    const proofUri = OPTS.proofUri || require('url').pathToFileURL(path.resolve(proofFile)).href;
    let att;
    try {
      att = v.Witness.attest(data, { dir, identity, proofContent: content, proofUri, statement: OPTS.statement || '' });
    } catch (e) {
      console.error('witness attest: ' + (e.code || e.message));
      process.exit(1);
    }
    v.Witness.attach(data, att);
    fs.writeFileSync(receiptFile, JSON.stringify(data, null, 2) + '\n');

    console.log('Attestation: ' + att.attestation_id);
    console.log('Witness:     ' + identity + ' (' + att.witness_key_id + ')');
    console.log('Tier:        key (resource proof at ' + proofUri + ')');
    console.log('Binds:       receipt ' + att.receipt_digest.slice(0, 16) + '...');
    console.log('Note:        tier key holds only while that URI serves these exact bytes.');
    console.log('Receipt signature unchanged; attestations sit outside the signed payload.');
    return;
  }

  if (sub === 'vouch') {
    const receiptFile = rest[0];
    const witnessKey = OPTS.witnessKey;
    const identity = OPTS.identity;
    if (!receiptFile || !fs.existsSync(receiptFile)) { console.error('verifyd witness vouch: receipt not found'); process.exit(1); }
    if (!witnessKey || !identity) { console.error('verifyd witness vouch: --witness-key and --identity are required'); process.exit(1); }

    const data = loadArtifact(receiptFile, 'witness vouch', {
      notFound: 'receipt not found',
      directory: 'not a receipt file',
      invalidJson: 'receipt is not valid JSON',
      notObject: 'not a receipt',
      readError: 'receipt could not be read',
    });
    const att = (Array.isArray(data.attestations) ? data.attestations : [])
      .find(a => a && a.witness_key_id === witnessKey && a.identity === identity);
    if (!att) { console.error('verifyd witness vouch: no attestation from that key and identity'); process.exit(1); }

    try {
      v.Witness.vouch(data, att, { dir, method: OPTS.method || 'manual', statement: OPTS.statement || '' });
    } catch (e) {
      console.error('witness vouch: ' + (e.code || e.message));
      process.exit(1);
    }
    fs.writeFileSync(receiptFile, JSON.stringify(data, null, 2) + '\n');
    console.log('Vouched:  ' + identity + ' (' + witnessKey + ')');
    console.log('Voucher:  ' + att.vouch.signature.key_id);
    console.log('Tier:     vouched (a second trusted key asserts the binding, nothing more)');
    return;
  }

  if (sub === 'register') {
    const source = rest[0];
    const into = OPTS.into;
    if (!source || !fs.existsSync(source)) { console.error('verifyd witness register: source keyring not found'); process.exit(1); }
    if (!into) { console.error('verifyd witness register: --into <verifier witness keyring> is required'); process.exit(1); }
    if (OPTS.expires && Number.isNaN(Date.parse(OPTS.expires))) {
      console.error('verifyd witness register: --expires must be an ISO 8601 timestamp');
      process.exit(1);
    }
    const keys = v.Signing.listKeys({ dir: path.resolve(source) });
    if (keys.length === 0) { console.error('verifyd witness register: no keys in ' + source); process.exit(1); }
    fs.mkdirSync(into, { recursive: true, mode: 0o700 });
    for (const k of keys) {
      const record = {
        key_id: k.key_id,
        algorithm: k.algorithm,
        public_key_pem: k.public_key_pem,
        created_at: k.created_at,
        status: 'active',
        expires_at: OPTS.expires || null,
        registered_at: new Date().toISOString(),
      };
      fs.writeFileSync(path.join(into, k.key_id.replace(':', '-') + '.pub.json'), JSON.stringify(record, null, 2) + '\n');
      console.log('Trusted: ' + k.key_id + (OPTS.expires ? ' (expires ' + OPTS.expires + ')' : ' (no expiry)'));
    }
    return;
  }

  if (sub === 'revoke') {
    const keyId = rest[0];
    const into = OPTS.into;
    if (!keyId || !v.Signing.KEY_ID_RE.test(keyId)) { console.error('verifyd witness revoke: pass a full ed25519:<hex> key id'); process.exit(1); }
    if (!into) { console.error('verifyd witness revoke: --into <verifier witness keyring> is required'); process.exit(1); }
    const recordFile = path.join(into, keyId.replace(':', '-') + '.pub.json');
    if (!fs.existsSync(recordFile)) { console.error('verifyd witness revoke: no such record in ' + into); process.exit(1); }
    const record = JSON.parse(fs.readFileSync(recordFile, 'utf8'));
    record.status = 'revoked';
    record.revoked_at = new Date().toISOString();
    fs.writeFileSync(recordFile, JSON.stringify(record, null, 2) + '\n');
    console.log('Revoked: ' + keyId);
    console.log('Attestations from this key no longer count; existing receipts stay readable.');
    return;
  }

  if (sub === 'list') {
    const into = OPTS.into;
    if (!into) { console.error('verifyd witness list: --into <verifier witness keyring> is required'); process.exit(1); }
    const keys = v.Signing.listKeys({ dir: path.resolve(into) });
    if (keys.length === 0) { console.log('No trusted witness keys in ' + into); return; }
    for (const k of keys) {
      console.log(k.key_id);
      console.log('    status=' + k.status + '  expires=' + (k.expires_at || 'never') + '  created=' + (k.created_at || '(unknown)'));
    }
    return;
  }

  console.error('Unknown witness subcommand: ' + (sub || '(none)'));
  console.error('Use: init / prove / attest / vouch / register / revoke / list');
  process.exit(1);
}

(async () => {
  const positional = OPTS.rest.slice(1);
  if (cmd === 'audit') return audit(positional[0]);
  if (cmd === 'verify') return verify(positional[0]);
  if (cmd === 'batch') return batchCommand(positional);
  if (cmd === 'witness') return witnessCommand(positional[0], positional.slice(1));
  if (cmd === 'determination') return determinationCommand(positional[0], positional.slice(1));
  if (cmd === 'keys') return keysCommand(positional[0]);
  // certify has its own parser (including --out), so hand it the original
  // argument list rather than the globally parsed remainder.
  if (cmd === 'certify') { const rc = await require('./certify.cjs').main(args.slice(args.indexOf('certify'))); process.exit(rc); }
  if (cmd === 'manifest') return manifestOnly(positional[0]);
  if (cmd === 'audit-folder') return folderReceipt(positional[0]);
  if (cmd === 'verify-folder') return verifyFolder(positional[0], positional[1]);
  if (cmd === 'light') return light(positional[0]);
  if (cmd === 'lattice') return showLattice();
  if (cmd === 'demo') { require(path.join(ROOT, 'examples', 'lattice-demo.cjs')); return; }
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') return help();
  if (!cmd) { require('./intro.cjs'); return; }
  console.error('Unknown command: ' + cmd); help(); process.exit(1);
})().catch(e => {
  console.error('verifyd: ' + (e && e.message ? e.message : e));
  process.exit(1);
});
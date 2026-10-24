#!/usr/bin/env node
'use strict';

/*
  Verifyd Premium ASCII Certificate
  - ASCII only: safe in Windows PowerShell, cmd, CI, logs, GitHub, email.
  - ANSI color optional: uses String.fromCharCode(27), no escaped literals.
  - Evidence-honest: separates receipt validity from engine authenticity.
*/

const fs = require('fs');
const path = require('path');

const v = require('../engine/verifyd.cjs');
const Artifacts = require('../engine/artifacts.cjs');
const TrustScore = v.TrustScoreCalculator;

const ESC = String.fromCharCode(27);

const A = {
  reset: ESC + '[0m',
  bold: ESC + '[1m',
  dim: ESC + '[2m',
  red: ESC + '[31m',
  green: ESC + '[32m',
  yellow: ESC + '[33m',
  blue: ESC + '[34m',
  magenta: ESC + '[35m',
  cyan: ESC + '[36m',
  white: ESC + '[37m'
};

const W = 78;

function paint(enabled, code, s) {
  s = String(s == null ? '' : s);
  return enabled ? code + s + A.reset : s;
}

function C(enabled) {
  return {
    bold: s => paint(enabled, A.bold, s),
    dim: s => paint(enabled, A.dim, s),
    red: s => paint(enabled, A.red, s),
    green: s => paint(enabled, A.green, s),
    yellow: s => paint(enabled, A.yellow, s),
    blue: s => paint(enabled, A.blue, s),
    magenta: s => paint(enabled, A.magenta, s),
    cyan: s => paint(enabled, A.cyan, s),
    white: s => paint(enabled, A.white, s),
    status: s => {
      const x = String(s || '').toUpperCase();
      if (['VALID', 'PASSED', 'PASS', 'CLEAN', 'TRUE', 'ACTIVE', 'RECORDED', 'VERIFIED'].includes(x)) {
        return paint(enabled, A.bold + A.green, x);
      }
      if (['PROVISIONAL', 'DEPOSITED', 'SUSPICIOUS', 'UNKNOWN', 'WARN', 'WARNING', 'LOCAL', 'UNSIGNED', 'LOCAL / UNSIGNED'].includes(x)) {
        return paint(enabled, A.bold + A.yellow, x);
      }
      if (['FAILED', 'FAIL', 'TAMPERED', 'FALSE', 'REJECTED', 'MISSING', 'UNVERIFIED'].includes(x)) {
        return paint(enabled, A.bold + A.red, x);
      }
      return paint(enabled, A.bold, x);
    }
  };
}

function stripAnsi(s) {
  const re = new RegExp(ESC + '\\[[0-9;]*m', 'g');
  return String(s == null ? '' : s).replace(re, '');
}

function vlen(s) {
  return stripAnsi(s).length;
}

function fit(s, width) {
  s = String(s == null ? '' : s);
  const plain = stripAnsi(s);
  if (plain.length <= width) return s + ' '.repeat(width - plain.length);

  // If colored, fallback to plain trimming to avoid breaking ANSI sequences.
  if (plain !== s) {
    return plain.slice(0, Math.max(0, width - 3)) + '...';
  }

  return s.slice(0, Math.max(0, width - 3)) + '...';
}

function short(s, n) {
  if (!s) return '(none)';
  s = String(s);
  n = n || 44;
  if (s.length <= n) return s;
  const left = Math.floor((n - 3) / 2);
  const right = n - 3 - left;
  return s.slice(0, left) + '...' + s.slice(-right);
}

function comma(n) {
  if (n == null || n === '') return '(none)';
  const x = Number(n);
  return Number.isFinite(x) ? x.toLocaleString('en-US') : String(n);
}

function border(ch) {
  return '+' + ch.repeat(W - 2) + '+\n';
}

function row(text) {
  return '| ' + fit(text, W - 4) + ' |\n';
}

function row2(left, right) {
  const gap = 3;
  const lw = Math.floor((W - 4 - gap) / 2);
  const rw = W - 4 - gap - lw;
  return '| ' + fit(left, lw) + ' '.repeat(gap) + fit(right, rw) + ' |\n';
}

function center(text) {
  text = String(text == null ? '' : text);
  const len = vlen(text);
  const space = Math.max(0, W - 4 - len);
  const left = Math.floor(space / 2);
  const right = space - left;
  return '| ' + ' '.repeat(left) + text + ' '.repeat(right) + ' |\n';
}

function section(title, color) {
  return '\n' + color.cyan('-- ' + title.toUpperCase() + ' ') + '-'.repeat(Math.max(2, W - 5 - title.length)) + '\n';
}

function kv(label, value) {
  return '  ' + fit(label + ':', 20) + String(value == null ? '(none)' : value) + '\n';
}

function policyPassed(checks) {
  if (!Array.isArray(checks) || checks.length === 0) return null;
  return checks.every(c => c.result === 'pass' || c.result === 'warn');
}

function normalize(data) {
  const core = data.receipt && data.receipt.this_hash ? data.receipt : data;
  // One owner: the signed envelope's `receipt`. `data.audit` is legacy input.
  const auditBlock = (data.receipt && data.receipt.this_hash) ? data.receipt : (data.audit || core.audit || {});
  const checks = auditBlock.policy_checks || core.policy_checks || [];
  const policyOk = policyPassed(checks);
  const signature = data.signature && data.signature.value ? data.signature : null;
  const latticeStatus = (core.lattice && core.lattice.status) || auditBlock.lattice_status || null;

  const folder = core.folder || (core.manifest ? {
    root_label: core.manifest.root_label,
    file_count: core.manifest.file_count,
    excluded_count: core.manifest.excluded_count,
    total_size_bytes: core.manifest.total_size_bytes,
    manifest_hash: core.manifest.manifest_hash,
    path_normalization: core.manifest.path_normalization,
    symlink_policy: core.manifest.symlink_policy
  } : null);

  const light = core.audit && core.audit.audit_mode === 'light_exif'
    ? core.audit
    : (core.receipt_type === 'light_exif' ? core.audit : null);

  let mode = core.audit_mode || core.receipt_type || data.audit_mode || 'document';
  if (folder) mode = 'folder';
  if (light) mode = 'light_exif';

  let sealStatus = 'VALID';
  if (light && light.forgery_posture) sealStatus = light.forgery_posture.verdict || 'UNKNOWN';
  else if (data.chain_valid === false) sealStatus = 'FAILED';
  else if (policyOk === false) sealStatus = 'FAILED';
  else if (latticeStatus) sealStatus = latticeStatus;
  else if (folder) sealStatus = 'VALID';

  const engineIdentity = core.engine_identity || data.engine_identity || {};
  const engineAuth =
    engineIdentity.engine_authenticity ||
    engineIdentity.authenticity ||
    'LOCAL / UNSIGNED';

  const policyProfile =
    engineIdentity.policy_profile ||
    core.policy_profile ||
    data.policy_profile ||
    'verifyd-standard-v1';

  let subject = {
    name: '(unknown)',
    type: '(unknown)',
    size: '(not recorded)',
    hash: core.this_hash || '(none)'
  };

  if (data.document) {
    subject.name = data.document.file || data.document.title || '(document)';
    subject.type = data.document.file ? (path.extname(data.document.file).replace('.', '').toUpperCase() || 'document') : 'document';
    subject.size = data.document.words ? data.document.words + ' words' : '(not recorded)';
    subject.hash = data.document.sha256 ? 'sha256:' + data.document.sha256 : subject.hash;
  }

  if (folder) {
    subject.name = folder.root_label || '(folder)';
    subject.type = 'folder';
    subject.size = comma(folder.total_size_bytes) + ' bytes';
    subject.hash = folder.manifest_hash || subject.hash;
  }

  if (light && light.file) {
    subject.name = light.file.path_label || '(file)';
    subject.type = light.file.magic_type || 'file';
    subject.size = comma(light.file.size_bytes) + ' bytes';
    subject.hash = light.file.sha256 || subject.hash;
  }

  return {
    core,
    data,
    auditBlock,
    signature,
    latticeStatus,
    checks,
    folder,
    light,
    mode,
    sealStatus,
    subject,
    policyOk,
    engineAuth,
    policyProfile,
    receipt_id: core.receipt_id || '(none)',
    this_hash: core.this_hash || '(none)',
    prev_hash: core.prev_hash || '(none)',
    issued_at: core.created_at || core.issued_at || (core.session && core.session.started_at) || new Date().toISOString(),
    version: core.valf_version || '1.0',
    engine_manifest_hash: engineIdentity.engine_manifest_hash || '(not recorded)',
    release_signature: engineIdentity.release_signature || engineIdentity.release_signature_status || 'MISSING',
    signature_status: signature ? 'SIGNED' : 'UNSIGNED',
    signer_key_id: signature ? signature.key_id : '(none)',
    time_token: data.timestamp && data.timestamp.token ? 'PRESENT' : 'NONE',
    time_authority: (data.timestamp && data.timestamp.tsa_url) || null
  };
}

function renderCertificate(data, opts) {
  opts = opts || {};
  const color = C(!!opts.color);
  const r = normalize(data);
  // Policy on the certificate follows the assurance feature, not
  // PolicyEngine.passed(): a warning or an untraceable citation is not PASSED.
  const strictPolicy = opts.assurance && opts.assurance.evidence && opts.assurance.evidence.policy;
  if (strictPolicy && strictPolicy.status !== 'absent') r.policyOk = strictPolicy.value === 1;
  if (opts.integrity && opts.integrity.hash === 'MISMATCH') r.sealStatus = 'TAMPERED';
  if (opts.verdict) {
    // A verified pass may keep the lattice word; anything less must not read as
    // a seal. Without a signed receipt there is no verdict to pass, so the
    // certificate says UNVERIFIED instead of inheriting normalize()'s VALID.
    if (opts.verdict.ok) {
      if (r.sealStatus !== 'TAMPERED') r.sealStatus = r.latticeStatus === 'RATIFIED' ? 'RATIFIED' : 'VALID';
    } else {
      if (r.sealStatus !== 'TAMPERED') r.sealStatus = 'REJECTED';
      if (r.latticeStatus === 'RATIFIED') r.latticeStatus = 'RATIFIED (UNVERIFIED)';
    }
  } else if (r.sealStatus !== 'TAMPERED') {
    r.sealStatus = 'UNVERIFIED';
  }

  const receiptIntegrity = opts.integrity
    ? opts.integrity.hash
    : (r.this_hash && r.this_hash !== '(none)' ? 'NOT CHECKED' : 'MISSING');
  const engineAuthLabel = String(r.engineAuth || '').toUpperCase();

  let out = '';

  out += border('=');
  out += center(color.bold(color.magenta('VERIFYD')));
  out += center(color.bold('TAMPER-EVIDENT AUDIT CERTIFICATE'));
  out += center(color.dim('portable receipt seal / deterministic evidence record'));
  out += border('-');

  out += row2(
    'SEAL STATUS        ' + color.status(r.sealStatus),
    'AUDIT MODE         ' + color.cyan(r.mode)
  );

  out += row2(
    'RECEIPT INTEGRITY  ' + color.status(receiptIntegrity),
    'ENGINE AUTH        ' + color.status(engineAuthLabel)
  );

  out += row2(
    'POLICY PROFILE     ' + color.dim(r.policyProfile),
    'RELEASE SIG        ' + color.status(r.release_signature)
  );

  out += border('=');

  out += section('Certificate', color);
  out += kv('Certificate ID', color.blue('verifyd-cert_' + short(r.receipt_id, 22)));
  out += kv('Receipt ID', color.blue(r.receipt_id));
  out += kv('Issued At', color.dim(r.issued_at));
  out += kv('Verifyd Version', color.dim(r.version));
  out += kv('Canonicalizer', color.dim('verifyd-strict-json-v2'));

  out += section('Subject', color);
  out += kv('Name', r.subject.name);
  out += kv('Type', color.dim(r.subject.type));
  out += kv('Size', r.subject.size);
  out += kv('Primary Hash', color.blue(short(r.subject.hash, 56)));
  if (opts.integrity && opts.integrity.artifact) {
    const label = {
      valid: 'VALID',
      changed: 'CHANGED',
      missing: 'NOT FOUND',
      unreadable: 'UNCHECKED',
      unrecorded: 'NOT RECORDED',
    }[opts.integrity.artifact] || 'NOT CHECKED';
    out += kv('Artifact', color.status(label));
  }

  out += section('Receipt Proof', color);
  out += kv('Receipt Hash', color.blue(short(r.this_hash, 56)));
  out += kv('Previous Hash', color.dim(short(r.prev_hash, 56)));
  out += kv('Hash Status', color.status(receiptIntegrity));
  out += kv('Receipt Signature', color.status(opts.integrity ? opts.integrity.signature : 'NOT CHECKED'));
  out += kv('Signer Key ID', color.dim(short(r.signer_key_id, 48)));
  out += kv('Time Token', color.status(r.time_token));
  if (r.time_authority) out += kv('Time Authority', color.dim(short(r.time_authority, 48)));
  // Same evidence object verify prints from; the certificate never runs its
  // own ledger check.
  const ledgerEvidence = opts.evidence && opts.evidence.ledger;
  if (ledgerEvidence && ledgerEvidence.requested) {
    out += kv('Ledger', color.status(ledgerEvidence.status === 'IN CHAIN' ? 'IN CHAIN' : ledgerEvidence.status) +
      color.dim(ledgerEvidence.status === 'IN CHAIN'
        ? '  (' + (ledgerEvidence.anchored ? 'ANCHORED' : 'UNANCHORED') + ')'
        : (ledgerEvidence.reason ? '  ' + short(ledgerEvidence.reason, 40) : '')));
  } else if (ledgerEvidence) {
    // No --ledger: say so, so a PASSED certificate is never mistaken for an
    // anchored ledger verdict.
    out += kv('Ledger', color.status('NOT CHECKED') + color.dim('  (no --ledger)'));
  }
  out += kv('Stage Trace', r.core.engine_trace ? color.status('RECORDED') : color.status('MISSING'));

  out += section('Audit Result', color);
  if (r.policyOk !== null) out += kv('Policy', color.status(r.policyOk ? 'PASSED' : 'UNVERIFIED'));
  if (r.auditBlock.document_quality) {
    out += kv('Doc Quality', color.dim(String(r.auditBlock.document_quality.value) +
      ' / 100 (heuristic, UNCALIBRATED, not a probability)'));
  } else if (r.auditBlock.trust_score) {
    out += kv('Legacy Field', color.dim(String(r.auditBlock.trust_score.value) +
      ' / 100 (old heuristic, UNCALIBRATED; not this version\'s score)'));
  }
  if (opts.assurance && !opts.assurance.error) {
    const a = opts.assurance;
    out += kv('Assurance', color.status(a.percent + ' / 100') + color.dim('  p=' + a.probability.toFixed(3)));
    out += kv('Assurance Model', color.dim(a.scheme + ' ' + a.model_version + ' / ' + a.labels_origin + ' labels'));
    out += kv('Assurance Data', color.dim('sha256:' + short(a.dataset_sha256, 40)));
    if (a.absent.length) out += kv('Evidence Absent', color.yellow(a.absent.join(', ')));
    if (a.notes.length) out += kv('Assurance Notes', color.dim(a.notes.map(n => n.code).join(', ')));
  } else if (opts.assurance) {
    out += kv('Assurance', color.status('NOT COMPUTED') + color.dim('  ' + opts.assurance.error));
  }
  if (r.latticeStatus) out += kv('Lattice Status', color.status(r.latticeStatus));
  if (r.data.chain_valid !== undefined) out += kv('Chain Valid', color.status(String(!!r.data.chain_valid).toUpperCase()));
  out += kv('Seal Status', color.status(r.sealStatus));
  if (opts.verdict) {
    out += kv('Verification', color.status(opts.verdict.ok ? 'PASSED' : 'REJECTED'));
    if (!opts.verdict.ok && opts.verdict.reasons.length) {
      out += kv('Reason', color.dim(short(opts.verdict.reasons.join('; '), 56)));
    }
  }

  if (r.folder) {
    out += section('Folder Manifest', color);
    out += kv('Root', r.folder.root_label || '(folder)');
    out += kv('Files', comma(r.folder.file_count));
    out += kv('Excluded', comma(r.folder.excluded_count || 0));
    out += kv('Total Size', comma(r.folder.total_size_bytes) + ' bytes');
    out += kv('Manifest Hash', color.blue(short(r.folder.manifest_hash, 56)));
    out += kv('Path Mode', color.dim(r.folder.path_normalization || 'posix-relative-v1'));
    out += kv('Symlink Policy', color.status(r.folder.symlink_policy || 'reject'));
  }

  if (r.light) {
    const a = r.light;
    out += section('Light Metadata Posture', color);

    if (a.file) {
      out += kv('File', a.file.path_label || '(file)');
      out += kv('Magic Type', color.dim(a.file.magic_type || '(unknown)'));
      out += kv('File Hash', color.blue(short(a.file.sha256, 56)));
    }

    if (a.metadata) {
      out += kv('Metadata Present', color.status(String(!!a.metadata.metadata_present).toUpperCase()));
      out += kv('Metadata Trusted', color.status(String(!!a.metadata.trusted_as_truth).toUpperCase()));
      out += kv('Metadata Hash', color.blue(short(a.metadata.metadata_hash, 56)));
    }

    if (a.forgery_posture) {
      const flags = a.forgery_posture.flags || [];
      out += kv('Posture', color.status(a.forgery_posture.verdict || 'unknown'));
      out += kv('Confidence', color.yellow(a.forgery_posture.confidence || 'low'));
      out += kv('Flags', flags.length ? color.yellow(flags.join(', ')) : color.green('(none)'));
    }
  }

  out += section('Engine Authenticity', color);
  out += kv('Engine Auth', color.status(engineAuthLabel));
  out += kv('Policy Profile', color.dim(r.policyProfile));
  out += kv('Engine Manifest', color.blue(short(r.engine_manifest_hash, 56)));
  out += kv('Release Signature', color.status(r.release_signature));
  out += color.dim('  Note: LOCAL / UNSIGNED means the receipt is internally checkable, but\n');
  out += color.dim('  not yet tied to an official signed Verifyd release.\n');
  out += color.dim('  A receipt signature proves key possession over these bytes, not honesty.\n');

  out += section('Declaration', color);
  out += '  Verifyd confirms that the receipt and subject hashes above form a\n';
  out += '  tamper-evident evidence record under deterministic canonicalization.\n\n';
  out += color.dim('  This certificate does not claim authorship, truth, legal ownership,\n');
  out += color.dim('  or absolute absence of manipulation. It records audit execution and\n');
  out += color.dim('  evidence posture at issuance time.\n');
  if (opts.assurance && !opts.assurance.error) {
    out += color.dim('  The assurance probability estimates whether the evidence above holds.\n');
    out += color.dim('  It is fitted on synthetic labels, not observed audit outcomes, so it\n');
    out += color.dim('  shows the method is wired, not that the estimate matches the world.\n');
  }


  out += section('Verify', color);
  out += '  Document receipt: verifyd verify <receipt.json>   (signature + hash + keyring)\n';
  out += '  Timestamp token:  add --tsa-ca <pem> to check the TSA chain\n';
  out += '  Folder receipt:   verifyd verify-folder <folder> <receipt.json>\n';
  out += '  Engine release:   verifyd verify-engine    (pending signed release layer)\n';

  out += section('Canonical Law', color);
  out += '  Never coerce. Expand meaning. Archive everything.\n';

  out += '\n' + border('=');

  return out;
}

function renderCompletion(outFile, data, colorEnabled) {
  const color = C(!!colorEnabled);
  const r = normalize(data);

  let out = '';
  out += '\n';
  out += border('-');
  out += row(color.bold('VERIFYD CERTIFICATE WRITTEN'));
  out += row2('FILE   ' + color.blue(outFile), 'STATUS ' + color.status(r.sealStatus));
  out += row2('RECEIPT ' + color.status('TAMPER-EVIDENT'), 'ENGINE ' + color.status(String(r.engineAuth).toUpperCase()));
  out += row(color.dim('Integrity travels by hash. Trust travels by verification.'));
  out += border('-');
  return out;
}

function usage() {
  console.log('Usage:');
  console.log('  node bin/certify.cjs <receipt.json> [--color] [--ansi] [--out file]');
  console.log('  node bin/verifyd.cjs certify <receipt.json> [--color] [--ansi] [--out file]');
  console.log('    --keyring <dir>         keyring that must trust the signer (assurance recompute)');
  console.log('    --witness-keys <dir>    trusted witness keys (assurance recompute)');
  console.log('    --tsa-ca <pem>          TSA root, so attested time counts as attested');
  console.log('    --batch <root.json>     authenticate the inclusion root');
  console.log('    --determination <file>  include a signed compliance determination');
  console.log('    --reviewer-keyring <d>  keyring that must trust the reviewer');
  console.log('    --artifact <file>       source document to rehash (default: beside the receipt)');
  console.log('');
  console.log('Default saves plain ASCII .txt. --color colors preview. --ansi saves colored ANSI file.');
}

function argValue(argv, flag) {
  const index = argv.indexOf(flag);
  return index >= 0 && argv[index + 1] && !argv[index + 1].startsWith('--') ? argv[index + 1] : null;
}

// A certificate must not call a tampered receipt valid. Recompute the stored
// hash and verify the signature when a document receipt is present; folder and
// light records carry a hash but no signature.
function checkIntegrity(data, evidence) {
  try {
    if (data.receipt && typeof data.receipt === 'object') {
      const stored = typeof data.receipt.this_hash === 'string' ? data.receipt.this_hash : null;
      let hash = 'MISSING';
      if (stored) {
        const recomputed = v.sha256(v.canonicalJSON(data.receipt, ['this_hash']));
        hash = recomputed === stored ? 'VALID' : 'MISMATCH';
      }

      // Signature verification is owned by AssuranceEvidence; never re-open
      // the envelope here, or the certificate and the score can disagree.
      const signature = evidence
        ? (evidence.signature.ok ? 'VALID' : (evidence.signature.code || 'INVALID'))
        : 'NOT CHECKED';
      const artifact = evidence && evidence.artifact ? evidence.artifact.status : null;
      return { hash, signature, artifact };
    }

    if (typeof data.this_hash === 'string') {
      const recomputed = v.sha256(v.canonicalJSON(data, ['this_hash']));
      return { hash: recomputed === data.this_hash ? 'VALID' : 'MISMATCH', signature: 'UNSIGNED' };
    }
  } catch (e) {
    return { hash: 'MISMATCH', signature: 'ERROR' };
  }
  return { hash: 'MISSING', signature: 'UNSIGNED' };
}

async function main(argv) {
  argv = argv || process.argv.slice(2);
  if (argv[0] === 'certify') argv = argv.slice(1);

  const valueFlags = new Set(['--out', '--keyring', '--witness-keys', '--tsa-ca', '--batch', '--determination', '--reviewer-keyring', '--artifact']);
  let receiptFile = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (valueFlags.has(a)) { i += 1; continue; }
    if (a.startsWith('--')) continue;
    receiptFile = a;
    break;
  }
  const colorOut = argv.includes('--color');
  const ansiFile = argv.includes('--ansi');

  const outIndex = argv.indexOf('--out');
  let outFile = outIndex >= 0 ? argv[outIndex + 1] : null;

  if (!receiptFile || receiptFile === 'help' || receiptFile === '--help' || receiptFile === '-h') {
    usage();
    return receiptFile ? 0 : 1;
  }

  const read = Artifacts.readJsonObject(receiptFile, {
    messages: {
      notFound: 'receipt not found: ' + receiptFile,
      directory: 'not a receipt file',
      invalidJson: 'receipt is not valid JSON',
      notObject: 'not a receipt',
      readError: 'receipt could not be read',
    },
  });
  if (!read.ok) {
    console.error('verifyd certify: ' + read.message);
    if (read.code === 'IS_DIRECTORY') {
      console.error('  Pass a receipt from audit or audit-folder, not a folder.');
    }
    return 1;
  }

  const data = read.value;
  const looksLikeReceipt =
    (data.receipt && typeof data.receipt === 'object') ||
    typeof data.this_hash === 'string' ||
    typeof data.receipt_type === 'string' ||
    (data.manifest && typeof data.manifest === 'object');
  if (!looksLikeReceipt) {
    console.error('verifyd certify: not a receipt: ' + receiptFile);
    return 1;
  }
  if (argValue(argv, '--determination') && !(data.receipt && typeof data.receipt === 'object')) {
    console.error('verifyd certify: --determination needs a signed document receipt');
    return 1;
  }

  if (!outFile) {
    outFile = receiptFile.replace(/\.json$/i, '') + '.verifyd-certificate' + (ansiFile ? '.ansi.txt' : '.txt');
  }

  // Recompute the probability from the receipt and the evidence on this
  // machine. Rendering never trusts a score stored in the file.
  let assurance = null;
  let evidence = null;
  if (data && data.receipt) {
    try {
      evidence = await v.AssuranceEvidence.collect(data, {
        keyring: argValue(argv, '--keyring') || v.Signing.defaultKeyringDir(),
        witnessKeys: argValue(argv, '--witness-keys') || process.env.VERIFYD_WITNESS_KEYS || null,
        tsaCa: argValue(argv, '--tsa-ca') || process.env.VERIFYD_TSA_CA || null,
        batch: argValue(argv, '--batch'),
        determination: argValue(argv, '--determination'),
        reviewerKeyring: argValue(argv, '--reviewer-keyring'),
        receiptPath: receiptFile,
        artifact: argValue(argv, '--artifact'),
        ledger: argValue(argv, '--ledger'),
        anchor: argValue(argv, '--anchor'),
        requireAnchor: argv.includes('--require-anchor'),
      });
      assurance = await TrustScore.assess(data, { evidence });
    } catch (e) {
      assurance = { error: e.code || e.message };
    }
  }

  const integrity = checkIntegrity(data, evidence);
  const verdict = evidence ? v.AssuranceEvidence.verdict(data, evidence) : null;

  const saved = renderCertificate(data, { color: ansiFile, assurance, integrity, verdict, evidence });
  const preview = renderCertificate(data, { color: colorOut, assurance, integrity, verdict, evidence });

  fs.writeFileSync(outFile, saved, 'utf8');

  console.log(preview);
  console.log('Certificate saved: ' + outFile);
  console.log(renderCompletion(outFile, data, colorOut));

  const failed = (integrity && (integrity.hash !== 'VALID' ||
    (data.receipt && typeof data.receipt === 'object' && integrity.signature !== 'VALID'))) ||
    (verdict && !verdict.ok);
  return failed ? 1 : 0;
}

if (require.main === module) {
  main().then(rc => process.exit(rc), e => {
    console.error('verifyd certify: ' + (e.code || e.message));
    process.exit(1);
  });
}

module.exports = {
  main,
  renderCertificate,
  renderCompletion,
  normalize
};
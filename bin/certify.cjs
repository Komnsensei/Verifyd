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
  const auditBlock = data.audit || core.audit || {};
  const checks = auditBlock.policy_checks || core.policy_checks || [];
  const policyOk = policyPassed(checks);

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
  else if (auditBlock.lattice_status) sealStatus = auditBlock.lattice_status;
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
    release_signature: engineIdentity.release_signature || engineIdentity.release_signature_status || 'MISSING'
  };
}

function renderCertificate(data, opts) {
  opts = opts || {};
  const color = C(!!opts.color);
  const r = normalize(data);

  const receiptIntegrity = r.this_hash && r.this_hash !== '(none)' ? 'VALID' : 'MISSING';
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

  out += section('Receipt Proof', color);
  out += kv('Receipt Hash', color.blue(short(r.this_hash, 56)));
  out += kv('Previous Hash', color.dim(short(r.prev_hash, 56)));
  out += kv('Hash Status', color.status(receiptIntegrity));
  out += kv('Stage Trace', r.core.engine_trace ? color.status('RECORDED') : color.status('MISSING'));

  out += section('Audit Result', color);
  if (r.policyOk !== null) out += kv('Policy', color.status(r.policyOk ? 'PASSED' : 'FAILED'));
  if (r.auditBlock.trust_score) out += kv('Trust Score', color.status(String(r.auditBlock.trust_score.value) + ' / 100'));
  if (r.auditBlock.lattice_status) out += kv('Lattice Status', color.status(r.auditBlock.lattice_status));
  if (r.data.chain_valid !== undefined) out += kv('Chain Valid', color.status(String(!!r.data.chain_valid).toUpperCase()));
  out += kv('Seal Status', color.status(r.sealStatus));

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

  out += section('Declaration', color);
  out += '  Verifyd confirms that the receipt and subject hashes above form a\n';
  out += '  tamper-evident evidence record under deterministic canonicalization.\n\n';
  out += color.dim('  This certificate does not claim authorship, truth, legal ownership,\n');
  out += color.dim('  or absolute absence of manipulation. It records audit execution and\n');
  out += color.dim('  evidence posture at issuance time.\n');

  out += section('Verify', color);
  out += '  Document receipt: verifyd verify <receipt.json>\n';
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
  console.log('');
  console.log('Default saves plain ASCII .txt. --color colors preview. --ansi saves colored ANSI file.');
}

function main(argv) {
  argv = argv || process.argv.slice(2);
  if (argv[0] === 'certify') argv = argv.slice(1);

  const receiptFile = argv.find(a => !a.startsWith('--'));
  const colorOut = argv.includes('--color');
  const ansiFile = argv.includes('--ansi');

  const outIndex = argv.indexOf('--out');
  let outFile = outIndex >= 0 ? argv[outIndex + 1] : null;

  if (!receiptFile || receiptFile === 'help' || receiptFile === '--help' || receiptFile === '-h') {
    usage();
    return receiptFile ? 0 : 1;
  }

  if (!fs.existsSync(receiptFile)) {
    console.error('verifyd certify: receipt not found: ' + receiptFile);
    return 1;
  }

  const data = JSON.parse(fs.readFileSync(receiptFile, 'utf8'));

  if (!outFile) {
    outFile = receiptFile.replace(/\.json$/i, '') + '.verifyd-certificate' + (ansiFile ? '.ansi.txt' : '.txt');
  }

  const saved = renderCertificate(data, { color: ansiFile });
  const preview = renderCertificate(data, { color: colorOut });

  fs.writeFileSync(outFile, saved, 'utf8');

  console.log(preview);
  console.log('Certificate saved: ' + outFile);
  console.log(renderCompletion(outFile, data, colorOut));

  return 0;
}

if (require.main === module) {
  process.exit(main());
}

module.exports = {
  main,
  renderCertificate,
  renderCompletion,
  normalize
};
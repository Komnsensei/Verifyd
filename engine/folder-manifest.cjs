'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { DEFAULT_LIMITS } = require('./limits.cjs');
const Canonical = require('./canonicalize.cjs');
const SecretScan = require('./secret-scan.cjs');
const FileType = require('./file-type.cjs');

function sha256Buffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function posixRel(root, file) {
  const rel = path.relative(root, file);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    const e = new Error('PATH_TRAVERSAL_REJECTED');
    e.code = 'PATH_TRAVERSAL_REJECTED';
    throw e;
  }
  return rel.split(path.sep).join('/');
}

function shouldExclude(rel, opts) {
  const excludes = opts.exclude || [
    '.git/',
    'node_modules/',
    '.env',
    '.DS_Store',
    'Thumbs.db'
  ];

  return excludes.some(x => {
    if (x.endsWith('/')) return rel === x.slice(0, -1) || rel.startsWith(x);
    return rel === x || rel.endsWith('/' + x);
  });
}

function walk(root, opts, out) {
  opts = opts || {};
  out = out || [];

  const entries = fs.readdirSync(root, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name));

  for (const ent of entries) {
    const full = path.join(root, ent.name);
    const st = fs.lstatSync(full);

    if (st.isSymbolicLink()) {
      const e = new Error('SYMLINK_REJECTED: ' + full);
      e.code = 'SYMLINK_REJECTED';
      throw e;
    }

    if (st.isDirectory()) {
      walk(full, opts, out);
    } else if (st.isFile()) {
      out.push(full);
    } else {
      const e = new Error('UNSUPPORTED_FILE_TYPE: ' + full);
      e.code = 'UNSUPPORTED_FILE_TYPE';
      throw e;
    }
  }

  return out;
}

function buildManifest(rootDir, opts) {
  opts = opts || {};
  const limits = Object.assign({}, DEFAULT_LIMITS, opts.limits || {});
  const root = path.resolve(rootDir);

  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    const e = new Error('FOLDER_NOT_FOUND');
    e.code = 'FOLDER_NOT_FOUND';
    throw e;
  }

  const files = walk(root, opts, []);
  const manifest = [];
  let total = 0;
  const seen = new Set();
  let excluded_count = 0;

  for (const full of files) {
    const rel = posixRel(root, full);

    if (shouldExclude(rel, opts)) {
      excluded_count++;
      continue;
    }

    if (seen.has(rel)) {
      const e = new Error('DUPLICATE_NORMALIZED_PATH: ' + rel);
      e.code = 'DUPLICATE_NORMALIZED_PATH';
      throw e;
    }
    seen.add(rel);

    const before = fs.statSync(full);
    const buf = fs.readFileSync(full);
    const after = fs.statSync(full);

    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      const e = new Error('FILE_CHANGED_DURING_AUDIT: ' + rel);
      e.code = 'FILE_CHANGED_DURING_AUDIT';
      throw e;
    }

    total += buf.length;
    if (manifest.length + 1 > limits.maxFolderFiles) {
      const e = new Error('FOLDER_FILE_LIMIT_EXCEEDED');
      e.code = 'FOLDER_FILE_LIMIT_EXCEEDED';
      throw e;
    }
    if (total > limits.maxFolderBytes) {
      const e = new Error('FOLDER_BYTE_LIMIT_EXCEEDED');
      e.code = 'FOLDER_BYTE_LIMIT_EXCEEDED';
      throw e;
    }

    const textish = /\.(txt|md|json|js|cjs|mjs|ts|tsx|jsx|css|html|xml|yml|yaml|env)$/i.test(rel);
    let secret = { has_secret: false };
    if (textish) secret = SecretScan.scanText(buf.toString('utf8'));

    if (opts.strict && secret.has_secret) {
      const e = new Error('SECRET_DETECTED_IN_FOLDER: ' + rel);
      e.code = 'SECRET_DETECTED_IN_FOLDER';
      throw e;
    }

    manifest.push({
      path: rel,
      size_bytes: buf.length,
      sha256: sha256Buffer(buf),
      magic_type: FileType.detectMagic(buf)
    });
  }

  manifest.sort((a, b) => a.path.localeCompare(b.path));

  const canonical = Canonical.canonicalJSON({
    manifest_version: 'verifyd-folder-manifest-v1',
    root_label: path.basename(root),
    entries: manifest
  });

  const manifest_hash = sha256Buffer(Buffer.from(canonical, 'utf8'));

  return {
    manifest_version: 'verifyd-folder-manifest-v1',
    root_label: path.basename(root),
    file_count: manifest.length,
    excluded_count,
    total_size_bytes: total,
    path_normalization: 'posix-relative-v1',
    symlink_policy: 'reject',
    manifest_hash: 'sha256:' + manifest_hash,
    entries: manifest
  };
}

function verifyManifest(rootDir, expected, opts) {
  const actual = buildManifest(rootDir, opts || {});
  const ok = actual.manifest_hash === expected.manifest_hash;
  return { valid: ok, actual, expected_hash: expected.manifest_hash, actual_hash: actual.manifest_hash };
}

module.exports = { buildManifest, verifyManifest };

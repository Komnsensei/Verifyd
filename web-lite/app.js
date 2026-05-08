'use strict';

const $ = id => document.getElementById(id);

let currentReceipt = null;
let currentCertificate = '';

function bytes(n) {
  if (!Number.isFinite(n)) return '0 bytes';
  const units = ['bytes', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(2)) + ' ' + units[i];
}

function hex(buffer) {
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256File(file) {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return hex(digest);
}

async function sha256Text(text) {
  const buf = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return hex(digest);
}

function canonicalJSONString(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(v) {
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(sortValue);
  const out = {};
  for (const k of Object.keys(v).sort()) out[k] = sortValue(v[k]);
  return out;
}

function safePath(file) {
  return file.webkitRelativePath || file.name;
}

async function auditFiles(files) {
  files = Array.from(files || []);
  if (!files.length) return;

  const issued = new Date().toISOString();

  if (files.length === 1 && !files[0].webkitRelativePath) {
    const file = files[0];
    const h = await sha256File(file);

    const receipt = {
      valf_version: 'web-lite-0.1',
      receipt_type: 'web_file',
      audit_mode: 'web_file',
      receipt_id: crypto.randomUUID(),
      created_at: issued,
      engine_identity: {
        engine_authenticity: 'WEB LITE / UNSIGNED',
        policy_profile: 'verifyd-web-lite-v0',
        release_signature: 'MISSING'
      },
      subject: {
        name: file.name,
        type: file.type || 'application/octet-stream',
        size_bytes: file.size,
        sha256: 'sha256:' + h
      },
      evidence: {
        local_browser_hashing: true,
        uploaded: false,
        webcrypto_sha256: true
      }
    };

    receipt.this_hash = 'sha256:' + await sha256Text(canonicalJSONString({...receipt, this_hash: undefined}));

    showReceipt(receipt);
    return;
  }

  const entries = [];
  let total = 0;

  for (const file of files) {
    const h = await sha256File(file);
    const p = safePath(file).replaceAll('\\', '/');
    total += file.size;
    entries.push({
      path: p,
      size_bytes: file.size,
      sha256: 'sha256:' + h,
      type: file.type || 'application/octet-stream'
    });
  }

  entries.sort((a, b) => a.path.localeCompare(b.path));

  const manifestBody = {
    manifest_version: 'verifyd-web-folder-manifest-v0',
    entries
  };

  const manifestHash = 'sha256:' + await sha256Text(canonicalJSONString(manifestBody));
  const rootLabel = entries[0] && entries[0].path.includes('/') ? entries[0].path.split('/')[0] : 'browser-folder';

  const receipt = {
    valf_version: 'web-lite-0.1',
    receipt_type: 'web_folder',
    audit_mode: 'folder',
    receipt_id: crypto.randomUUID(),
    created_at: issued,
    engine_identity: {
      engine_authenticity: 'WEB LITE / UNSIGNED',
      policy_profile: 'verifyd-web-lite-v0',
      release_signature: 'MISSING'
    },
    folder: {
      root_label: rootLabel,
      file_count: entries.length,
      total_size_bytes: total,
      manifest_hash: manifestHash,
      path_normalization: 'browser-relative-posix-v0',
      symlink_policy: 'not exposed by browser'
    },
    manifest: {
      ...manifestBody,
      manifest_hash: manifestHash
    },
    evidence: {
      local_browser_hashing: true,
      uploaded: false,
      webcrypto_sha256: true
    }
  };

  receipt.this_hash = 'sha256:' + await sha256Text(canonicalJSONString({...receipt, this_hash: undefined}));

  showReceipt(receipt);
}

function short(s, n = 56) {
  if (!s) return '(none)';
  s = String(s);
  if (s.length <= n) return s;
  const left = Math.floor((n - 3) / 2);
  return s.slice(0, left) + '...' + s.slice(-(n - 3 - left));
}

function cert(receipt) {
  const isFolder = !!receipt.folder;
  const subjectName = isFolder ? receipt.folder.root_label : receipt.subject.name;
  const subjectType = isFolder ? 'folder' : receipt.subject.type;
  const subjectSize = isFolder ? receipt.folder.total_size_bytes : receipt.subject.size_bytes;
  const subjectHash = isFolder ? receipt.folder.manifest_hash : receipt.subject.sha256;

  return [
    '+============================================================================+',
    '|                                  VERIFYD                                    |',
    '|                    WEB LITE TAMPER-EVIDENT CERTIFICATE                     |',
    '|                  local browser receipt / no upload                         |',
    '+----------------------------------------------------------------------------+',
    '| SEAL STATUS        VALID             AUDIT MODE         ' + (isFolder ? 'folder' : 'file').padEnd(18) + ' |',
    '| RECEIPT INTEGRITY  VALID             ENGINE AUTH        WEB LITE / UNSIGNED |',
    '| POLICY PROFILE     verifyd-web-lite-v0 RELEASE SIG        MISSING          |',
    '+============================================================================+',
    '',
    '-- SUBJECT -------------------------------------------------------------------',
    '  Name:               ' + subjectName,
    '  Type:               ' + subjectType,
    '  Size:               ' + bytes(subjectSize),
    '  Primary Hash:       ' + short(subjectHash),
    '',
    '-- RECEIPT PROOF -------------------------------------------------------------',
    '  Receipt ID:         ' + receipt.receipt_id,
    '  Receipt Hash:       ' + short(receipt.this_hash),
    '  Issued At:          ' + receipt.created_at,
    '  Local Hashing:      TRUE',
    '  Uploaded:           FALSE',
    '',
    isFolder ? '-- FOLDER MANIFEST -----------------------------------------------------------\n' +
      '  Files:              ' + receipt.folder.file_count + '\n' +
      '  Total Size:         ' + bytes(receipt.folder.total_size_bytes) + '\n' +
      '  Manifest Hash:      ' + short(receipt.folder.manifest_hash) + '\n' +
      '  Path Mode:          ' + receipt.folder.path_normalization + '\n'
      : '',
    '-- ENGINE AUTHENTICITY -------------------------------------------------------',
    '  Engine Auth:        WEB LITE / UNSIGNED',
    '  Policy Profile:     verifyd-web-lite-v0',
    '  Release Signature:  MISSING',
    '  Note: Browser receipts are locally checkable but not signed release proofs.',
    '',
    '-- DECLARATION ---------------------------------------------------------------',
    '  Verifyd Web Lite records hashes and evidence posture in your browser.',
    '  It does not prove truth, authorship, legal ownership, or official engine',
    '  authenticity. Files are not uploaded by this page.',
    '',
    '-- CANONICAL LAW -------------------------------------------------------------',
    '  Never coerce. Expand meaning. Archive everything.',
    '+============================================================================+'
  ].filter(Boolean).join('\n');
}

function showReceipt(receipt) {
  currentReceipt = receipt;
  currentCertificate = cert(receipt);

  const isFolder = !!receipt.folder;
  $('resultPanel').classList.remove('hidden');
  $('resultTitle').textContent = isFolder ? 'Folder receipt ready' : 'File receipt ready';
  $('sealStatus').textContent = 'VALID';
  $('subjectName').textContent = isFolder ? receipt.folder.root_label : receipt.subject.name;
  $('auditMode').textContent = isFolder ? 'folder' : 'file';
  $('subjectSize').textContent = bytes(isFolder ? receipt.folder.total_size_bytes : receipt.subject.size_bytes);
  $('primaryHash').textContent = isFolder ? receipt.folder.manifest_hash : receipt.subject.sha256;
  $('certificatePreview').textContent = currentCertificate;

  $('resultPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function download(name, content, type) {
  const blob = new Blob([content], { type });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

$('fileInput').addEventListener('change', e => auditFiles(e.target.files));
$('folderInput').addEventListener('change', e => auditFiles(e.target.files));

const dz = $('dropzone');

['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => {
  e.preventDefault();
  dz.classList.add('drag');
}));

['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => {
  e.preventDefault();
  dz.classList.remove('drag');
}));

dz.addEventListener('drop', e => {
  const files = e.dataTransfer.files;
  auditFiles(files);
});

$('downloadReceipt').addEventListener('click', () => {
  if (!currentReceipt) return;
  download('verifyd-web-lite-receipt.json', JSON.stringify(currentReceipt, null, 2), 'application/json');
});

$('downloadCert').addEventListener('click', () => {
  if (!currentCertificate) return;
  download('verifyd-web-lite-certificate.txt', currentCertificate, 'text/plain');
});

$('copyCert').addEventListener('click', async () => {
  if (!currentCertificate) return;
  await navigator.clipboard.writeText(currentCertificate);
  $('copyCert').textContent = 'Copied';
  setTimeout(() => $('copyCert').textContent = 'Copy Certificate', 1200);
});
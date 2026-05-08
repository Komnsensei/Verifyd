'use strict';

const $ = id => document.getElementById(id);
let receipt = null;

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

function sortValue(v) {
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(sortValue);
  const out = {};
  for (const k of Object.keys(v).sort()) out[k] = sortValue(v[k]);
  return out;
}

$('fileInput').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;

  const h = await sha256File(file);

  receipt = {
    valf_version: 'web-lite-extension-0.1',
    receipt_type: 'web_file',
    audit_mode: 'web_file',
    receipt_id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
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

  receipt.this_hash = 'sha256:' + await sha256Text(JSON.stringify(sortValue({...receipt, this_hash: undefined})));

  $('hash').textContent = receipt.subject.sha256;
  $('result').classList.remove('hidden');
});

$('download').addEventListener('click', () => {
  if (!receipt) return;
  const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'verifyd-extension-receipt.json';
  a.click();
});
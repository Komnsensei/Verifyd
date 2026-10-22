#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const dir = process.argv[2] || path.join(__dirname, '..', 'auditdeck');
const pdfs = fs.readdirSync(dir).filter(f => f.toLowerCase().endsWith('.pdf'));
console.log('Found ' + pdfs.length + ' PDFs');

const VERIFYD = path.join(__dirname, 'verifyd.cjs');
const CERTIFY = path.join(__dirname, 'certify.cjs');
const summary = [];

for (let i = 0; i < pdfs.length; i++) {
  const pdf = pdfs[i];
  const full = path.join(dir, pdf);
  process.stdout.write('[' + (i+1) + '/' + pdfs.length + '] ' + pdf.slice(0,55) + ' ');
  try {
    execSync('node "' + VERIFYD + '" audit "' + full + '"', { stdio: 'pipe' });
    const receiptFile = full.replace(/\.pdf$/i, '.verifyd-receipt.json');
    if (fs.existsSync(receiptFile)) {
      execSync('node "' + CERTIFY + '" "' + receiptFile + '"', { stdio: 'pipe' });
      const data = JSON.parse(fs.readFileSync(receiptFile, 'utf8'));
      summary.push({
        file: pdf,
        words: data.document.words,
        sha: data.document.sha256.slice(0, 12),
        trust: data.audit.trust_score.value,
        lattice: data.audit.lattice_status,
        receipt: data.receipt.this_hash.slice(0, 12),
        valid: data.chain_valid
      });
      console.log('OK ' + data.audit.trust_score.value + '/100');
    } else {
      console.log('FAIL no receipt');
      summary.push({ file: pdf, error: 'no receipt produced' });
    }
  } catch (e) {
    summary.push({ file: pdf, error: String(e.message).slice(0, 80) });
    console.log('ERR');
  }
}

console.log('\n=== AUDITDECK BATCH SUMMARY ===\n');
let ok = 0;
summary.forEach((s, i) => {
  console.log((i+1) + '. ' + s.file);
  if (s.error) {
    console.log('   FAIL: ' + s.error);
  } else {
    ok++;
    console.log('   words=' + s.words + ' trust=' + s.trust + '/100 lattice=' + s.lattice);
    console.log('   sha=' + s.sha + '... receipt=' + s.receipt + '... valid=' + s.valid);
  }
});
console.log('\nSealed: ' + ok + '/' + summary.length);

fs.writeFileSync(path.join(dir, 'BATCH_SUMMARY.json'),
  JSON.stringify({ run_at: new Date().toISOString(), folder: dir, results: summary }, null, 2));
console.log('Summary: ' + path.join(dir, 'BATCH_SUMMARY.json'));

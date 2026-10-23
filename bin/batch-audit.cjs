#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const dir = process.argv[2] || path.join(__dirname, '..', 'auditdeck');
if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
  console.error('batch-audit: folder not found: ' + dir);
  console.error('Usage: node bin/batch-audit.cjs <folder-of-pdfs>');
  process.exit(1);
}
const pdfs = fs.readdirSync(dir).filter(f => f.toLowerCase().endsWith('.pdf'));
if (pdfs.length === 0) {
  console.error('batch-audit: no PDFs in ' + dir);
  process.exit(1);
}
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
      let certified = false;
      try {
        execSync('node "' + CERTIFY + '" "' + receiptFile + '"', { stdio: 'pipe' });
        certified = true;
      } catch (e) {
        certified = false;
      }
      // Sealing is not trust. Verify each receipt with the same verifier a
      // reader would use, under the keyring that signed it, and report both.
      let verified = false;
      let verifyError = null;
      try {
        execSync('node "' + VERIFYD + '" verify "' + receiptFile + '"', { stdio: 'pipe' });
        verified = true;
      } catch (e) {
        const text = String((e.stdout || '') + (e.stderr || ''));
        const reason = text.split(/\r?\n/).map(line => line.trim()).filter(line => /^Reason:/.test(line)).pop();
        verifyError = reason ? reason.replace(/^Reason:\s*/, '') : 'verification failed';
      }
      const data = JSON.parse(fs.readFileSync(receiptFile, 'utf8'));
      const r = data.receipt || {};
      summary.push({
        file: pdf,
        words: data.document.words,
        sha: data.document.sha256.slice(0, 12),
        quality: r.document_quality ? r.document_quality.value : null,
        lattice: r.lattice ? r.lattice.status : null,
        receipt: String(r.this_hash || '').slice(0, 12),
        signed: Boolean(data.signature && data.signature.value),
        verified,
        certified,
        verify_error: verifyError
      });
      console.log('OK ' + (r.document_quality ? 'quality=' + r.document_quality.value + '/100' : 'no quality') +
        (data.signature ? ' signed' : ' UNSIGNED') +
        (verified ? ' verified' : ' NOT VERIFIED (' + verifyError + ')'));
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
let verifiedCount = 0;
let certifiedCount = 0;
summary.forEach((s, i) => {
  console.log((i+1) + '. ' + s.file);
  if (s.error) {
    console.log('   FAIL: ' + s.error);
  } else {
    ok++;
    if (s.verified) verifiedCount++;
    if (s.certified) certifiedCount++;
    console.log('   words=' + s.words + ' quality=' + s.quality + '/100 (heuristic) lattice=' + s.lattice);
    console.log('   sha=' + s.sha + '... receipt=' + s.receipt + '... signed=' + s.signed +
      ' verified=' + s.verified + (s.verify_error ? ' (' + s.verify_error + ')' : ''));
  }
});
console.log('\nSealed: ' + ok + '/' + summary.length);
console.log('Verified: ' + verifiedCount + '/' + summary.length + ' under the keyring that signed them');
console.log('Certified: ' + certifiedCount + '/' + summary.length);
if (ok !== summary.length || verifiedCount !== summary.length) process.exitCode = 1;

fs.writeFileSync(path.join(dir, 'BATCH_SUMMARY.json'),
  JSON.stringify({ run_at: new Date().toISOString(), folder: dir, results: summary }, null, 2));
console.log('Summary: ' + path.join(dir, 'BATCH_SUMMARY.json'));

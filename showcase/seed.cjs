'use strict';

// Regenerates showcase/data/cases.json from the scenario corpus.
// Every receipt is sealed through the real Verifyd engine.

const fs = require('fs');
const path = require('path');
const { buildCampus } = require('./lib/campus.cjs');

const outDir = path.join(__dirname, 'data');
const outFile = path.join(outDir, 'cases.json');

const data = buildCampus();
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(outFile, JSON.stringify(data, null, 2) + '\n');

console.log('Seeded ' + data.cases.length + ' campus cases');
console.log('Receipts sealed: ' + data.summary.sealed + ' / chain valid: ' + data.summary.chain_valid);
data.cases.forEach(c => {
  const v = c.verification;
  const flag = c.status === 'TAMPERED' ? ' (tamper detected)' : c.status === 'BLOCKED' ? ' (refused)' : '';
  console.log('  ' + c.case_no.padEnd(9) + c.status.padEnd(11) + 'trust ' + String(c.trust_score.value).padStart(3) + '/100  ' + (v && v.valid ? 'VALID' : 'INVALID') + flag);
});
console.log('Wrote ' + outFile);

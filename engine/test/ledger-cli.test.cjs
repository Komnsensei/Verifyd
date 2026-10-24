// Ledger CLI end to end: audit --ledger, verify --ledger, chain verify and the
// certificate agree because they read the same evidence object.
//
// The receipt carries an unsigned ledger block, so these tests also pin the
// rule that a false claim is REJECTED while a receipt with no block is not.

'use strict';

const test = require('node:test');
const assert = require('node:assert');

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(ROOT, 'bin', 'verifyd.cjs');
const Ledger = require('../ledger.cjs');

function run(args, env) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: Object.assign({}, process.env, env),
  });
}

function checkpointFile(ledgerPath) {
  return Ledger.ledgerPaths(ledgerPath).checkpoints;
}

test('audit --ledger, verify --ledger, chain verify and certify agree', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-cli-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const keyring = path.join(dir, 'keys');
  const ledger = path.join(dir, 'ledger.jsonl');
  const env = { VERIFYD_KEYRING: keyring };

  assert.equal(run(['keys', 'init'], env).status, 0);
  assert.equal(run(['chain', 'init', '--ledger', ledger], env).status, 0);

  const docs = [];
  for (let i = 0; i < 2; i++) {
    const file = path.join(dir, 'doc' + i + '.txt');
    fs.writeFileSync(file, 'Audit document ' + i + ' about evidence and receipts.\n');
    docs.push(file);
    const audited = run(['audit', file, '--ledger', ledger], env);
    assert.equal(audited.status, 0, audited.stderr);
    assert.match(audited.stdout, /Ledger: {7}IN CHAIN \(seq \d+, tree \d+, UNANCHORED\)/);
  }

  const receipt = docs[0].replace(/\.txt$/, '.verifyd-receipt.json');
  const verified = run(['verify', receipt, '--ledger', ledger], env);
  assert.equal(verified.status, 0, verified.stderr);
  assert.match(verified.stdout, /Ledger: {7}IN CHAIN \(UNANCHORED\)/);
  assert.match(verified.stdout, /Status: {7}VALID/);

  // Without --ledger the verdict is receipt integrity only, and says so.
  const unchecked = run(['verify', receipt], env);
  assert.equal(unchecked.status, 0, unchecked.stderr);
  assert.match(unchecked.stdout, /Ledger: {7}NOT CHECKED \(no --ledger\)/);
  assert.match(unchecked.stdout, /Status: {7}VALID/);

  // chain verify: local walk plus an anchor file taken from the ledger.
  const checkpoints = fs.readFileSync(checkpointFile(ledger), 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  const genesis = checkpoints[0];
  const first = checkpoints.find(c => c.tree_size === 1);
  const anchor = path.join(dir, 'anchor.json');
  fs.writeFileSync(anchor, JSON.stringify(first, null, 2) + '\n');
  const chainOk = run(['chain', 'verify', '--ledger', ledger, '--anchor', anchor], env);
  assert.equal(chainOk.status, 0, chainOk.stderr);
  assert.match(chainOk.stdout, /Ledger: {7}VALID \(anchored incremental, tree 2, anchor 1\)/);

  const localOnly = run(['chain', 'verify', '--ledger', ledger], env);
  assert.equal(localOnly.status, 0, localOnly.stderr);
  assert.match(localOnly.stdout, /Ledger: {7}VALID \(full local, tree 2, UNANCHORED\)/);

  // A retained head with another root at this size is a fork, exit 1.
  const head = JSON.parse(fs.readFileSync(checkpointFile(ledger), 'utf8').split('\n').filter(Boolean).slice(-1)[0]);
  const heads = path.join(dir, 'heads.jsonl');
  fs.writeFileSync(heads, JSON.stringify({
    ledger_id: genesis.checkpoint_hash,
    tree_size: 2,
    root_hash: 'a'.repeat(64),
    checkpoint_hash: 'b'.repeat(64),
  }) + '\n');
  const fork = run(['chain', 'verify', '--ledger', ledger, '--heads', heads], env);
  assert.equal(fork.status, 1);
  assert.match(fork.stdout, /Ledger: {7}FORK/);

  // --require-anchor turns an unanchored membership into a failure.
  const required = run(['verify', receipt, '--ledger', ledger, '--require-anchor'], env);
  assert.equal(required.status, 1);
  assert.match(required.stdout, /Status: {7}REJECTED/);

  // certify reads the same evidence: passed here, rejected after the block is
  // altered, and never with its own ledger check.
  const certOk = run(['certify', receipt, '--ledger', ledger, '--out', path.join(dir, 'ok.txt')], env);
  assert.equal(certOk.status, 0, certOk.stderr);
  assert.match(certOk.stdout, /Ledger: +IN CHAIN +\(UNANCHORED\)/);
  assert.match(certOk.stdout, /Verification: +PASSED/);

  const data = JSON.parse(fs.readFileSync(receipt, 'utf8'));
  data.ledger.seq = 9;
  fs.writeFileSync(receipt, JSON.stringify(data, null, 2) + '\n');
  const certBad = run(['certify', receipt, '--ledger', ledger, '--out', path.join(dir, 'bad.txt')], env);
  assert.equal(certBad.status, 1);
  assert.match(certBad.stdout, /Ledger: +NOT IN CHAIN/);
  assert.match(certBad.stdout, /Verification: +REJECTED/);

  const verifyBad = run(['verify', receipt, '--ledger', ledger], env);
  assert.equal(verifyBad.status, 1);
  assert.match(verifyBad.stdout, /Status: {7}REJECTED/);
  assert.match(verifyBad.stdout, /Reason: {7}ledger not in chain/);

  // The tampered block is outside the signature, so the signature itself stays
  // valid: the rejection is the membership claim, not the receipt bytes.
  assert.match(verifyBad.stdout, /Signature: {4}VALID/);
});

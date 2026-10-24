// Equivalence of the incremental RFC 6962 frontier with a full rebuild.
//
// inspectLedger computes every checkpoint's prefix root in one pass. The rest of
// the suite only builds ledgers up to 8 entries, so this file crosses that
// ceiling on purpose: 64 entries, every size 0..64, three independent digest
// sets, plus one non-contiguous size list. Each size is compared with
// Merkle.buildTree over the same prefix, which is the definition the frontier
// has to match. 64 keeps the whole file under a second while still covering
// many carries, non-powers of two and sizes the suite never reaches.

'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const test = require('node:test');

const Merkle = require('../merkle.cjs');
const { prefixRoots } = require('../ledger-store.cjs');

const MAX = 64;

function digestSet(seed, count) {
  const digests = [];
  let previous = Buffer.from(seed.padEnd(32, '.').slice(0, 32));
  for (let i = 0; i < count; i++) {
    previous = crypto.createHash('sha256').update(previous).update(String(i)).digest();
    digests.push(previous.toString('hex'));
  }
  return digests;
}

function fullRoot(digests, size) {
  if (size === 0) return Merkle.rootHash(0, Merkle.sha256(Buffer.alloc(0))).toString('hex');
  const leaves = digests.slice(0, size).map(digest => Buffer.from(digest, 'hex'));
  return Merkle.buildTree(leaves).root.toString('hex');
}

test('the incremental frontier agrees with a full rebuild at every size 0..64', () => {
  const sizes = Array.from({ length: MAX + 1 }, (_, size) => size);
  for (const seed of ['alpha', 'beta', 'gamma']) {
    const digests = digestSet(seed, MAX);
    const roots = Array.from(prefixRoots(digests, sizes));
    assert.deepEqual(roots.map(([size]) => size), sizes, 'roots must be yielded in order');
    for (const [size, root] of roots) {
      assert.equal(root, fullRoot(digests, size),
        'seed ' + seed + ', size ' + size + ': incremental root differs from buildTree');
    }
  }
});

test('the incremental frontier agrees across skipped checkpoint sizes', () => {
  const digests = digestSet('skips', MAX);
  const sizes = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 64];
  const roots = Array.from(prefixRoots(digests, sizes));
  assert.deepEqual(roots.map(([size]) => size), sizes);
  for (const [size, root] of roots) {
    assert.equal(root, fullRoot(digests, size), 'skipped-size root differs at ' + size);
  }
});

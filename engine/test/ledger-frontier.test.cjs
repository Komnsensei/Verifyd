// The frontier is the single producer of incrementally added roots and inclusion
// paths. This file pins both against the batch functions it replaces for append:
// buildTree for the root and inclusion() for the path, at every size 1..64.
// 64 crosses the 8-entry ceiling the rest of the suite never passes and covers
// every carry shape, while keeping the file well under the default test budget.

'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const test = require('node:test');

const Merkle = require('../merkle.cjs');

const MAX = 64;

function digestSet(seed, count) {
  const digests = [];
  let previous = Buffer.from(seed.padEnd(32, '.').slice(0, 32));
  for (let i = 0; i < count; i++) {
    previous = crypto.createHash('sha256').update(previous).update(String(i)).digest();
    digests.push(previous);
  }
  return digests;
}

test('frontier roots and inclusion paths match buildTree and inclusion at every size', () => {
  for (const seed of ['frontier-one', 'frontier-two']) {
    const buffers = digestSet(seed, MAX);
    const frontier = Merkle.createFrontier();

    for (let index = 0; index < MAX; index++) {
      const appended = frontier.append(buffers[index]);
      assert.equal(appended.size, index + 1);

      const tree = Merkle.buildTree(buffers.slice(0, index + 1));
      assert.equal(appended.root.toString('hex'), tree.root.toString('hex'),
        'seed ' + seed + ', size ' + (index + 1) + ': frontier root differs from buildTree');
      assert.equal(frontier.root().toString('hex'), tree.root.toString('hex'),
        'seed ' + seed + ', size ' + (index + 1) + ': root() differs from the append root');

      const included = Merkle.inclusion(index, buffers.slice(0, index + 1));
      assert.deepEqual(
        appended.path.map(hash => hash.toString('hex')),
        included.path.map(hash => hash.toString('hex')),
        'seed ' + seed + ', size ' + (index + 1) + ': inclusion path differs');
    }
  }
});

test('push grows the frontier without changing its root sequence', () => {
  const buffers = digestSet('push', MAX);
  const frontier = Merkle.createFrontier();
  assert.equal(frontier.size, 0);
  assert.equal(frontier.root().toString('hex'),
    Merkle.rootHash(0, Merkle.sha256(Buffer.alloc(0))).toString('hex'));
  for (let index = 0; index < MAX; index++) {
    assert.equal(frontier.push(buffers[index]), index + 1);
    assert.equal(frontier.root().toString('hex'), Merkle.buildTree(buffers.slice(0, index + 1)).root.toString('hex'));
  }
});

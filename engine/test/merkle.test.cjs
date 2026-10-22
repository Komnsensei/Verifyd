'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const Merkle = require('../merkle.cjs');

function digest(label) {
  return crypto.createHash('sha256').update(label).digest();
}

function leaves(n) {
  return Array.from({ length: n }, (_, i) => digest('receipt-' + i));
}

// Deliberately separate implementation of the same RFC 6962 shape, used only
// to cross-check the module's roots.
function referenceRoot(payloadDigests) {
  const left = Buffer.from([0x00]);
  const right = Buffer.from([0x01]);
  const leaf = d => crypto.createHash('sha256').update(Buffer.concat([left, d])).digest();
  const node = (a, b) => crypto.createHash('sha256').update(Buffer.concat([right, a, b])).digest();
  function mth(nodes) {
    if (nodes.length === 0) return crypto.createHash('sha256').update(Buffer.alloc(0)).digest();
    if (nodes.length === 1) return nodes[0];
    let k = 1;
    while (k * 2 < nodes.length) k *= 2;
    return node(mth(nodes.slice(0, k)), mth(nodes.slice(k)));
  }
  const size = Buffer.alloc(8);
  size.writeBigUInt64BE(BigInt(payloadDigests.length));
  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x02]), size, mth(payloadDigests.map(leaf))]))
    .digest();
}

test('roots match an independent RFC 6962 implementation for sizes 1..9', () => {
  for (let n = 1; n <= 9; n++) {
    const tree = Merkle.buildTree(leaves(n));
    assert.strictEqual(tree.root.toString('hex'), referenceRoot(leaves(n)).toString('hex'), 'size ' + n);
  }
});

test('the root is deterministic and order binds', () => {
  const set = leaves(5);
  const a = Merkle.buildTree(set).root.toString('hex');
  const b = Merkle.buildTree(set).root.toString('hex');
  assert.strictEqual(a, b, 'same leaves in the same order give the same root');

  const reordered = [set[1], set[0], set[2], set[3], set[4]];
  assert.notStrictEqual(Merkle.buildTree(reordered).root.toString('hex'), a, 'order is part of the commitment');
});

test('leaf and internal nodes are domain separated', () => {
  const d = digest('one');
  assert.notStrictEqual(
    Merkle.leafHash(d).toString('hex'),
    crypto.createHash('sha256').update(d).digest('hex'),
    'a leaf is not the bare digest'
  );
  assert.notStrictEqual(
    Merkle.leafHash(d).toString('hex'),
    Merkle.nodeHash(d, d).toString('hex'),
    'a leaf hash cannot be read as an internal node'
  );
});

test('every index verifies for every size', () => {
  for (let n = 1; n <= 9; n++) {
    const set = leaves(n);
    const tree = Merkle.buildTree(set);
    for (let i = 0; i < n; i++) {
      const proof = Merkle.inclusion(i, set);
      assert.strictEqual(proof.path.length, Merkle.depthFor(i, n), 'path depth for ' + i + '/' + n);
      const res = Merkle.verifyInclusion({
        index: i,
        size: n,
        leafDigest: set[i],
        path: proof.path.map(h => h.toString('hex')),
        root: tree.root.toString('hex'),
      });
      assert.strictEqual(res.ok, true, 'index ' + i + ' of ' + n + ': ' + res.reason);
    }
  }
});

test('a single-leaf tree has an empty path and a size-bound root', () => {
  const set = leaves(1);
  const proof = Merkle.inclusion(0, set);
  assert.deepStrictEqual(proof.path, []);
  assert.notStrictEqual(proof.root.toString('hex'), Merkle.leafHash(set[0]).toString('hex'));
  assert.strictEqual(proof.root.toString('hex'),
    Merkle.rootHash(1, Merkle.leafHash(set[0])).toString('hex'));

  const res = Merkle.verifyInclusion({
    index: 0,
    size: 1,
    leafDigest: set[0],
    path: [],
    root: proof.root.toString('hex'),
  });
  assert.strictEqual(res.ok, true, res.reason);
});

test('an altered leaf is rejected', () => {
  const set = leaves(4);
  const proof = Merkle.inclusion(2, set);
  const res = Merkle.verifyInclusion({
    index: 2,
    size: 4,
    leafDigest: digest('not-in-the-batch'),
    path: proof.path.map(h => h.toString('hex')),
    root: proof.root.toString('hex'),
  });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'root_mismatch');
});

test('a reordered path is rejected', () => {
  const set = leaves(4);
  const proof = Merkle.inclusion(0, set);
  assert.ok(proof.path.length >= 2);
  const path = proof.path.map(h => h.toString('hex'));
  [path[0], path[1]] = [path[1], path[0]];

  const res = Merkle.verifyInclusion({ index: 0, size: 4, leafDigest: set[0], path, root: proof.root.toString('hex') });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'root_mismatch');
});

test('a shortened path is rejected', () => {
  const set = leaves(4);
  const proof = Merkle.inclusion(1, set);
  const path = proof.path.map(h => h.toString('hex'));
  path.pop();

  const res = Merkle.verifyInclusion({ index: 1, size: 4, leafDigest: set[1], path, root: proof.root.toString('hex') });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'invalid_path_length');
});

test('an extended path is rejected', () => {
  const set = leaves(4);
  const proof = Merkle.inclusion(1, set);
  const path = proof.path.map(h => h.toString('hex')).concat([digest('extra').toString('hex')]);

  const res = Merkle.verifyInclusion({ index: 1, size: 4, leafDigest: set[1], path, root: proof.root.toString('hex') });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'invalid_path_length');
});

test('a wrong leaf index is rejected', () => {
  const set = leaves(4);
  const proof = Merkle.inclusion(1, set);

  for (const index of [0, 2, 3]) {
    const res = Merkle.verifyInclusion({
      index,
      size: 4,
      leafDigest: set[1],
      path: proof.path.map(h => h.toString('hex')),
      root: proof.root.toString('hex'),
    });
    assert.strictEqual(res.ok, false, 'index ' + index + ' must not verify');
  }
});

test('a tree size that does not match is rejected', () => {
  const set = leaves(4);
  const proof = Merkle.inclusion(0, set);

  for (const size of [3, 5, 8]) {
    const res = Merkle.verifyInclusion({
      index: 0,
      size,
      leafDigest: set[0],
      path: proof.path.map(h => h.toString('hex')),
      root: proof.root.toString('hex'),
    });
    assert.strictEqual(res.ok, false, 'size ' + size + ' must not verify');
  }
});

test('a proof from another batch is rejected', () => {
  const batchA = leaves(4);
  const batchB = [digest('other-0'), digest('other-1'), digest('other-2'), digest('other-3')];
  const proofA = Merkle.inclusion(2, batchA);
  const rootA = Merkle.buildTree(batchA).root.toString('hex');

  const res = Merkle.verifyInclusion({
    index: 2,
    size: 4,
    leafDigest: batchB[2],
    path: proofA.path.map(h => h.toString('hex')),
    root: rootA,
  });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'root_mismatch');
});

test('malformed inputs are rejected, not thrown', () => {
  const set = leaves(2);
  const proof = Merkle.inclusion(0, set);
  const root = proof.root.toString('hex');
  const path = proof.path.map(h => h.toString('hex'));

  assert.strictEqual(Merkle.verifyInclusion({ index: 0, size: 2, leafDigest: set[0], path: ['zz'], root }).reason, 'malformed_path_hash');
  assert.strictEqual(Merkle.verifyInclusion({ index: -1, size: 2, leafDigest: set[0], path, root }).reason, 'invalid_leaf_index');
  assert.strictEqual(Merkle.verifyInclusion({ index: 0, size: 0, leafDigest: set[0], path: [], root }).reason, 'invalid_tree_size');
  assert.strictEqual(Merkle.verifyInclusion({ index: 0, size: 2, leafDigest: set[0], path, root: 'nope' }).reason, 'invalid_root');
  assert.strictEqual(Merkle.verifyInclusion({ index: 0, size: 2, leafDigest: 'short', path, root }).reason, 'invalid_leaf_digest');
});

test('the proof is logarithmic and carries only sibling hashes', () => {
  for (const size of [2, 3, 4, 8, 16, 17]) {
    const set = leaves(size);
    const index = Math.floor(size / 2);
    const proof = Merkle.inclusion(index, set);

    assert.strictEqual(proof.path.length, Merkle.depthFor(index, size));
    assert.ok(proof.path.length <= Math.ceil(Math.log2(size)),
      'path for ' + size + ' leaves is logarithmic, got ' + proof.path.length);
    assert.ok(!proof.path.some(h => h.equals(Merkle.leafHash(set[index]))),
      'the proof never contains the leaf it proves');
  }
});

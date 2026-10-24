// Consistency proofs: a tree of size m is a prefix of a tree of size n.
//
// The proof is checked against a reference implementation written from the
// RFC 6962 definition (subtree hashes recomputed per range), not against the
// code under test, at every pair of sizes up to 64.

'use strict';

const test = require('node:test');
const assert = require('node:assert');

const crypto = require('crypto');

const Merkle = require('../merkle.cjs');

function digest(seed) {
  return crypto.createHash('sha256').update('consistency:' + seed).digest();
}

function leaves(count, salt) {
  const out = [];
  for (let i = 0; i < count; i++) out.push(digest((salt || '') + i));
  return out;
}

// Reference: MTH over the half-open range [start, end), straight from the
// definition. Deliberately not Merkle.mth, which is internal.
function refMth(hashes, start, end) {
  const size = end - start;
  if (size === 0) return Merkle.sha256(Buffer.alloc(0));
  if (size === 1) return hashes[start];
  let k = 1;
  while (k * 2 < size) k *= 2;
  return Merkle.nodeHash(refMth(hashes, start, start + k), refMth(hashes, start + k, end));
}

function refSubproof(m, hashes, start, end, known) {
  const size = end - start;
  if (m === 0) return [];
  if (m === size) return known ? [] : [refMth(hashes, start, end).toString('hex')];
  let k = 1;
  while (k * 2 < size) k *= 2;
  if (m <= k) {
    return refSubproof(m, hashes, start, start + k, known)
      .concat([refMth(hashes, start + k, end).toString('hex')]);
  }
  return refSubproof(m - k, hashes, start + k, end, false)
    .concat([refMth(hashes, start, start + k).toString('hex')]);
}

function refRoot(size, hashes) {
  return Merkle.rootHash(size, refMth(hashes, 0, size)).toString('hex');
}

test('consistency proofs verify at every pair of sizes up to 64', () => {
  for (const salt of ['a', 'b', 'c']) {
    for (let n = 1; n <= 64; n++) {
      const digests = leaves(n, salt);
      const hashes = digests.map(Merkle.leafHash);
      for (let m = 0; m <= n; m++) {
        const proof = Merkle.consistency(m, digests);
        const expectedRootM = m === 0
          ? Merkle.rootHash(0, Merkle.sha256(Buffer.alloc(0))).toString('hex')
          : refRoot(m, hashes);
        assert.equal(proof.root_m, expectedRootM, 'root_m at m=' + m + ', n=' + n);
        assert.equal(proof.root_n, refRoot(n, hashes), 'root_n at m=' + m + ', n=' + n);
        assert.deepEqual(proof.path, m === 0 || m === n ? [] : refSubproof(m, hashes, 0, n, true),
          'path at m=' + m + ', n=' + n);
        const verdict = Merkle.verifyConsistency({
          m,
          n,
          rootM: proof.root_m,
          rootN: proof.root_n,
          prefixMth: proof.prefix_mth,
          path: proof.path,
        });
        assert.equal(verdict.ok, true, 'm=' + m + ', n=' + n + ': ' + verdict.reason);
      }
    }
  }
});

test('a proof from one prefix does not verify for another', () => {
  const digests = leaves(20, 'fork');
  const proof = Merkle.consistency(7, digests);
  for (const m of [1, 6, 8, 19]) {
    const other = Merkle.consistency(m, digests);
    const verdict = Merkle.verifyConsistency({
      m,
      n: 20,
      rootM: other.root_m,
      rootN: proof.root_n,
      prefixMth: proof.prefix_mth,
      path: proof.path,
    });
    assert.equal(verdict.ok, false, 'proof for 7 must not prove m=' + m);
  }
});

test('truncated, reordered, extended and non-hex paths are refused', () => {
  const digests = leaves(13, 'tamper');
  const proof = Merkle.consistency(5, digests);
  const base = { m: 5, n: 13, rootM: proof.root_m, rootN: proof.root_n, prefixMth: proof.prefix_mth };

  // Dropping the last sibling still consumes the same number of path elements,
  // so it is rejected by the reconstructed root rather than by length.
  const truncated = Merkle.verifyConsistency(Object.assign({}, base, { path: proof.path.slice(0, -1) }));
  assert.equal(truncated.ok, false);

  const empty = Merkle.verifyConsistency(Object.assign({}, base, { path: [] }));
  assert.equal(empty.ok, false);
  assert.equal(empty.reason, 'invalid_path_length');

  const extended = Merkle.verifyConsistency(Object.assign({}, base, { path: proof.path.concat([proof.path[0]]) }));
  assert.equal(extended.ok, false);

  const reordered = Merkle.verifyConsistency(Object.assign({}, base, { path: proof.path.slice().reverse() }));
  assert.equal(reordered.ok, false);

  const nonHex = Merkle.verifyConsistency(Object.assign({}, base, { path: ['not-hex'].concat(proof.path.slice(1)) }));
  assert.equal(nonHex.ok, false);
  assert.equal(nonHex.reason, 'malformed_path_hash');

  const swappedRoots = Merkle.verifyConsistency(Object.assign({}, base, { rootM: proof.root_n, rootN: proof.root_m }));
  assert.equal(swappedRoots.ok, false);
});

test('the size prefix is what a wrong size cannot be talked around', () => {
  const digests = leaves(9, 'size');
  const proof = Merkle.consistency(4, digests);
  for (const n of [5, 8, 10]) {
    const tree = Merkle.buildTree(digests.slice(0, Math.min(n, digests.length)));
    const verdict = Merkle.verifyConsistency({
      m: 4,
      n,
      rootM: proof.root_m,
      rootN: n <= digests.length ? tree.root.toString('hex') : proof.root_n,
      prefixMth: proof.prefix_mth,
      path: proof.path,
    });
    assert.equal(verdict.ok, false, 'proof for n=9 must not verify as n=' + n);
  }
});

test('an empty prefix is a prefix of everything, and equality needs no path', () => {
  const digests = leaves(6, 'edge');
  const empty = Merkle.consistency(0, digests);
  assert.deepEqual(empty.path, []);
  assert.equal(Merkle.verifyConsistency({
    m: 0,
    n: 6,
    rootM: empty.root_m,
    rootN: empty.root_n,
    prefixMth: empty.prefix_mth,
    path: empty.path,
  }).ok, true);

  const same = Merkle.consistency(6, digests);
  assert.deepEqual(same.path, []);
  assert.equal(Merkle.verifyConsistency({
    m: 6,
    n: 6,
    rootM: same.root_m,
    rootN: same.root_n,
    prefixMth: same.prefix_mth,
    path: same.path,
  }).ok, true);
  assert.equal(Merkle.verifyConsistency({
    m: 6,
    n: 6,
    rootM: same.root_m,
    rootN: same.root_n,
    prefixMth: same.prefix_mth,
    path: [same.prefix_mth],
  }).ok, false);

  assert.throws(() => Merkle.consistency(7, digests), /exceeds the tree size/);
  assert.throws(() => Merkle.consistency(-1, digests), /non-negative/);
});

// Published known-answer vectors from Google's certificate-transparency
// reference tree (cpp/merkletree/merkle_tree_test.cc, kInputs / kSHA256Roots /
// kSHA256Proofs). These are unprefixed RFC 6962 Merkle tree hashes, so they
// check prefix_mth and the SUBPROOF path, which are the parts this scheme
// shares with RFC 6962; the size-prefixed roots are checked separately.
const CT_INPUTS = [
  '',
  '00',
  '10',
  '2021',
  '3031',
  '40414243',
  '5051525354555657',
  '606162636465666768696a6b6c6d6e6f',
].map(hex => Buffer.from(hex, 'hex'));

const CT_MTH = [
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];

const CT_PROOFS = [
  {
    m: 1,
    n: 8,
    path: [
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ],
  },
  {
    m: 6,
    n: 8,
    path: [
      '0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a',
      'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    ],
  },
  {
    m: 2,
    n: 5,
    path: [
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
    ],
  },
  { m: 1, n: 1, path: [] },
];

test('published RFC 6962 vectors match the hash rules and the verifier', () => {
  // Our leaf rule commits to a 32-byte payload digest, so the published leaf
  // inputs (arbitrary byte strings) cannot be fed to buildTree. The hash rules
  // themselves are the same, so they are checked directly against the published
  // roots, and the published SUBPROOF paths are checked against the verifier:
  // a vector set written by someone else, not by these tests.
  const leafHashes = CT_INPUTS.map(input =>
    Merkle.sha256(Buffer.concat([Buffer.from([0x00]), input])));
  const refMthOf = (start, end) => {
    const size = end - start;
    if (size === 1) return leafHashes[start];
    let k = 1;
    while (k * 2 < size) k *= 2;
    return Merkle.nodeHash(refMthOf(start, start + k), refMthOf(start + k, end));
  };
  for (let size = 1; size <= CT_INPUTS.length; size++) {
    assert.equal(refMthOf(0, size).toString('hex'), CT_MTH[size - 1],
      'published MTH at size ' + size + ' from the leaf/node rules');
  }

  for (const vector of CT_PROOFS) {
    const verdict = Merkle.verifyConsistency({
      m: vector.m,
      n: vector.n,
      rootM: Merkle.rootHash(vector.m, Buffer.from(CT_MTH[vector.m - 1], 'hex')).toString('hex'),
      rootN: Merkle.rootHash(vector.n, Buffer.from(CT_MTH[vector.n - 1], 'hex')).toString('hex'),
      prefixMth: CT_MTH[vector.m - 1],
      path: vector.path,
    });
    assert.equal(verdict.ok, true, vector.m + ' of ' + vector.n + ': ' + verdict.reason);
  }

  // The generator must produce the same published path when it can be applied
  // to the same tree shape; the published tree's leaves are not 32-byte
  // digests, so the generator is checked against the reference above and the
  // verifier here.
  const bad = Merkle.verifyConsistency({
    m: 2,
    n: 5,
    rootM: CT_MTH[1],
    rootN: CT_MTH[4],
    prefixMth: CT_MTH[1],
    path: CT_PROOFS[2].path,
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, 'root_mismatch');
});

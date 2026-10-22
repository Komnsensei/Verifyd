// Verifyd Merkle inclusion proofs - scheme verifyd-merkle-v1
// Zero dependencies. SHA-256 only.
//
// WHAT AN INCLUSION PROOF PROVES
//   That a specific leaf is one of the leaves that produced a specific root
//   hash, at a specific index in a tree of a specific size. Given only the
//   receipt's own payload digest, its index, the tree size and its path, a
//   verifier recomputes the root and compares it to the root it trusts.
//
// WHAT IT DOES NOT PROVE
//   - That the receipt content is true. Inclusion is a position in a set, not
//     an endorsement of what the set says.
//   - That the batch is complete, or that no other receipts exist.
//   - That history was not rewritten. Without a consistency proof between
//     successive roots, whoever publishes roots can replace the whole tree and
//     publish a new valid root. Consistency proofs are deliberately not part
//     of this scheme, so this is NOT an append-only guarantee.
//   - Anything about the signer. The root signature says who signed the root;
//     it does not make the contents honest.
//
// TREE DEFINITION (RFC 6962 shape, fully specified so it cannot be guessed at)
//   leaf_hash  = SHA-256(0x00 || payload_digest)
//   node_hash  = SHA-256(0x01 || left || right)
//   empty tree = SHA-256("")
//   tree of 1  = leaf_hash
//   tree of n  = node_hash(MTH(D[0:k]), MTH(D[k:n])) where k is the largest
//                power of two strictly less than n
//   root       = SHA-256(0x02 || uint64be(tree_size) || MTH(D[0:n]))
//   Leaves are the SHA-256 digests of the signed receipt payloads (the same
//   bytes the receipt signature and any timestamp token cover), so the proof
//   binds to signed bytes, never to raw file bytes.
//
//   The root commits to the tree size. Without that, a path from a 4-leaf tree
//   re-read as a 3-leaf tree can reproduce the same root, so the claimed size
//   would be unverifiable; the size prefix makes that lie change the root.
//
//   Order is the order the batch was given; that order assigns leaf indices
//   and is therefore part of the commitment. The same receipts in the same
//   order always produce the same root.
//
//   A path is bottom-up: at each level the sibling hash is appended, and the
//   side is derived from the index and the tree size, never from the proof
//   itself. Paths carry no direction bits, so a reordered or truncated path
//   fails rather than silently verifying under a different reading.

'use strict';

const crypto = require('crypto');

const SCHEME = 'verifyd-merkle-v1';
const ROOT_DOMAIN = 'verifyd-merkle-root-v1\n';
const HASH_BYTES = 32;
const HEX_RE = /^[0-9a-f]{64}$/i;

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

function leafHash(payloadDigest) {
  if (!Buffer.isBuffer(payloadDigest) || payloadDigest.length !== HASH_BYTES) {
    throw new Error('leaf digest must be a 32-byte SHA-256 digest');
  }
  return sha256(Buffer.concat([Buffer.from([0x00]), payloadDigest]));
}

function nodeHash(left, right) {
  if (!Buffer.isBuffer(left) || left.length !== HASH_BYTES ||
      !Buffer.isBuffer(right) || right.length !== HASH_BYTES) {
    throw new Error('node children must be 32-byte hashes');
  }
  return sha256(Buffer.concat([Buffer.from([0x01]), left, right]));
}

function largestPowerOfTwoLessThan(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function mth(nodes) {
  if (nodes.length === 0) return sha256(Buffer.alloc(0));
  if (nodes.length === 1) return nodes[0];
  const k = largestPowerOfTwoLessThan(nodes.length);
  return nodeHash(mth(nodes.slice(0, k)), mth(nodes.slice(k)));
}

function sizeBytes(size) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(size));
  return buf;
}

function rootHash(size, mthRoot) {
  return sha256(Buffer.concat([Buffer.from([0x02]), sizeBytes(size), mthRoot]));
}

function buildTree(payloadDigests) {
  if (!Array.isArray(payloadDigests) || payloadDigests.length === 0) {
    throw new Error('a Merkle tree needs at least one leaf');
  }
  const leaves = payloadDigests.map(leafHash);
  const inner = mth(leaves);
  return {
    scheme: SCHEME,
    size: leaves.length,
    root: rootHash(leaves.length, inner),
    mth_root: inner,
    leaf_hashes: leaves,
  };
}

function pathFor(index, leafHashes) {
  const n = leafHashes.length;
  if (n === 1) return [];
  const k = largestPowerOfTwoLessThan(n);
  if (index < k) {
    return pathFor(index, leafHashes.slice(0, k)).concat([mth(leafHashes.slice(k))]);
  }
  return pathFor(index - k, leafHashes.slice(k)).concat([mth(leafHashes.slice(0, k))]);
}

function inclusion(index, payloadDigests) {
  if (!Number.isInteger(index) || index < 0 || index >= payloadDigests.length) {
    throw new Error('leaf index out of range');
  }
  const leaves = payloadDigests.map(leafHash);
  const inner = mth(leaves);
  return {
    scheme: SCHEME,
    index,
    size: leaves.length,
    root: rootHash(leaves.length, inner),
    path: pathFor(index, leaves),
  };
}

function depthFor(index, size) {
  if (size === 1) return 0;
  const k = largestPowerOfTwoLessThan(size);
  if (index < k) return depthFor(index, k) + 1;
  return depthFor(index - k, size - k) + 1;
}

function computeRoot(index, size, leaf, path) {
  if (size === 1) {
    if (path.length !== 0) throw new Error('path longer than tree depth');
    return leaf;
  }
  if (path.length === 0) throw new Error('path shorter than tree depth');
  const k = largestPowerOfTwoLessThan(size);
  const sibling = path[path.length - 1];
  const rest = path.slice(0, -1);
  if (index < k) {
    return nodeHash(computeRoot(index, k, leaf, rest), sibling);
  }
  return nodeHash(sibling, computeRoot(index - k, size - k, leaf, rest));
}

function invalid(reason) {
  return { ok: false, reason, computed_root: null };
}

function verifyInclusion(input) {
  const { index, size, leafDigest, root } = input || {};
  let path = input && input.path;

  if (!Number.isInteger(size) || size < 1) return invalid('invalid_tree_size');
  if (!Number.isInteger(index) || index < 0 || index >= size) return invalid('invalid_leaf_index');
  if (!Buffer.isBuffer(leafDigest) || leafDigest.length !== HASH_BYTES) return invalid('invalid_leaf_digest');
  if (!Array.isArray(path)) return invalid('invalid_path');
  if (typeof root !== 'string' || !HEX_RE.test(root)) return invalid('invalid_root');

  const expectedDepth = depthFor(index, size);
  if (path.length !== expectedDepth) {
    return invalid('invalid_path_length');
  }

  const siblings = [];
  for (const item of path) {
    if (typeof item !== 'string' || !HEX_RE.test(item)) return invalid('malformed_path_hash');
    siblings.push(Buffer.from(item, 'hex'));
  }

  let computed;
  try {
    computed = rootHash(size, computeRoot(index, size, leafHash(leafDigest), siblings));
  } catch (e) {
    return invalid('invalid_path');
  }

  const computedHex = computed.toString('hex');
  if (computedHex !== root.toLowerCase()) {
    return { ok: false, reason: 'root_mismatch', computed_root: computedHex };
  }
  return { ok: true, reason: null, computed_root: computedHex };
}

module.exports = {
  SCHEME,
  ROOT_DOMAIN,
  HASH_BYTES,
  sha256,
  leafHash,
  nodeHash,
  largestPowerOfTwoLessThan,
  sizeBytes,
  rootHash,
  buildTree,
  inclusion,
  depthFor,
  verifyInclusion,
};

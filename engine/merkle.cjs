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
//   - That history was not rewritten, by an inclusion proof alone. Whoever
//     publishes roots can still replace the whole tree and publish a new valid
//     root; only a consistency proof between the two heads detects that.
//     consistency() and verifyConsistency() supply that for two trees of the
//     same scheme, but a batch itself remains a set, not an append-only log.
//     The append-only claim belongs to the ledger's chained checkpoints, which
//     use these same tree rules.
//   - Anything about the signer. The root signature says who signed the root;
//     it does not make the contents honest.
//
// INCREMENTAL USE
//   buildTree and inclusion answer questions about a finished leaf list.
//   createFrontier() answers the same questions while leaves arrive: the
//   ledger's inspection checks every checkpoint prefix root from one pass with
//   it, append takes the new leaf's root and inclusion path from it, and fsck
//   reseal continues it. It is the same tree shape above, not a second scheme.
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

// Incremental RFC 6962 frontier.
//
// The stack holds the roots of the complete subtrees that cover the leaves seen
// so far, in decreasing power-of-two order. MTH(n) is the right fold of that
// decomposition, so root() is one O(log n) fold; adding a leaf is one node hash
// per carry. This is the only place that knows the tree shape besides buildTree
// and pathFor, and it produces the same roots and the same inclusion path as
// they do (engine/test/ledger-frontier.test.cjs pins both).
function createFrontier() {
  const stack = [];
  let size = 0;

  function root() {
    if (size === 0) return rootHash(0, sha256(Buffer.alloc(0)));
    let acc = stack[stack.length - 1].hash;
    for (let i = stack.length - 2; i >= 0; i--) acc = nodeHash(stack[i].hash, acc);
    return rootHash(size, acc);
  }

  // Adds one leaf and returns its inclusion path when asked. The path is built
  // bottom-up: each left sibling consumed by a carry, then the remaining
  // complete subtrees from the top of the stack down.
  function add(payloadDigest, withPath) {
    const leaf = leafHash(payloadDigest);
    const path = withPath ? [] : null;
    let node = leaf;
    let span = 1;
    while (stack.length && stack[stack.length - 1].span === span) {
      const left = stack.pop();
      if (path) path.push(left.hash);
      node = nodeHash(left.hash, node);
      span *= 2;
    }
    if (path) {
      for (let i = stack.length - 1; i >= 0; i--) path.push(stack[i].hash);
    }
    stack.push({ hash: node, span });
    size += 1;
    return path;
  }

  return {
    get size() { return size; },
    root,
    // Adds a leaf; the caller asks for root() only when a checkpoint needs one,
    // so an inspection does not fold once per entry.
    push(payloadDigest) {
      add(payloadDigest, false);
      return size;
    },
    // Adds a leaf and returns the root and inclusion path for exactly that leaf.
    append(payloadDigest) {
      const path = add(payloadDigest, true);
      return { size, root: root(), path };
    },
  };
}

// --- consistency proofs (RFC 6962 section 2.1.2) ---------------------------
//
// A consistency proof answers one question: is the tree of size m a prefix of
// the tree of size n? The path is the list SUBPROOF emits.
//
// This scheme's roots commit to the tree size (0x02 || uint64be(n) || MTH), so
// a verifier holding only root_m cannot fold the first m leaves into the larger
// tree: the size prefix cannot be stripped by hashing. The proof therefore also
// carries MTH(D[0:m]) as `prefix_mth`, which is public data and lets the
// verifier check root_m and reconstruct root_n from the path.

const EMPTY_MTH = sha256(Buffer.alloc(0));

// `known` is RFC 6962's `b`: true while the whole tree of size m is still
// implied by the caller's root, false once the recursion has entered a right
// subtree, whose terminal hash must then come from the path.
function consistencySubproof(m, leaves, known) {
  const n = leaves.length;
  if (m === n) return known ? [] : [mth(leaves)];
  const k = largestPowerOfTwoLessThan(n);
  if (m <= k) {
    return consistencySubproof(m, leaves.slice(0, k), known).concat([mth(leaves.slice(k))]);
  }
  return consistencySubproof(m - k, leaves.slice(k), false).concat([mth(leaves.slice(0, k))]);
}

function consistency(m, payloadDigests) {
  if (!Array.isArray(payloadDigests)) throw new Error('digests must be an array');
  const n = payloadDigests.length;
  if (!Number.isInteger(m) || m < 0) throw new Error('first tree size must be a non-negative integer');
  if (m > n) throw new Error('first tree size ' + m + ' exceeds the tree size ' + n);

  const leaves = payloadDigests.map(leafHash);
  const prefixMth = m === 0 ? EMPTY_MTH : mth(leaves.slice(0, m));
  return {
    scheme: SCHEME,
    m,
    n,
    root_m: rootHash(m, prefixMth).toString('hex'),
    root_n: rootHash(n, mth(leaves)).toString('hex'),
    prefix_mth: prefixMth.toString('hex'),
    // An empty prefix has no subtree to prove, and equality needs no path.
    path: (m === 0 || m === n) ? [] : consistencySubproof(m, leaves, true).map(h => h.toString('hex')),
  };
}

// Mirrors SUBPROOF: `seed` is MTH(D[0:m]) while the recursion is still on the
// left edge of the original prefix, and null once it has moved into a right
// subtree, where the terminal subtree hash comes from the path instead.
function foldConsistency(m, n, hashes, pos, seed) {
  if (m === n) {
    if (seed) return { mthM: seed, mthN: seed, pos };
    if (pos >= hashes.length) throw new Error('path shorter than the tree depth');
    return { mthM: hashes[pos], mthN: hashes[pos], pos: pos + 1 };
  }
  const k = largestPowerOfTwoLessThan(n);
  if (m <= k) {
    const sub = foldConsistency(m, k, hashes, pos, seed);
    if (sub.pos >= hashes.length) throw new Error('path shorter than the tree depth');
    const right = hashes[sub.pos];
    return { mthM: sub.mthM, mthN: nodeHash(sub.mthN, right), pos: sub.pos + 1 };
  }
  const sub = foldConsistency(m - k, n - k, hashes, pos, null);
  if (sub.pos >= hashes.length) throw new Error('path shorter than the tree depth');
  const left = hashes[sub.pos];
  return { mthM: nodeHash(left, sub.mthM), mthN: nodeHash(left, sub.mthN), pos: sub.pos + 1 };
}

function verifyConsistency(input) {
  const { m, n, prefixMth } = input || {};
  const rootM = input && input.rootM;
  const rootN = input && input.rootN;
  const path = input && input.path;

  const bad = (reason) => ({ ok: false, reason, computed_root: null });
  if (!Number.isInteger(n) || n < 0) return bad('invalid_tree_size');
  if (!Number.isInteger(m) || m < 0 || m > n) return bad('invalid_first_tree_size');
  if (typeof rootM !== 'string' || !HEX_RE.test(rootM)) return bad('invalid_root_m');
  if (typeof rootN !== 'string' || !HEX_RE.test(rootN)) return bad('invalid_root_n');
  if (!Array.isArray(path)) return bad('invalid_path');

  // The empty tree is a prefix of every tree; nothing about root_n is proven
  // by a proof of this shape, and the verifier is told so in the result.
  if (m === 0) {
    if (path.length !== 0) return bad('invalid_path_length');
    if (rootHash(0, EMPTY_MTH).toString('hex') !== rootM.toLowerCase()) return bad('root_mismatch');
    return { ok: true, reason: null, computed_root: null };
  }

  if (m === n) {
    if (path.length !== 0) return bad('invalid_path_length');
    return rootM.toLowerCase() === rootN.toLowerCase()
      ? { ok: true, reason: null, computed_root: rootN.toLowerCase() }
      : bad('root_mismatch');
  }

  if (typeof prefixMth !== 'string' || !HEX_RE.test(prefixMth)) return bad('invalid_prefix_mth');
  const seed = Buffer.from(prefixMth, 'hex');
  if (rootHash(m, seed).toString('hex') !== rootM.toLowerCase()) return bad('root_mismatch');

  const hashes = [];
  for (const item of path) {
    if (typeof item !== 'string' || !HEX_RE.test(item)) return bad('malformed_path_hash');
    hashes.push(Buffer.from(item, 'hex'));
  }

  let folded;
  try {
    folded = foldConsistency(m, n, hashes, 0, seed);
  } catch (e) {
    return bad(/shorter/.test(e.message) ? 'invalid_path_length' : 'invalid_path');
  }
  if (folded.pos !== hashes.length) return bad('invalid_path_length');
  if (!folded.mthM.equals(seed)) return bad('root_mismatch_m');

  const computed = rootHash(n, folded.mthN).toString('hex');
  if (computed !== rootN.toLowerCase()) {
    return { ok: false, reason: 'root_mismatch_n', computed_root: computed };
  }
  return { ok: true, reason: null, computed_root: computed };
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
  createFrontier,
  consistency,
  verifyConsistency,
  inclusion,
  depthFor,
  verifyInclusion,
};

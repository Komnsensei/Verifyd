// Phase A acceptance: the ledger's byte-level contract is frozen.
//
// Every vector below was reviewed and then pinned: exact tag, exact canonical
// body, exact SHA-256. The test compares bytes and digests against those
// constants, not against another call into the module, so a change to a tag,
// a canonicalization rule or a preimage layout fails here instead of silently
// redefining what a signature covers.
//
// A vector that changes between Node versions is a defect, not a test update.

'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const test = require('node:test');

const Ledger = require('../ledger.cjs');
const Merkle = require('../merkle.cjs');
const Signing = require('../signing.cjs');

// Fixed inputs. Every value is a constant so the canonical body below is
// reproducible by hand, and none of them comes from the implementation.
const H_A = 'a'.repeat(64);
const H_B = 'b'.repeat(64);
const H_C = 'c'.repeat(64);
const H_D4 = 'd4'.repeat(32);
const H_E5 = 'e5'.repeat(32);
const H_F6 = 'f6'.repeat(32);
const H_07 = '07'.repeat(32);
const H_18 = '18'.repeat(32);
const KEY_A = 'ed25519:' + 'a1'.repeat(32);
const KEY_B = 'ed25519:' + 'b2'.repeat(32);
const KEY_W = 'ed25519:' + 'c3'.repeat(32);
const RECEIPT_ID = '00000000-0000-4000-8000-000000000000';
const BATCH_ID = '00000000-0000-4000-8000-000000000001';
const ENTRY_RECEIPT_ID = '00000000-0000-4000-8000-000000000002';
const AT = '2026-10-23T00:00:00.000Z';

const RECEIPT_SAMPLE = {
  valf_version: '1.0',
  receipt_type: 'document',
  signed_at: AT,
  document: { name: 'sample.txt', content_hash: H_A },
  receipt: { receipt_id: RECEIPT_ID, this_hash: H_B },
};

const ROOT_SAMPLE = {
  valf_version: '1.0',
  batch_type: 'merkle',
  scheme: 'verifyd-merkle-v1',
  batch_id: BATCH_ID,
  created_at: AT,
  tree_size: 2,
  root_hash: H_C,
};

const ENTRY = Ledger.buildEntry({
  ledger_id: H_D4,
  seq: 1,
  payload_digest: H_E5,
  receipt_id: ENTRY_RECEIPT_ID,
  recorded_at: AT,
  writer_key_id: KEY_A,
  prev_entry_hash: Ledger.GENESIS,
});

// H_07 stands in for the genesis checkpoint hash: the head after one entry
// names its predecessor, never GENESIS.
const CHECKPOINT = Ledger.checkpointBody({
  ledger_id: H_D4,
  tree_size: 1,
  root_hash: H_F6,
  created_at: AT,
  prev_checkpoint_hash: H_07,
  policy_hash: H_18,
});

// The checkpoint hash above, pinned. The cosignature and publication samples
// name it, so this one vector set describes a single coherent head.
const CHECKPOINT_HASH = 'fee04342e84679c41202e59094a4df5d53d63c6093996d194e74000465381fac';

const POLICY_SAMPLE = {
  writer_keys: [KEY_B, KEY_A],
  admin_keys: [KEY_A],
  witness_policy: { threshold: 2, witnesses: [KEY_W] },
};

const COSIGN = Ledger.cosignStatement({
  ledger_id: H_D4,
  checkpoint_hash: CHECKPOINT_HASH,
  tree_size: 1,
  root_hash: H_F6,
  witness_key_id: KEY_W,
  identity: 'witness@example.org',
  cosigned_at: AT,
});

const PUBLICATION = Ledger.publicationStatement({
  ledger_id: H_D4,
  tree_size: 1,
  root_hash: H_F6,
  checkpoint_hash: CHECKPOINT_HASH,
});

const REVOCATION = Ledger.buildRevocation({
  ledger_id: H_D4,
  key_id: KEY_B,
  revoked_at: AT,
  recorded_at: AT,
  head_tree_size: 1,
  head_checkpoint_hash: CHECKPOINT_HASH,
  reason: null,
});

const ENTRY_HASH = '62c9b238cfa1512b4102ca8bf5f167bd0ffff80a8ccfb33966b4cf2c50552009';
const EMPTY_TREE_ROOT = 'f0c1e0b4cd1983b9c92909f8145cc102993e4c797489c0ba98639fd93056b82f';
const GENESIS_LEDGER_ID = '34eb43e90023ce43919eefe3d1884e50c76e02cba587059cf229e13ce04bc9b4';

const CHECKPOINT_BODY = '{"checkpoint_type":"ledger","created_at":"' + AT + '",'
  + '"ledger_id":"' + H_D4 + '","policy_hash":"' + H_18 + '",'
  + '"prev_checkpoint_hash":"' + H_07 + '","root_hash":"' + H_F6 + '",'
  + '"scheme":"verifyd-ledger-v1","tree_size":1}';

const ENTRY_HASH_BODY = '{"ledger_id":"' + H_D4 + '","payload_digest":"' + H_E5 + '",'
  + '"prev_entry_hash":"GENESIS","receipt_id":"' + ENTRY_RECEIPT_ID + '",'
  + '"recorded_at":"' + AT + '","scheme":"verifyd-ledger-v1","seq":1,'
  + '"writer_key_id":"' + KEY_A + '"}';

const VECTORS = [
  {
    name: 'receipt',
    tag: 'verifyd-receipt-v1\n',
    body: '{"document":{"content_hash":"' + H_A + '","name":"sample.txt"},'
      + '"receipt":{"receipt_id":"' + RECEIPT_ID + '","this_hash":"' + H_B + '"},'
      + '"receipt_type":"document","signed_at":"' + AT + '","valf_version":"1.0"}',
    sha256: '0641c5d487db5ce05a24bf9ccf6258751481ab50e6f7f809c104445f5c11e65f',
  },
  {
    name: 'merkle_root',
    tag: 'verifyd-merkle-root-v1\n',
    body: '{"batch_id":"' + BATCH_ID + '","batch_type":"merkle",'
      + '"created_at":"' + AT + '","root_hash":"' + H_C + '",'
      + '"scheme":"verifyd-merkle-v1","tree_size":2,"valf_version":"1.0"}',
    sha256: 'b3247b85c499e00cc590a2352be161709ca7419312a80290ae1be89f07fe127e',
  },
  {
    name: 'entry_hash',
    tag: 'verifyd-ledger-entry-v1\nhash\n',
    body: ENTRY_HASH_BODY,
    sha256: ENTRY_HASH,
  },
  {
    name: 'entry_sig',
    tag: 'verifyd-ledger-entry-v1\nsig\n',
    body: '{"entry_hash":"' + ENTRY_HASH + '",' + ENTRY_HASH_BODY.slice(1),
    sha256: '9d7cecbed75a616bfeb277f968a7c7da37e822c8d8b2948acd8e749ad2042915',
  },
  {
    name: 'checkpoint_hash',
    tag: 'verifyd-chain-checkpoint-v1\nhash\n',
    body: CHECKPOINT_BODY,
    sha256: CHECKPOINT_HASH,
  },
  {
    name: 'checkpoint_sig',
    tag: 'verifyd-chain-checkpoint-v1\nsig\n',
    body: CHECKPOINT_BODY,
    sha256: '151891fc7ef40e564b427a505cd608b8e2f2f64d3c81890ee5156b4ef7e8267d',
  },
  {
    name: 'policy',
    tag: 'verifyd-ledger-policy-v1\n',
    body: '{"admin_keys":["' + KEY_A + '"],'
      + '"witness_policy":{"threshold":2,"witnesses":["' + KEY_W + '"]},'
      + '"writer_keys":["' + KEY_A + '","' + KEY_B + '"]}',
    sha256: 'c6fe6d0cb8ac687edf1c7146f8bc3f7f3b37fbb403be477b65e7026791a6e4a1',
  },
  {
    name: 'cosign',
    tag: 'verifyd-chain-cosign-v1\n',
    body: '{"checkpoint_hash":"' + CHECKPOINT_HASH + '","cosigned_at":"' + AT + '",'
      + '"identity":"witness@example.org","ledger_id":"' + H_D4 + '",'
      + '"root_hash":"' + H_F6 + '","scheme":"verifyd-ledger-v1","tree_size":1,'
      + '"witness_key_id":"' + KEY_W + '"}',
    sha256: '3c1d0f589c10e663afb7354d9189925438f6d8d39d632988fe97d0e97d8e025c',
  },
  {
    name: 'publication',
    tag: 'verifyd-chain-publication-v1\n',
    body: '{"checkpoint_hash":"' + CHECKPOINT_HASH + '","ledger_id":"' + H_D4 + '",'
      + '"root_hash":"' + H_F6 + '","scheme":"verifyd-chain-publication-v1","tree_size":1}',
    sha256: 'f3812dd94d88f84992a25d7510745aee2570af90abfe11ba718a30e5d75b55f6',
  },
  {
    name: 'revocation',
    tag: 'verifyd-ledger-revocation-v1\n',
    body: '{"head_checkpoint_hash":"' + CHECKPOINT_HASH + '","head_tree_size":1,'
      + '"key_id":"' + KEY_B + '","ledger_id":"' + H_D4 + '","reason":null,'
      + '"recorded_at":"' + AT + '","revoked_at":"' + AT + '",'
      + '"scheme":"verifyd-ledger-v1"}',
    sha256: '7ad62858ffc5cb1e0a1e0475c6349bf9d69a3d64e4eb1d085bb2984d28974e70',
  },
];

function implementationBytes(name) {
  switch (name) {
    case 'receipt':
      return Signing.signingPayload(RECEIPT_SAMPLE);
    case 'merkle_root':
      return Signing.signingPayload(ROOT_SAMPLE, { domain: Merkle.ROOT_DOMAIN });
    case 'entry_hash':
      return Ledger.entryHashPreimage(ENTRY);
    case 'entry_sig':
      return Ledger.entrySigningPayload(ENTRY);
    case 'checkpoint_hash':
      return Ledger.checkpointHashPreimage(CHECKPOINT);
    case 'checkpoint_sig':
      return Ledger.checkpointSigningPayload(CHECKPOINT);
    case 'policy':
      return Ledger.policyBytes(POLICY_SAMPLE);
    case 'cosign':
      return Ledger.cosignSigningPayload(COSIGN);
    case 'publication':
      return Ledger.publicationStatementBytes(PUBLICATION);
    case 'revocation':
      return Ledger.revocationSigningPayload(REVOCATION);
    default:
      throw new Error('no implementation binding for vector ' + name);
  }
}

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

test('the registry holds exactly the ten frozen domain tags', () => {
  assert.equal(Ledger.TAG_REGISTRY.length, 10);
  assert.equal(VECTORS.length, 10);

  const registry = {};
  for (const entry of Ledger.TAG_REGISTRY) {
    assert.equal(typeof entry.name, 'string');
    assert.equal(typeof entry.covers, 'string');
    assert.ok(entry.tag.endsWith('\n'), 'tag must end with a newline: ' + entry.name);
    assert.equal(registry[entry.name], undefined, 'duplicate registry name: ' + entry.name);
    registry[entry.name] = entry.tag;
  }

  for (const vector of VECTORS) {
    assert.equal(registry[vector.name], vector.tag, 'registry tag drifted: ' + vector.name);
  }

  const tags = Object.values(registry);
  assert.equal(new Set(tags).size, tags.length, 'duplicate tag in registry');
  assert.equal(new Set(tags.map(t => t.replace(/\n/g, '\\n'))).size, 10);
});

test('every domain vector matches its frozen bytes and digest', () => {
  for (const vector of VECTORS) {
    const expected = Buffer.from(vector.tag + vector.body, 'utf8');
    const actual = implementationBytes(vector.name);

    assert.ok(Buffer.isBuffer(actual), vector.name + ': preimage must be a Buffer');
    assert.equal(actual.toString('utf8'), expected.toString('utf8'),
      vector.name + ': preimage bytes drifted');
    assert.equal(sha256Hex(actual), vector.sha256, vector.name + ': digest drifted');
    // The digest of the frozen bytes must equal the digest of what the module
    // produced, so neither side can drift alone.
    assert.equal(sha256Hex(expected), vector.sha256);
  }
});

test('receipt and batch-root domains are unchanged by the ledger scheme', () => {
  // The ledger adds no member to either sample, so the bytes a receipt or a
  // batch root signs today are byte-identical to the pinned vector. Phase C
  // adds `ledger` to the receipt omit list; that must leave this vector alone.
  const receiptVector = VECTORS.find(v => v.name === 'receipt');
  const rootVector = VECTORS.find(v => v.name === 'merkle_root');
  assert.equal(Signing.signingPayload(RECEIPT_SAMPLE).toString('utf8'),
    receiptVector.tag + receiptVector.body);
  assert.equal(Signing.signingPayload(ROOT_SAMPLE, { domain: Merkle.ROOT_DOMAIN }).toString('utf8'),
    rootVector.tag + rootVector.body);
  assert.notEqual(Merkle.ROOT_DOMAIN, Signing.DOMAIN);
});

test('a non-integer number is refused with a named error, never rounded', () => {
  const cases = [0.5, -1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 2];
  for (const value of cases) {
    assert.throws(() => Ledger.canonical({ n: value }), (e) => e.code === 'LEDGER_NON_INTEGER_NUMBER',
      'expected LEDGER_NON_INTEGER_NUMBER for ' + String(value));
  }
  assert.throws(() => Ledger.canonical({ nested: [{ deep: 1.25 }] }), (e) => e.code === 'LEDGER_NON_INTEGER_NUMBER');

  // The same refusal applies where a builder takes the number directly.
  assert.throws(() => Ledger.checkpointBody({
    ledger_id: H_D4,
    tree_size: 1.5,
    root_hash: H_F6,
    created_at: AT,
    prev_checkpoint_hash: Ledger.GENESIS,
    policy_hash: H_18,
  }), (e) => e.code === 'LEDGER_NON_INTEGER_NUMBER');

  assert.equal(Ledger.canonical({ n: 3 }), '{"n":3}');
  assert.equal(Ledger.canonical({ n: -0 }), '{"n":0}');
  assert.equal(Ledger.canonical({ n: Number.MAX_SAFE_INTEGER }), '{"n":9007199254740991}');
});

test('an unknown scheme or version is refused, never parsed best-effort', () => {
  assert.throws(() => Ledger.entryHash(Object.assign({}, ENTRY, { scheme: 'verifyd-ledger-v2' })),
    (e) => e.code === 'LEDGER_UNSUPPORTED');
  assert.throws(() => Ledger.checkpointHash(Object.assign({}, CHECKPOINT, { scheme: 'verifyd-chain-v1' })),
    (e) => e.code === 'LEDGER_UNSUPPORTED');
  assert.throws(() => Ledger.cosignSigningPayload(Object.assign({}, COSIGN, { scheme: Merkle.SCHEME })),
    (e) => e.code === 'LEDGER_UNSUPPORTED');
  assert.throws(() => Ledger.entryHash(null), (e) => e.code === 'LEDGER_MALFORMED');
  assert.throws(() => Ledger.entryHash([]), (e) => e.code === 'LEDGER_MALFORMED');

  // A publication statement has its own scheme and must not be accepted as a
  // ledger object, or the other way round.
  assert.throws(() => Ledger.publicationStatementBytes(Object.assign({}, PUBLICATION, { scheme: Ledger.SCHEME })),
    (e) => e.code === 'LEDGER_UNSUPPORTED');
  assert.throws(() => Ledger.checkpointHash(Object.assign({}, CHECKPOINT, { scheme: Ledger.PUBLICATION_SCHEME })),
    (e) => e.code === 'LEDGER_UNSUPPORTED');
});

test('the size-0 genesis root is reproducible without Merkle.buildTree([])', () => {
  assert.throws(() => Merkle.buildTree([]), /at least one leaf/);

  const root = Ledger.emptyRoot();
  assert.equal(root.toString('hex'), EMPTY_TREE_ROOT);

  // Independent recomputation from the published rule:
  // SHA-256(0x02 || uint64be(0) || SHA-256(""))
  const size = Buffer.alloc(8);
  size.writeBigUInt64BE(0n);
  const expected = crypto.createHash('sha256').update(Buffer.concat([
    Buffer.from([0x02]),
    size,
    crypto.createHash('sha256').update(Buffer.alloc(0)).digest(),
  ])).digest();
  assert.equal(root.toString('hex'), expected.toString('hex'));

  const genesis = Ledger.genesisBody({ created_at: AT, policy_hash: H_18 });
  assert.equal(genesis.scheme, 'verifyd-ledger-v1');
  assert.equal(genesis.checkpoint_type, 'ledger');
  assert.equal(genesis.ledger_id, 'GENESIS');
  assert.equal(genesis.tree_size, 0);
  assert.equal(genesis.prev_checkpoint_hash, 'GENESIS');
  assert.equal(genesis.root_hash, EMPTY_TREE_ROOT);

  const id = Ledger.ledgerIdFromGenesis(genesis);
  assert.equal(id, GENESIS_LEDGER_ID);
  assert.equal(id, Ledger.checkpointHash(genesis));
  // The id is content-bound: a different creation time is a different ledger.
  assert.notEqual(Ledger.ledgerIdFromGenesis(Object.assign({}, genesis, { created_at: '2026-10-24T00:00:00.000Z' })), id);
  assert.throws(() => Ledger.ledgerIdFromGenesis(Object.assign({}, genesis, { ledger_id: H_D4 })),
    (e) => e.code === 'LEDGER_MALFORMED');
});

test('an entry signature covers the entry hash, and the hash ignores the signature', () => {
  assert.equal(ENTRY.entry_hash, ENTRY_HASH);

  const signed = Object.assign({}, ENTRY, { signature: { value: 'not-verified-here' } });
  assert.equal(Ledger.entryHash(signed), ENTRY_HASH);
  assert.equal(Ledger.entrySigningPayload(signed).toString('utf8'),
    Ledger.entrySigningPayload(ENTRY).toString('utf8'));

  // entry_hash is the digest of the body, so it cannot also be hashed into it;
  // it is covered by the signature preimage instead.
  const altered = Object.assign({}, ENTRY, { entry_hash: H_A });
  assert.notEqual(Ledger.entrySigningPayload(altered).toString('utf8'),
    Ledger.entrySigningPayload(ENTRY).toString('utf8'));
  assert.equal(Ledger.entryHash(altered), ENTRY_HASH);

  // payload_digest is what binds the receipt, so it must be covered by both.
  assert.notEqual(Ledger.entryHash(Object.assign({}, ENTRY, { payload_digest: H_A })), ENTRY_HASH);
});

test('a checkpoint signature covers its body and the hash ignores the signature', () => {
  const signed = Object.assign({}, CHECKPOINT, { signature: { value: 'not-verified-here' } });
  assert.equal(Ledger.checkpointHash(signed), Ledger.checkpointHash(CHECKPOINT));
  assert.equal(Ledger.checkpointSigningPayload(signed).toString('utf8'),
    Ledger.checkpointSigningPayload(CHECKPOINT).toString('utf8'));

  for (const field of ['tree_size', 'root_hash', 'ledger_id', 'policy_hash', 'prev_checkpoint_hash']) {
    const altered = Object.assign({}, CHECKPOINT, { [field]: field === 'tree_size' ? 2 : H_A });
    assert.notEqual(Ledger.checkpointHash(altered), Ledger.checkpointHash(CHECKPOINT),
      field + ' must change the checkpoint hash');
  }
});

test('a body under two tags produces two different digests', () => {
  const digests = VECTORS.map(v => v.sha256);
  assert.equal(new Set(digests).size, 10, 'every domain digest must be distinct');

  // Same canonical body, different tags: the signatures cannot be swapped.
  const entrySigBytes = Ledger.entrySigningPayload(ENTRY).toString('utf8');
  const body = entrySigBytes.slice('verifyd-ledger-entry-v1\nsig\n'.length);
  assert.notEqual(sha256Hex('verifyd-ledger-entry-v1\nhash\n' + body), sha256Hex(entrySigBytes));
});

test('policy hashing is order-insensitive and refuses duplicates', () => {
  const reversed = { writer_keys: [KEY_A, KEY_B], admin_keys: [KEY_A], witness_policy: POLICY_SAMPLE.witness_policy };
  assert.equal(Ledger.policyHash(reversed), Ledger.policyHash(POLICY_SAMPLE));
  assert.equal(Ledger.policyHash(POLICY_SAMPLE),
    'c6fe6d0cb8ac687edf1c7146f8bc3f7f3b37fbb403be477b65e7026791a6e4a1');

  assert.throws(() => Ledger.policyBody({ writer_keys: [KEY_A, KEY_A], admin_keys: [KEY_A] }),
    (e) => e.code === 'LEDGER_MALFORMED');
  assert.throws(() => Ledger.policyBody({ writer_keys: [KEY_A], admin_keys: [KEY_A], witness_policy: [1] }),
    (e) => e.code === 'LEDGER_MALFORMED');
});

test('impossible entry and checkpoint shapes are refused', () => {
  const malformed = (e) => e.code === 'LEDGER_MALFORMED';
  const entryBase = {
    ledger_id: H_D4,
    payload_digest: H_E5,
    receipt_id: null,
    recorded_at: AT,
    writer_key_id: KEY_A,
  };

  // In v1, seq equals the tree size of the checkpoint that follows, so there is
  // no seq 0 and GENESIS is only the predecessor of seq 1.
  assert.throws(() => Ledger.entryBody(Object.assign({}, entryBase, { seq: 0, prev_entry_hash: Ledger.GENESIS })),
    malformed, 'seq 0 must be refused');
  assert.throws(() => Ledger.entryBody(Object.assign({}, entryBase, { seq: 1, prev_entry_hash: H_A })),
    malformed, 'seq 1 must name GENESIS');
  assert.throws(() => Ledger.entryBody(Object.assign({}, entryBase, { seq: 2, prev_entry_hash: Ledger.GENESIS })),
    malformed, 'seq 2 must name the seq 1 entry hash');
  assert.equal(Ledger.entryBody(Object.assign({}, entryBase, { seq: 2, prev_entry_hash: H_A })).seq, 2);

  const cpBase = {
    ledger_id: H_D4,
    tree_size: 1,
    root_hash: H_F6,
    created_at: AT,
    prev_checkpoint_hash: H_07,
    policy_hash: H_18,
  };

  assert.throws(() => Ledger.checkpointBody(Object.assign({}, cpBase, { prev_checkpoint_hash: Ledger.GENESIS })),
    malformed, 'a checkpoint after genesis must name its predecessor');
  assert.throws(() => Ledger.checkpointBody(Object.assign({}, cpBase, { ledger_id: Ledger.GENESIS })),
    malformed, 'only size 0 may carry the GENESIS id');
  assert.throws(() => Ledger.checkpointBody(Object.assign({}, cpBase, { tree_size: 0 })),
    malformed, 'size 0 needs the GENESIS id');
  assert.throws(() => Ledger.checkpointBody(Object.assign({}, cpBase, {
    ledger_id: Ledger.GENESIS,
    tree_size: 0,
    prev_checkpoint_hash: Ledger.GENESIS,
  })), malformed, 'size 0 must carry the empty tree root, not a fabricated one');

  assert.equal(Ledger.checkpointBody(cpBase).tree_size, 1);
  assert.equal(Ledger.checkpointBody(Ledger.genesisBody({ created_at: AT, policy_hash: H_18 })).tree_size, 0);
});

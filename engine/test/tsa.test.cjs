'use strict';

const test = require('node:test');
const assert = require('node:assert');
const net = require('net');

const TSA = require('../tsa.cjs');
const asn1 = require('../asn1.cjs');
const { hasOpenssl, startTsa, makeUnrelatedCa } = require('./helpers/test-tsa.cjs');

const available = hasOpenssl();
const skip = available ? false : 'openssl is not available';

const payload = Buffer.from('verifyd signed payload bytes for timestamping');
const digest = TSA.sha256(payload);

let tsa = null;

test.before(async () => {
  if (!available) return;
  tsa = await startTsa();
});

test.after(async () => {
  if (tsa) await tsa.close();
});

test('request encoding is a well formed TimeStampReq', () => {
  const nonce = 42n;
  const request = TSA.buildRequest(digest, { nonce });
  const node = asn1.parse(request);

  assert.strictEqual(node.tag, 0x30, 'TimeStampReq is a SEQUENCE');
  const [version, imprint, nonceNode, certReq] = node.children;

  assert.strictEqual(asn1.decodeInteger(version.value), 1n, 'version 1');
  assert.strictEqual(imprint.tag, 0x30);
  assert.strictEqual(asn1.decodeOid(imprint.children[0].children[0].value), TSA.OID.sha256);
  assert.ok(imprint.children[1].value.equals(digest), 'imprint carries the payload digest');
  assert.strictEqual(asn1.decodeInteger(nonceNode.value), nonce);
  assert.strictEqual(certReq.tag, 0x01, 'certReq present');
  assert.strictEqual(certReq.value[0], 0xff, 'certReq TRUE');
});

test('a real TSA token verifies against its root', { skip }, async () => {
  const result = await TSA.requestTimestamp(tsa.url, payload);
  assert.strictEqual(result.ok, true, result.error);
  assert.ok(Buffer.isBuffer(result.token) && result.token.length > 200);

  const roots = TSA.loadRoots(tsa.caPath);
  const analysis = TSA.verifyToken(result.token, digest, { roots });

  assert.strictEqual(analysis.status, 'attested', analysis.reasons.join(', '));
  assert.strictEqual(analysis.imprint_match, true);
  assert.strictEqual(analysis.signature_valid, true);
  assert.strictEqual(analysis.digest_attribute_valid, true);
  assert.strictEqual(analysis.chain.trusted, true);
  assert.strictEqual(analysis.nonce, result.nonce, 'TSA echoed the request nonce');
  assert.ok(!Number.isNaN(Date.parse(analysis.gen_time)));
  assert.match(analysis.gen_time, /^\d{4}-\d{2}-\d{2}T/);
});

test('a token for other bytes fails the imprint check', { skip }, async () => {
  const result = await TSA.requestTimestamp(tsa.url, payload);
  const roots = TSA.loadRoots(tsa.caPath);
  const analysis = TSA.verifyToken(result.token, TSA.sha256(Buffer.from('different bytes')), { roots });

  assert.strictEqual(analysis.status, 'invalid');
  assert.ok(analysis.reasons.includes('imprint_mismatch'), analysis.reasons.join(', '));
  assert.strictEqual(analysis.imprint_match, false);
});

test('a token issued under an unrelated root is rejected', { skip }, async () => {
  const result = await TSA.requestTimestamp(tsa.url, payload);
  const unrelated = makeUnrelatedCa(tsa.caDir);
  const analysis = TSA.verifyToken(result.token, digest, { roots: TSA.loadRoots(unrelated) });

  assert.strictEqual(analysis.status, 'invalid');
  assert.ok(analysis.reasons.some(r => r.startsWith('chain_')), analysis.reasons.join(', '));
  assert.strictEqual(analysis.signature_valid, true, 'the token signature itself is fine');
});

test('without a trust root the token is unverified, never attested', { skip }, async () => {
  const result = await TSA.requestTimestamp(tsa.url, payload);
  const analysis = TSA.verifyToken(result.token, digest, { roots: [] });

  assert.strictEqual(analysis.status, 'unverified');
  assert.strictEqual(analysis.imprint_match, true);
  assert.strictEqual(analysis.signature_valid, true);
  assert.strictEqual(analysis.chain.reason, 'no_trust_roots_configured');
});

test('a corrupt token is reported as invalid, not thrown', { skip }, async () => {
  const analysis = TSA.verifyToken(Buffer.from('not a timestamp token at all'), digest, { roots: [] });
  assert.strictEqual(analysis.status, 'invalid');
  assert.ok(analysis.reasons[0].startsWith('token_parse_failed'), analysis.reasons.join(', '));
});

test('an unreachable TSA returns an error instead of throwing', async () => {
  const port = await new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });

  const result = await TSA.requestTimestamp('http://127.0.0.1:' + port + '/tsa', payload, { timeoutMs: 2000 });
  assert.strictEqual(result.ok, false);
  assert.match(result.error, /tsa_unreachable/);
});

test('an invalid TSA url is handled without throwing', async () => {
  const result = await TSA.requestTimestamp('ftp://example.invalid/tsa', payload, { timeoutMs: 500 });
  assert.strictEqual(result.ok, false);
  assert.match(result.error, /unsupported_tsa_protocol|invalid_tsa_url/);
});

test('loadRoots explains a missing CA file', () => {
  assert.throws(() => TSA.loadRoots('does-not-exist.pem'), /cannot read CA file|TSA_CA_UNREADABLE/);
});

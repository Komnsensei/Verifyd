// Verifyd external timestamping - RFC 3161 (Time-Stamp Protocol).
// Zero dependencies: Node crypto plus the minimal DER reader in engine/asn1.cjs.
//
// WHAT A TIMESTAMP PROVES
//   That the authority which signed this token signed a message imprint equal
//   to the SHA-256 of our signed payload, and that the authority asserts that
//   imprint existed at (or before) the token's genTime.
//
// WHAT IT DOES NOT PROVE
//   - That the receipt content is true, complete, or produced by an honest
//     signer. It binds time to bytes, nothing else.
//   - That the audit actually ran at genTime: a receipt can be timestamped
//     long after it was signed, or a backdated clock can still be timestamped.
//     All it rules out is claiming the bytes did not exist before genTime.
//   - That the authority itself is trustworthy. Trust comes from the CA you
//     configure; without one the token is reported as UNVERIFIED, never as
//     attested.
//   - Anything about revocation: CRLs and OCSP are not checked.
//
// BINDING MODEL
//   The token cannot live inside the signed payload (that would be circular),
//   so it is attached to the envelope after signing. The digest that the token
//   covers is the SHA-256 of exactly the bytes the receipt signature covers
//   (domain tag plus canonical envelope, minus `signature` and `timestamp`).
//   Verification recomputes those bytes, recomputes the digest, and requires
//   the token's messageImprint to equal it. A token lifted from another
//   receipt therefore cannot pass.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');

const asn1 = require('./asn1.cjs');

const OID = Object.freeze({
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  rsaSha256: '1.2.840.113549.1.1.11',
  rsaSha384: '1.2.840.113549.1.1.12',
  rsaSha512: '1.2.840.113549.1.1.13',
  rsaEncryption: '1.2.840.113549.1.1.1',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  ecdsaSha384: '1.2.840.10045.4.3.3',
  ecdsaSha512: '1.2.840.10045.4.3.4',
  ecPublicKey: '1.2.840.10045.2.1',
  ed25519: '1.3.101.112',
  timeStamping: '1.3.6.1.5.5.7.3.8',
});

const DIGEST_NAME = {
  [OID.sha1]: 'sha1',
  [OID.sha256]: 'sha256',
  [OID.sha384]: 'sha384',
  [OID.sha512]: 'sha512',
};

// signature algorithm OID -> node verify algorithm (null means Ed25519)
const SIGNATURE_ALG = {
  [OID.rsaSha256]: 'sha256',
  [OID.rsaSha384]: 'sha384',
  [OID.rsaSha512]: 'sha512',
  [OID.ecdsaSha256]: 'sha256',
  [OID.ecdsaSha384]: 'sha384',
  [OID.ecdsaSha512]: 'sha512',
  [OID.ed25519]: null,
};

const DEFAULT_TIMEOUT_MS = 10000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

function fail(code, detail) {
  const e = new Error(detail || code);
  e.code = code;
  return e;
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

function configuredUrl(cliValue) {
  return cliValue || process.env.VERIFYD_TSA_URL || null;
}

function configuredCaPath(cliValue) {
  return cliValue || process.env.VERIFYD_TSA_CA || null;
}

function configuredTimeout(cliValue) {
  const raw = cliValue || process.env.VERIFYD_TSA_TIMEOUT_MS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
}

// ---------------------------------------------------------------- request

function algorithmIdentifierSha256() {
  return asn1.sequence([asn1.oid(OID.sha256)]);
}

function buildRequest(imprint, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(imprint) || imprint.length !== 32) {
    throw fail('INVALID_IMPRINT', 'imprint must be a 32-byte SHA-256 digest');
  }
  const parts = [
    asn1.integer(1),
    asn1.sequence([algorithmIdentifierSha256(), asn1.octetString(imprint)]),
  ];
  if (opts.nonce !== undefined && opts.nonce !== null) parts.push(asn1.integer(opts.nonce));
  if (opts.certReq !== false) parts.push(asn1.boolean(true));
  return asn1.sequence(parts);
}

function parseResponse(buf) {
  const root = asn1.parse(buf);
  if (root.tag !== 0x30) throw fail('MALFORMED_RESPONSE', 'TimeStampResp is not a SEQUENCE');
  const statusInfo = root.children[0];
  if (!statusInfo || statusInfo.tag !== 0x30) throw fail('MALFORMED_RESPONSE', 'missing PKIStatusInfo');
  const statusNode = statusInfo.children[0];
  const status = statusNode ? Number(asn1.decodeInteger(statusNode.value)) : -1;
  const statusText = statusInfo.children[1] && statusInfo.children[1].tag === 0x30
    ? statusInfo.children[1].children.map(c => c.value.toString('utf8')).join('; ')
    : null;
  const tokenNode = root.children[1] || null;
  return {
    status,
    granted: status === 0 || status === 1,
    statusText,
    token: tokenNode ? tokenNode.raw : null,
  };
}

// ---------------------------------------------------------------- token

function parseTstInfo(buf) {
  const root = asn1.parse(buf);
  if (root.tag !== 0x30) throw fail('MALFORMED_TSTINFO', 'TSTInfo is not a SEQUENCE');

  let version = null;
  let policy = null;
  let messageImprint = null;
  let serialNumber = null;
  let genTime = null;
  let nonce = null;

  for (const child of root.children) {
    if (child.tag === 0x02) {
      if (version === null) version = Number(asn1.decodeInteger(child.value));
      else if (nonce === null) nonce = asn1.decodeInteger(child.value);
    } else if (child.tag === 0x06 && policy === null) {
      policy = asn1.decodeOid(child.value);
    } else if (child.tag === 0x30 && !messageImprint) {
      const alg = child.children[0];
      const digest = child.children.find(c => c.tag === 0x04);
      if (!alg || alg.tag !== 0x30 || !digest) throw fail('MALFORMED_TSTINFO', 'bad messageImprint');
      messageImprint = {
        algorithm: asn1.decodeOid(alg.children[0].value),
        hashedMessage: digest.value,
      };
    } else if (child.tag === 0x02 && serialNumber === null) {
      serialNumber = asn1.decodeInteger(child.value);
    } else if ((child.tag === 0x18 || child.tag === 0x17) && genTime === null) {
      genTime = asn1.decodeTime(child);
    }
  }

  // serialNumber and nonce are both INTEGER: pick them by position after genTime
  // is known, so the second INTEGER encountered before genTime is the serial.
  const ints = root.children.filter(c => c.tag === 0x02);
  if (ints.length >= 2) serialNumber = asn1.decodeInteger(ints[1].value);
  if (ints.length >= 3) nonce = asn1.decodeInteger(ints[2].value);

  if (!messageImprint) throw fail('MALFORMED_TSTINFO', 'missing messageImprint');
  if (!genTime) throw fail('MALFORMED_TSTINFO', 'missing genTime');

  return {
    version,
    policy,
    messageImprint,
    serialNumber: serialNumber === null ? null : serialNumber.toString(),
    genTime,
    nonce: nonce === null ? null : nonce.toString(),
  };
}

function parseToken(tokenDer) {
  const contentInfo = asn1.parse(tokenDer);
  if (contentInfo.tag !== 0x30) throw fail('MALFORMED_TOKEN', 'ContentInfo is not a SEQUENCE');

  const contentType = contentInfo.children[0];
  if (!contentType || contentType.tag !== 0x06) throw fail('MALFORMED_TOKEN', 'missing content type');
  if (asn1.decodeOid(contentType.value) !== OID.signedData) {
    throw fail('MALFORMED_TOKEN', 'ContentInfo is not SignedData');
  }
  const explicit = contentInfo.children.find(c => c.tag === 0xA0);
  if (!explicit) throw fail('MALFORMED_TOKEN', 'missing SignedData content');

  const signedData = explicit.children[0];
  if (!signedData || signedData.tag !== 0x30) throw fail('MALFORMED_TOKEN', 'bad SignedData');

  const digestAlgorithms = signedData.children[1];
  const encap = signedData.children[2];
  if (!encap || encap.tag !== 0x30) throw fail('MALFORMED_TOKEN', 'missing encapContentInfo');

  const eContentTypeNode = encap.children[0];
  if (!eContentTypeNode || eContentTypeNode.tag !== 0x06) {
    throw fail('MALFORMED_TOKEN', 'missing eContentType');
  }
  const eContentType = asn1.decodeOid(eContentTypeNode.value);
  if (eContentType !== OID.tstInfo) throw fail('MALFORMED_TOKEN', 'eContentType is not TSTInfo');

  const eContentWrapper = encap.children.find(c => c.tag === 0xA0);
  const eContentNode = eContentWrapper && eContentWrapper.children[0];
  if (!eContentNode || eContentNode.tag !== 0x04) throw fail('MALFORMED_TOKEN', 'missing eContent');
  const eContent = eContentNode.value;

  const certNode = signedData.children.find(c => c.tag === 0xA0);
  const certs = certNode
    ? certNode.children.filter(c => c.tag === 0x30).map(c => c.raw)
    : [];

  // SignedData ends with signerInfos; digestAlgorithms is the other SET.
  const signerInfosNode = signedData.children.filter(c => c.tag === 0x31).pop();
  if (!signerInfosNode || signerInfosNode.children.length === 0) {
    throw fail('MALFORMED_TOKEN', 'missing signerInfos');
  }
  const signerInfo = signerInfosNode.children[0];

  const sid = signerInfo.children[1];
  const digestAlgorithmNode = signerInfo.children[2];
  const signedAttrsNode = signerInfo.children.find(c => c.tag === 0xA0) || null;
  const signatureAlgorithmNode = signerInfo.children.find((c, i) => i >= 3 && c.tag === 0x30 && c !== digestAlgorithmNode);
  const signatureNode = signerInfo.children.filter(c => c.tag === 0x04).pop();

  if (!digestAlgorithmNode || digestAlgorithmNode.tag !== 0x30) {
    throw fail('MALFORMED_TOKEN', 'missing digestAlgorithm');
  }
  if (!signatureAlgorithmNode || !signatureNode || signatureNode.tag !== 0x04) {
    throw fail('MALFORMED_TOKEN', 'missing signature');
  }

  const signedAttrs = signedAttrsNode
    ? { raw: signedAttrsNode.raw, der: Buffer.concat([Buffer.from([0x31]), signedAttrsNode.raw.slice(1)]) }
    : null;

  let attributes = {};
  if (signedAttrsNode) {
    for (const attr of signedAttrsNode.children) {
      if (attr.tag !== 0x30 || attr.children.length < 2) continue;
      const attrType = asn1.decodeOid(attr.children[0].value);
      const values = attr.children[1].children;
      attributes[attrType] = values.length === 1 ? values[0].value : values.map(v => v.value);
    }
  }

  return {
    eContent,
    digestAlgorithm: asn1.decodeOid(digestAlgorithmNode.children[0].value),
    signatureAlgorithm: asn1.decodeOid(signatureAlgorithmNode.children[0].value),
    signature: signatureNode.value,
    signedAttrs,
    attributes,
    certs,
    sid: sid ? sid.raw : null,
    sidTag: sid ? sid.tag : null,
    sidCls: sid ? sid.cls : null,
    signerSerial: sid && sid.tag === 0x30 && sid.children[1] && sid.children[1].tag === 0x02
      ? asn1.decodeInteger(sid.children[1].value).toString()
      : null,
    digestAlgorithmCount: digestAlgorithms ? digestAlgorithms.children.length : 0,
    tstInfo: parseTstInfo(eContent),
  };
}

// ---------------------------------------------------------------- trust

function sameCert(a, b) {
  try { return a.raw.equals(b.raw); } catch (_) { return false; }
}

function loadRoots(paths) {
  if (!paths) return [];
  const list = Array.isArray(paths) ? paths : String(paths).split(',');
  const roots = [];
  for (const raw of list) {
    const file = String(raw).trim();
    if (!file) continue;
    let pem;
    try {
      pem = fs.readFileSync(file, 'utf8');
    } catch (e) {
      throw fail('TSA_CA_UNREADABLE', 'cannot read CA file ' + file + ': ' + e.message);
    }
    const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
    if (blocks.length === 0) throw fail('TSA_CA_EMPTY', 'no certificate found in ' + file);
    for (const block of blocks) {
      roots.push(new crypto.X509Certificate(block));
    }
  }
  return roots;
}

function chainToRoot(signer, embedded, roots) {
  const path = [signer];
  let current = signer;

  for (let depth = 0; depth < 5; depth++) {
    if (roots.some(r => sameCert(r, current))) {
      return { trusted: true, root_subject: current.subject, path, reason: null };
    }
    const candidates = embedded
      .concat(roots)
      .filter(c => !sameCert(c, current) && c.subject === current.issuer);
    const next = candidates.find(c => {
      try { return current.checkIssued(c) && current.verify(c.publicKey); } catch (_) { return false; }
    });
    if (!next) return { trusted: false, root_subject: null, path, reason: 'chain_incomplete' };
    path.push(next);
    current = next;
  }
  return { trusted: false, root_subject: null, path, reason: 'chain_too_long' };
}

function isTimeStamping(signer) {
  const eku = Array.isArray(signer.keyUsage) ? signer.keyUsage : [];
  if (eku.length === 0) return { ok: false, present: false };
  return { ok: eku.includes(OID.timeStamping), present: true };
}

function invalid(reasons, extra) {
  return Object.assign({
    status: 'invalid',
    reasons,
    imprint_match: false,
    signature_valid: false,
    digest_attribute_valid: false,
    gen_time: null,
    policy: null,
    serial: null,
    nonce: null,
    signer: null,
    chain: null,
    checks: {},
  }, extra || {});
}

function verifyToken(tokenDer, expectedDigest, opts) {
  opts = opts || {};
  const roots = opts.roots || [];

  let token;
  try {
    token = parseToken(tokenDer);
  } catch (e) {
    return invalid(['token_parse_failed: ' + (e.code || e.message)]);
  }

  const tst = token.tstInfo;
  const reasons = [];
  const checks = {
    imprint_algorithm: tst.messageImprint.algorithm,
    imprint: false,
    signed_attrs_digest: false,
    signature: false,
    cert_valid_at_time: false,
    eku: false,
    chain: roots.length === 0 ? 'not_checked' : false,
  };

  if (tst.messageImprint.algorithm !== OID.sha256) {
    reasons.push('imprint_algorithm_unsupported: ' + tst.messageImprint.algorithm);
  } else if (!tst.messageImprint.hashedMessage.equals(expectedDigest)) {
    reasons.push('imprint_mismatch');
  } else {
    checks.imprint = true;
  }

  if (token.attributes[OID.contentType]) {
    const ct = Buffer.isBuffer(token.attributes[OID.contentType])
      ? asn1.decodeOid(token.attributes[OID.contentType])
      : null;
    if (ct && ct !== OID.tstInfo) reasons.push('content_type_attribute_mismatch');
  } else {
    reasons.push('content_type_attribute_missing');
  }

  const digestName = DIGEST_NAME[token.digestAlgorithm] || null;
  if (!digestName) {
    reasons.push('digest_algorithm_unsupported: ' + token.digestAlgorithm);
  } else if (token.attributes[OID.messageDigest]) {
    const expected = crypto.createHash(digestName).update(token.eContent).digest();
    if (Buffer.isBuffer(token.attributes[OID.messageDigest]) &&
        token.attributes[OID.messageDigest].equals(expected)) {
      checks.signed_attrs_digest = true;
    } else {
      reasons.push('signed_attrs_digest_mismatch');
    }
  } else {
    reasons.push('signed_attrs_missing_message_digest');
  }

  // pick the signer certificate
  let signerDer = token.certs[0] || null;
  if (token.signerSerial && token.certs.length > 1) {
    const match = token.certs.find(der => {
      try {
        const cert = new crypto.X509Certificate(der);
        return BigInt('0x' + cert.serialNumber) === BigInt(token.signerSerial);
      } catch (_) { return false; }
    });
    if (match) signerDer = match;
  }

  let signer = null;
  if (!signerDer) {
    reasons.push('signer_certificate_absent');
  } else {
    try {
      signer = new crypto.X509Certificate(signerDer);
    } catch (e) {
      reasons.push('signer_certificate_unparseable');
    }
  }

  if (signer && token.signedAttrs) {
    // CMS often names the key type (rsaEncryption) rather than a combined
    // hash+signature OID; in that case the digest comes from digestAlgorithm.
    let alg;
    if (token.signatureAlgorithm === OID.rsaEncryption || token.signatureAlgorithm === OID.ecPublicKey) {
      alg = DIGEST_NAME[token.digestAlgorithm];
    } else {
      alg = SIGNATURE_ALG[token.signatureAlgorithm];
    }
    if (alg === undefined) {
      reasons.push('signature_algorithm_unsupported: ' + token.signatureAlgorithm);
    } else {
      try {
        checks.signature = crypto.verify(alg, token.signedAttrs.der, signer.publicKey, token.signature);
      } catch (_) {
        checks.signature = false;
      }
      if (!checks.signature) reasons.push('token_signature_invalid');
    }
  } else if (signer) {
    reasons.push('signed_attrs_missing');
  }

  if (signer) {
    const at = tst.genTime.getTime();
    checks.cert_valid_at_time = at >= signer.validFromDate.getTime() && at <= signer.validToDate.getTime();
    if (!checks.cert_valid_at_time) reasons.push('signer_certificate_not_valid_at_gen_time');

    const eku = isTimeStamping(signer);
    checks.eku = eku.ok;
    if (!eku.present) reasons.push('signer_certificate_has_no_eku');
    else if (!eku.ok) reasons.push('signer_certificate_missing_time_stamping_eku');
  }

  let chain = null;
  if (signer && roots.length > 0) {
    const embedded = token.certs
      .map(der => { try { return new crypto.X509Certificate(der); } catch (_) { return null; } })
      .filter(Boolean);
    chain = chainToRoot(signer, embedded, roots);
    checks.chain = chain.trusted;
    if (!chain.trusted) reasons.push('chain_' + (chain.reason || 'untrusted'));
  }

  const hard = reasons.filter(r => r !== 'chain_incomplete' || roots.length > 0);
  let status;
  if (hard.length > 0) status = 'invalid';
  else if (roots.length === 0) status = 'unverified';
  else status = 'attested';

  return {
    status,
    reasons,
    imprint_match: checks.imprint,
    signature_valid: checks.signature,
    digest_attribute_valid: checks.signed_attrs_digest,
    gen_time: tst.genTime.toISOString(),
    policy: tst.policy,
    serial: tst.serialNumber,
    nonce: tst.nonce,
    signer: signer ? {
      subject: signer.subject.replace(/\n/g, ', '),
      issuer: signer.issuer.replace(/\n/g, ', '),
      serial: signer.serialNumber,
      not_before: signer.validFromDate.toISOString(),
      not_after: signer.validToDate.toISOString(),
    } : null,
    chain: chain ? {
      trusted: chain.trusted,
      root_subject: chain.root_subject ? chain.root_subject.replace(/\n/g, ', ') : null,
      reason: chain.reason,
      path: chain.path.map(c => c.subject.replace(/\n/g, ', ')),
    } : { trusted: false, root_subject: null, reason: roots.length ? 'not_checked' : 'no_trust_roots_configured', path: [] },
    checks,
  };
}

// ---------------------------------------------------------------- client

function post(urlString, body, timeoutMs) {
  return new Promise((resolve) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (e) {
      resolve({ ok: false, error: 'invalid_tsa_url' });
      return;
    }
    const transport = url.protocol === 'https:' ? https : url.protocol === 'http:' ? http : null;
    if (!transport) {
      resolve({ ok: false, error: 'unsupported_tsa_protocol: ' + url.protocol });
      return;
    }

    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    const req = transport.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/timestamp-query',
        Accept: 'application/timestamp-reply',
        'Content-Length': body.length,
        'User-Agent': 'verifyd/1.0 (rfc3161)',
      },
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          req.destroy();
          done({ ok: false, error: 'tsa_response_too_large' });
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          done({ ok: false, error: 'tsa_http_' + res.statusCode });
          return;
        }
        done({ ok: true, body: Buffer.concat(chunks) });
      });
    });

    req.on('error', (e) => done({ ok: false, error: 'tsa_unreachable: ' + (e.code || e.message) }));
    const timer = setTimeout(() => {
      req.destroy();
      done({ ok: false, error: 'tsa_timeout' });
    }, timeoutMs);
    if (timer.unref) timer.unref();

    req.write(body);
    req.end();
  });
}

async function requestTimestamp(urlString, payloadBytes, opts) {
  opts = opts || {};
  const imprint = sha256(payloadBytes);
  const nonce = crypto.randomBytes(8);
  if (nonce[0] & 0x80) nonce[0] &= 0x7f;
  const nonceValue = BigInt('0x' + nonce.toString('hex'));

  let request;
  try {
    request = buildRequest(imprint, { nonce: nonceValue });
  } catch (e) {
    return { ok: false, error: 'tsa_request_build_failed: ' + (e.code || e.message) };
  }

  const posted = await post(urlString, request, opts.timeoutMs || DEFAULT_TIMEOUT_MS);
  if (!posted.ok) return { ok: false, error: posted.error, imprint: imprint.toString('hex') };

  let response;
  try {
    response = parseResponse(posted.body);
  } catch (e) {
    return { ok: false, error: 'tsa_response_parse_failed: ' + (e.code || e.message), imprint: imprint.toString('hex') };
  }

  if (!response.granted || !response.token) {
    return {
      ok: false,
      error: 'tsa_rejected: status ' + response.status + (response.statusText ? ' (' + response.statusText + ')' : ''),
      imprint: imprint.toString('hex'),
    };
  }

  return {
    ok: true,
    token: response.token,
    imprint: imprint.toString('hex'),
    nonce: nonceValue.toString(),
    tsa_url: urlString,
  };
}

module.exports = {
  OID,
  DIGEST_NAME,
  DEFAULT_TIMEOUT_MS,
  configuredUrl,
  configuredCaPath,
  configuredTimeout,
  sha256,
  buildRequest,
  parseResponse,
  parseToken,
  verifyToken,
  loadRoots,
  requestTimestamp,
};

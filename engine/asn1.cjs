// Minimal DER reader/writer - just enough for RFC 3161.
// Zero dependencies. Definite lengths only (DER forbids indefinite form).

'use strict';

function fail(code, detail) {
  const e = new Error(detail || code);
  e.code = code;
  return e;
}

// ---------------------------------------------------------------- writer

function encodeLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

function tlv(tag, content) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content || []);
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

function sequence(parts) { return tlv(0x30, Buffer.concat(parts)); }
function set(parts) { return tlv(0x31, Buffer.concat(parts)); }
function octetString(buf) { return tlv(0x04, buf); }
function boolean(value) { return tlv(0x01, Buffer.from([value ? 0xff : 0x00])); }
function nullValue() { return tlv(0x05, Buffer.alloc(0)); }

function integer(value) {
  let v = typeof value === 'bigint' ? value : BigInt(value);
  if (v < 0n) throw fail('NEGATIVE_INTEGER', 'DER INTEGER here must be non-negative');
  const bytes = [];
  if (v === 0n) bytes.push(0);
  while (v > 0n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
}

function oid(dotted) {
  const parts = String(dotted).split('.').map(Number);
  if (parts.length < 2 || parts.some(n => !Number.isInteger(n) || n < 0)) {
    throw fail('INVALID_OID', dotted);
  }
  const bytes = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [part & 0x7f];
    let v = Math.floor(part / 128);
    while (v > 0) { chunk.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

// ---------------------------------------------------------------- reader

function readHeader(buf, offset) {
  if (!Buffer.isBuffer(buf)) throw fail('NOT_A_BUFFER');
  if (offset + 2 > buf.length) throw fail('TRUNCATED_TLV', 'offset ' + offset);

  const first = buf[offset];
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let p = offset + 1;

  if (tag === 0x1f) {
    tag = 0;
    let b;
    do {
      if (p >= buf.length) throw fail('TRUNCATED_HIGH_TAG');
      b = buf[p++];
      tag = (tag << 7) | (b & 0x7f);
    } while (b & 0x80);
  }

  if (p >= buf.length) throw fail('TRUNCATED_TLV', 'missing length');
  let length = buf[p++];

  if (length === 0x80) throw fail('INDEFINITE_LENGTH_UNSUPPORTED');
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw fail('INVALID_LENGTH', String(length));
    length = 0;
    for (let i = 0; i < count; i++) {
      if (p >= buf.length) throw fail('TRUNCATED_TLV', 'length bytes');
      length = length * 256 + buf[p++];
    }
  }

  const contentStart = p;
  const end = contentStart + length;
  if (end > buf.length) throw fail('TRUNCATED_CONTENT', 'need ' + length + ' bytes at ' + contentStart);

  return { cls, constructed, tag, tagByte: first, length, start: offset, contentStart, end };
}

// `tag` is the identifier octet (0x30 SEQUENCE, 0x02 INTEGER, 0xA0 context
// [0], ...) for low tag numbers, which is what RFC 3161 structures use.
// `tagNumber` is the bare tag number for code that wants DER semantics.
function parse(buf, offset) {
  offset = offset || 0;
  const header = readHeader(buf, offset);
  const node = {
    tag: (header.cls << 6) | (header.constructed ? 0x20 : 0) | header.tag,
    tagNumber: header.tag,
    tagByte: header.tagByte,
    cls: header.cls,
    constructed: header.constructed,
    length: header.length,
    start: header.start,
    contentStart: header.contentStart,
    end: header.end,
    raw: buf.slice(header.start, header.end),
    value: header.constructed ? null : buf.slice(header.contentStart, header.end),
    children: [],
  };
  if (header.constructed) {
    let p = header.contentStart;
    while (p < header.end) {
      const child = parse(buf, p);
      node.children.push(child);
      p = child.end;
    }
    if (p !== header.end) throw fail('TRAILING_BYTES', 'at ' + p);
  }
  return node;
}

function parseAll(buf) {
  const nodes = [];
  let p = 0;
  while (p < buf.length) {
    const node = parse(buf, p);
    nodes.push(node);
    p = node.end;
  }
  return nodes;
}

function decodeOid(buf) {
  if (buf.length === 0) throw fail('INVALID_OID', 'empty');
  const first = buf[0];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < buf.length; i++) {
    const b = buf[i];
    value = value * 128 + (b & 0x7f);
    if (!(b & 0x80)) { parts.push(value); value = 0; }
  }
  return parts.join('.');
}

function decodeInteger(buf) {
  let v = 0n;
  for (const b of buf) v = (v << 8n) | BigInt(b);
  return v;
}

function decodeTime(node) {
  const text = node.value.toString('ascii');
  if (node.tag === 0x18) {
    const m = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/);
    if (!m) throw fail('INVALID_GENERALIZED_TIME', text);
    const ms = m[7] ? Math.round(Number('0.' + m[7]) * 1000) : 0;
    return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms));
  }
  if (node.tag === 0x17) {
    const m = text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) throw fail('INVALID_UTC_TIME', text);
    const year = +m[1] < 50 ? 2000 + +m[1] : 1900 + +m[1];
    return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  }
  throw fail('NOT_A_TIME', 'tag ' + node.tag);
}

function find(nodes, tag) {
  return nodes.find(n => n.tag === tag) || null;
}

module.exports = {
  // writer
  tlv,
  sequence,
  set,
  octetString,
  boolean,
  nullValue,
  integer,
  oid,
  // reader
  parse,
  parseAll,
  decodeOid,
  decodeInteger,
  decodeTime,
  find,
};

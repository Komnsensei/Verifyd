'use strict';

const path = require('path');

function detectMagic(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf || []);

  if (buf.length >= 4 && buf.slice(0, 4).toString('hex') === '25504446') return 'application/pdf';
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length >= 8 && buf.slice(0, 8).toString('hex') === '89504e470d0a1a0a') return 'image/png';
  if (buf.length >= 6 && (buf.slice(0, 6).toString('ascii') === 'GIF87a' || buf.slice(0, 6).toString('ascii') === 'GIF89a')) return 'image/gif';
  if (buf.length >= 12 && buf.slice(0, 4).toString('ascii') === 'RIFF' && buf.slice(8, 12).toString('ascii') === 'WEBP') return 'image/webp';

  return 'application/octet-stream';
}

function expectedFromExtension(file) {
  const ext = path.extname(file).toLowerCase();
  if (ext === '.pdf') return 'application/pdf';
  if (ext === '.jpg' || ext === '.jpeg') return 'image/jpeg';
  if (ext === '.png') return 'image/png';
  if (ext === '.gif') return 'image/gif';
  if (ext === '.webp') return 'image/webp';
  if (ext === '.txt' || ext === '.md') return 'text/plain';
  return null;
}

function extensionMismatch(file, magic) {
  const expected = expectedFromExtension(file);
  if (!expected) return false;
  if (expected === 'text/plain') return false;
  return expected !== magic;
}

module.exports = { detectMagic, expectedFromExtension, extensionMismatch };

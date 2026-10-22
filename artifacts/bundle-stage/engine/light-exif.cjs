'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { DEFAULT_LIMITS } = require('./limits.cjs');
const FileType = require('./file-type.cjs');
const SecretScan = require('./secret-scan.cjs');

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function extractJpegExifBlock(buf) {
  if (!(buf[0] === 0xff && buf[1] === 0xd8)) return null;

  let i = 2;
  while (i + 4 < buf.length) {
    if (buf[i] !== 0xff) break;
    const marker = buf[i + 1];
    const len = buf.readUInt16BE(i + 2);
    if (len < 2) return { malformed: true, block: null };

    if (marker === 0xe1) {
      const block = buf.slice(i + 4, i + 2 + len);
      if (block.slice(0, 6).toString('ascii') === 'Exif\0\0') {
        return { malformed: false, block };
      }
    }

    i += 2 + len;
  }

  return null;
}

function asciiStrings(buf) {
  return (buf.toString('latin1').match(/[ -~]{4,}/g) || []).slice(0, 200);
}

function auditFile(file, opts) {
  opts = opts || {};
  const limits = Object.assign({}, DEFAULT_LIMITS, opts.limits || {});
  const full = path.resolve(file);

  if (!fs.existsSync(full) || !fs.statSync(full).isFile()) {
    const e = new Error('FILE_NOT_FOUND');
    e.code = 'FILE_NOT_FOUND';
    throw e;
  }

  const buf = fs.readFileSync(full);
  const magic = FileType.detectMagic(buf);
  const extMismatch = FileType.extensionMismatch(full, magic);
  const flags = [];

  if (extMismatch) flags.push('EXTENSION_MAGIC_MISMATCH');

  let metadata_present = false;
  let metadata_hash = null;
  let fields = {
    datetime_original: null,
    create_date: null,
    modify_date: null,
    camera_make: null,
    camera_model: null,
    software: null,
    gps_present: false
  };

  if (magic === 'image/jpeg') {
    const exif = extractJpegExifBlock(buf);

    if (exif && exif.malformed) flags.push('MALFORMED_EXIF_BLOCK');

    if (exif && exif.block) {
      metadata_present = true;

      if (exif.block.length > limits.maxMetadataBytes) {
        flags.push('OVERSIZED_METADATA_BLOCK');
      }

      metadata_hash = 'sha256:' + sha256(exif.block);

      const strings = asciiStrings(exif.block);
      const joined = strings.join('\n');

      const dates = joined.match(/\d{4}[:\-]\d{2}[:\-]\d{2}[ T:]\d{2}:\d{2}:\d{2}/g) || [];
      fields.datetime_original = dates[0] || null;
      fields.create_date = dates[1] || null;
      fields.modify_date = dates[2] || null;

      const softwareHit = strings.find(s => /(photoshop|lightroom|gimp|canva|midjourney|stable diffusion|dall-e|firefly|editor|generator)/i.test(s));
      fields.software = softwareHit || null;
      if (softwareHit) flags.push('EDITOR_OR_GENERATOR_SOFTWARE_MARKER');

      if (/GPS|GPSLatitude|GPSLongitude|N\0|S\0|E\0|W\0/i.test(joined)) {
        fields.gps_present = true;
      }

      if (SecretScan.scanText(joined).has_secret) {
        flags.push('SECRET_PATTERN_IN_METADATA');
      }

      if (dates.length >= 2 && dates[0] !== dates[1]) {
        flags.push('TIMESTAMP_FIELDS_DIFFER');
      }
    }
  } else {
    flags.push('NO_EXIF_PARSER_FOR_MAGIC_TYPE');
  }

  const strictFailFlags = [
    'EXTENSION_MAGIC_MISMATCH',
    'MALFORMED_EXIF_BLOCK',
    'OVERSIZED_METADATA_BLOCK',
    'SECRET_PATTERN_IN_METADATA'
  ];

  const failed = opts.strict && flags.some(f => strictFailFlags.includes(f));

  return {
    audit_mode: 'light_exif',
    file: {
      path_label: path.basename(full),
      size_bytes: buf.length,
      sha256: 'sha256:' + sha256(buf),
      magic_type: magic,
      extension: path.extname(full).toLowerCase()
    },
    metadata: {
      metadata_present,
      metadata_hash,
      trusted_as_truth: false,
      fields
    },
    forgery_posture: {
      verdict: failed ? 'failed' : flags.length ? 'suspicious' : metadata_present ? 'clean' : 'unknown',
      confidence: flags.length ? 'medium' : 'low',
      flags
    }
  };
}

module.exports = { auditFile };

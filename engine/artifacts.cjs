// Shared JSON artifact reader.
//
// Every receipt, determination and batch root is read through this module. It
// keeps the filesystem mistakes that used to leak EISDIR, and the JSON mistakes
// that used to reach verification, in one place. Callers choose the wording,
// but they do not re-implement the checks.
//
// Result shape:
//   { ok: true, file, value }
//   { ok: false, code, file, message, detail }
//
// Codes: NOT_FOUND, IS_DIRECTORY, INVALID_JSON, NOT_OBJECT, READ_ERROR.
// `NOT_OBJECT` covers null, arrays, strings, numbers and booleans. A JSON object
// is the only top-level shape any Verifyd artifact accepts.

'use strict';

const fs = require('fs');
const path = require('path');

function isJsonObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function readJsonObject(file, opts) {
  opts = opts || {};
  const messages = Object.assign({
    notFound: 'artifact not found',
    directory: 'not a file',
    invalidJson: 'artifact is not valid JSON',
    notObject: 'artifact is not a JSON object',
    readError: 'artifact could not be read',
  }, opts.messages || {});

  function failure(code, message, detail) {
    return {
      ok: false,
      code,
      file: file ? path.resolve(file) : null,
      message,
      detail: detail || null,
    };
  }

  if (!file) return failure('NOT_FOUND', messages.notFound);

  const abs = path.resolve(file);
  let stat;
  try {
    stat = fs.statSync(abs);
  } catch (e) {
    if (e.code === 'ENOENT') return failure('NOT_FOUND', messages.notFound, e.code);
    return failure('READ_ERROR', messages.readError + ': ' + (e.code || e.message), e.code || e.message);
  }

  if (stat.isDirectory()) {
    return failure('IS_DIRECTORY', messages.directory + ': ' + abs, 'EISDIR');
  }

  let text;
  try {
    text = fs.readFileSync(abs, 'utf8');
  } catch (e) {
    if (e.code === 'EISDIR') return failure('IS_DIRECTORY', messages.directory + ': ' + abs, e.code);
    if (e.code === 'ENOENT') return failure('NOT_FOUND', messages.notFound, e.code);
    return failure('READ_ERROR', messages.readError + ': ' + (e.code || e.message), e.code || e.message);
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch (e) {
    return failure('INVALID_JSON', messages.invalidJson + ': ' + e.message, e.message);
  }

  if (!isJsonObject(value)) {
    return failure('NOT_OBJECT', messages.notObject, 'top-level JSON value is not an object');
  }

  return { ok: true, file: abs, value };
}

module.exports = {
  isJsonObject,
  readJsonObject,
};

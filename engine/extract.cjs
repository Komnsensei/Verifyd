// Text extraction shared by audit and verification.
//
// A receipt records SHA-256 over the document text, so verification has to
// recover exactly the same text from the artifact. PDFs go through pdftotext
// with -layout in both directions; audit additionally leaves the extracted text
// beside the PDF as a reviewable artifact.

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function readText(file) {
  if (path.extname(file).toLowerCase() === '.pdf') {
    try {
      // Bound the child: a malformed or hostile PDF must not hang the audit or
      // the verifier. A timeout or overflow surfaces as an extraction error,
      // which verification reports as unreadable (and therefore rejected).
      return execFileSync('pdftotext', ['-layout', path.resolve(file), '-'], {
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
        timeout: 120000,
        killSignal: 'SIGKILL',
      });
    } catch (e) {
      const err = new Error('pdftotext failed. Install Poppler or Git for Windows. ' + e.message);
      err.code = 'PDFTOTEXT_FAILED';
      throw err;
    }
  }
  const text = fs.readFileSync(file, 'utf8');
  if (text.includes('\u0000')) {
    const err = new Error('not a text document (binary data); audit a text file or a PDF');
    err.code = 'NOT_TEXT';
    throw err;
  }
  return text;
}

function extractForAudit(file) {
  if (path.extname(file).toLowerCase() !== '.pdf') {
    return { text: readText(file), extracted: file };
  }
  const text = readText(file);
  const txtFile = file.replace(/\.pdf$/i, '.txt');
  fs.writeFileSync(txtFile, text);
  return { text, extracted: txtFile };
}

module.exports = { readText, extractForAudit };

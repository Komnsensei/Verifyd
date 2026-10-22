'use strict';

const fs = require('fs');

// Rotation-aware JSONL tailer.
//
// Cursor = {offset, size_at_read}. If the file shrinks or is replaced, the
// offset resets and the adapter reports a rotation so duplicates are visible in
// the evidence trail rather than silently dropped.
class JsonlTailer {
  constructor(opts) {
    opts = opts || {};
    this.file = opts.file;
    this.maxLines = opts.maxLines || 2000;
    this.maxLineBytes = opts.maxLineBytes || 65536;
    this.cursor = opts.cursor || null;
  }

  poll() {
    const out = { lines: [], cursor: this.cursor, rotated: false, missing: false, bad_lines: 0, truncated_lines: 0 };
    let st;
    try {
      st = fs.statSync(this.file);
    } catch (e) {
      out.missing = true;
      return out;
    }
    let offset = 0;
    if (this.cursor && this.cursor.offset <= st.size && this.cursor.size_at_read <= st.size) {
      offset = this.cursor.offset;
    } else if (this.cursor) {
      out.rotated = true;
    }

    const len = st.size - offset;
    if (len <= 0) {
      out.cursor = { offset, size_at_read: st.size };
      return out;
    }
    const readLen = Math.min(len, this.maxLines * 2048);
    const fd = fs.openSync(this.file, 'r');
    let buf;
    try {
      buf = Buffer.alloc(readLen);
      fs.readSync(fd, buf, 0, readLen, offset);
    } finally {
      fs.closeSync(fd);
    }

    let consumed = 0;
    let lineNo = 0;
    while (consumed < buf.length) {
      const nl = buf.indexOf(10, consumed);
      if (nl === -1) break;
      const raw = buf.slice(consumed, nl).toString('utf8');
      consumed = nl + 1;
      lineNo += 1;
      const absolute = offset + consumed;
      if (!raw.trim()) continue;
      if (raw.length > this.maxLineBytes) {
        out.truncated_lines += 1;
        out.cursor = { offset: absolute, size_at_read: st.size };
        continue;
      }
      let parsed = null;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        out.bad_lines += 1;
      }
      out.lines.push({ raw, parsed, line: lineNo, offset: absolute });
      out.cursor = { offset: absolute, size_at_read: st.size };
      if (out.lines.length >= this.maxLines) break;
    }
    if (!out.cursor) out.cursor = { offset, size_at_read: st.size };
    return out;
  }
}

module.exports = { JsonlTailer };

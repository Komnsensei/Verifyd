// Verifyd Audit Chain - VALF-1 Section 8
// Append-only ledger of audit receipts.

const fs = require('fs');

class AuditChain {
  constructor(filepath) {
    this.filepath = filepath || null;
    this.receipts = [];
    if (filepath && fs.existsSync(filepath)) {
      const lines = fs.readFileSync(filepath, 'utf8').split('\n').filter(Boolean);
      this.receipts = lines.map(l => JSON.parse(l));
    }
  }
  lastHash() {
    return this.receipts.length === 0 ? 'GENESIS' : this.receipts[this.receipts.length - 1].this_hash;
  }
  append(receipt) {
    if (receipt.prev_hash !== this.lastHash()) {
      throw new Error('prev_hash mismatch: receipt expects ' + receipt.prev_hash + ', chain at ' + this.lastHash());
    }
    this.receipts.push(receipt);
    if (this.filepath) fs.appendFileSync(this.filepath, JSON.stringify(receipt) + '\n');
  }
  length() { return this.receipts.length; }
  all() { return this.receipts.slice(); }
}

module.exports = AuditChain;

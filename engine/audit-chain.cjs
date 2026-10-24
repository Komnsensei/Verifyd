// Verifyd Audit Chain - VALF-1 Section 8
// Append-only ledger of audit receipts.
//
// SUPERSEDED by engine/ledger.cjs (CHAIN-DESIGN.md phases A and B). This class
// has no lock, no fsync, no read-back and no recovery, and nothing constructs it
// with a path, so it is not a durable ledger and must not be presented as one.
// It is kept only because four call sites still reference it (bin/verifyd.cjs,
// examples/audit-paper.cjs, examples/run-example.cjs, and the tracked
// artifacts/bundle-stage copy); retiring it belongs with the Phase F CLI work.
// Do not add ledger features here.

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

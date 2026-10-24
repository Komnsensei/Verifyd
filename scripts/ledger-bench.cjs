// Ledger append benchmark.
//
// Regenerates the numbers quoted in CHAIN-DESIGN.md section 17 and revision 2g.
// Every append goes through the public API against a fresh temporary ledger, so
// the lock, the durable writes, the inspection and the state cache are all in
// the measurement. Timings are machine-specific; quote the machine you ran it
// on.
//
//   node scripts/ledger-bench.cjs
//   npm run bench:ledger
//   node scripts/ledger-bench.cjs --sizes 50,100,200
//   node scripts/ledger-bench.cjs --json
//
// The default sizes are 50, 100, 200, 400 and 800, which takes about a minute.
// `inspect` is one full inspection of the finished ledger (the re-read and
// re-hash term); `floor` is the median append minus that inspection (lock, four
// file fsyncs, three directory fsyncs, the new tree, the inclusion path and the
// state rename). All times are milliseconds.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const Ledger = require('../engine/ledger.cjs');
const Store = require('../engine/ledger-store.cjs');
const Signing = require('../engine/signing.cjs');

const DEFAULT_SIZES = [50, 100, 200, 400, 800];

function now() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function median(values) {
  const sorted = values.slice().sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}

function round(value) {
  return Math.round(value * 10) / 10;
}

function parseSizes(text) {
  const sizes = String(text || '').split(',').map(part => Number(part.trim()));
  if (sizes.length === 0) throw new Error('--sizes needs at least one size');
  sizes.forEach((size, index) => {
    if (!Number.isSafeInteger(size) || size < 1) throw new Error('size must be a positive integer: ' + size);
    if (index > 0 && size <= sizes[index - 1]) throw new Error('sizes must be strictly increasing');
  });
  return sizes;
}

function parseArgs(argv) {
  const options = { sizes: DEFAULT_SIZES.slice(), json: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--sizes') {
      options.sizes = parseSizes(argv[i + 1]);
      i += 1;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--help' || arg === '-h') {
      console.log('usage: node scripts/ledger-bench.cjs [--sizes 50,100,200] [--json]');
      process.exit(0);
    } else {
      throw new Error('unknown argument: ' + arg);
    }
  }
  return options;
}

function digestFor(seed, n) {
  return crypto.createHash('sha256').update(seed + ':' + n).digest('hex');
}

function makeLedger() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-ledger-bench-'));
  const keyring = path.join(root, 'keys');
  fs.mkdirSync(keyring);
  const created = Signing.createKey({ dir: keyring });
  const signer = Ledger.keyringSigner({ dir: keyring });
  const ledger = path.join(root, 'ledger.jsonl');
  Ledger.initLedger(ledger, {
    signer,
    policy: { writer_keys: [created.key_id], admin_keys: [created.key_id] },
  });
  return { root, signer, ledger, paths: Ledger.ledgerPaths(ledger) };
}

function measure(size) {
  const env = makeLedger();
  try {
    const appends = [];
    const started = now();
    for (let i = 1; i <= size; i++) {
      const begun = now();
      Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestFor('bench', i) });
      appends.push(now() - begun);
    }
    const total = now() - started;

    const inspections = [];
    for (let i = 0; i < 3; i++) {
      const begun = now();
      Store.inspectLedger(env.paths, fs);
      inspections.push(now() - begun);
    }

    const append = median(appends.slice(-5));
    const inspect = median(inspections);
    return {
      n: size,
      append_ms: round(append),
      total_ms: round(total),
      inspect_ms: round(inspect),
      floor_ms: round(append - inspect),
    };
  } finally {
    fs.rmSync(env.root, { recursive: true, force: true });
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const rows = options.sizes.map(measure);
  if (options.json) {
    console.log(JSON.stringify({
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      rows,
    }, null, 2));
    return;
  }

  console.log('verifyd ledger append benchmark');
  console.log('node ' + process.version + ' on ' + process.platform + ' ' + process.arch);
  console.log('append_ms: median of the last five appends; total_ms: all appends;');
  console.log('inspect_ms: one inspection of the finished ledger; floor_ms: append - inspect.');
  console.log('');
  for (const row of rows) {
    console.log(String(row.n).padStart(6)
      + '  append ' + String(row.append_ms).padStart(7) + ' ms'
      + '  total ' + String(row.total_ms).padStart(9) + ' ms'
      + '  inspect ' + String(row.inspect_ms).padStart(7) + ' ms'
      + '  floor ' + String(row.floor_ms).padStart(6) + ' ms');
  }
}

try {
  main();
} catch (error) {
  console.error('ledger-bench: ' + error.message);
  process.exit(1);
}

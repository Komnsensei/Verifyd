#!/usr/bin/env node
// Verifyd trust-assurance calibration.
// Zero dependencies. Deterministic: fixed seed, fixed row order, fixed iteration
// count. `--write` regenerates the committed corpus and model; the default
// `--check` refits from the committed corpus and fails if either the model
// parameters or the held-out metrics have drifted from the committed artifact.
//
// The labels in the corpus are SYNTHETIC. They are drawn from a documented
// latent rule, not from real audit outcomes. A calibrated score over synthetic
// labels proves the machinery is wired correctly; it does NOT establish that the
// probability matches real-world assurance outcomes. The model artifact and the
// README say this in the same words.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const CORPUS = path.join(ROOT, 'engine', 'calibration', 'corpus.jsonl');
const MODEL = path.join(ROOT, 'engine', 'calibration', 'trust-model.json');

const SCHEME = 'verifyd-trust-assurance-v1';
const MODEL_VERSION = '1.4.0';
const CREATED_AT = '2026-10-23T00:00:00.000Z';
const FEATURES = [
  'signature',
  'time',
  'inclusion',
  'witness_count',
  'witness_tier',
  'policy',
  'ratification',
  'anchors',
  'determination',
  'ledger',
  'missing',
];
const TOTAL_ROWS = 1200;
const TRAIN_ROWS = 840;
const SEED = 20261022;
const TRAINING = {
  method: 'l2-logistic-regression',
  iterations: 4000,
  learning_rate: 0.8,
  l2: 0.001,
  seed: SEED,
};
const LABEL_RULE = [
  'signature, time, inclusion, witness_count, policy, anchors and determination are binary:',
  '1 only when checked and passed, 0 when absent, failed or unverifiable; a failed check never pays.',
  'witness_count is 1 only for a met quorum, and then tier is 0.5 or 1; policy is 1 only when every',
  'result passed and traced to a registered citation; anchors is 1 only when every external anchor has',
  'a verified resolution; ratification is 0 unless witness_count is 1; ledger is 1 only when receipt membership was checked',
  'against a trusted checkpoint (anchored), 0 when not recorded, unanchored or unverifiable.',
  'missing counts the five zero verification dimensions (signature, time, inclusion, witness, determination).',
  'z = -3.20 + 1.80*signature + 0.90*time + 0.70*inclusion + 1.10*witness_count',
  '+ 0.55*witness_tier + 0.70*policy + 0.50*ratification + 0.35*anchors',
  '+ 0.80*determination + 0.60*ledger - 0.90*missing; label ~ Bernoulli(sigmoid(z)) with a seeded PRNG.',
].join(' ');

// ----- deterministic PRNG and maths -----

function mulberry32(seed) {
  let a = seed | 0;
  return function next() {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function sigmoid(z) {
  if (z >= 0) return 1 / (1 + Math.exp(-z));
  const e = Math.exp(z);
  return e / (1 + e);
}

function draw(rng, values, weights) {
  const total = weights.reduce((a, b) => a + b, 0);
  let roll = rng() * total;
  for (let i = 0; i < values.length; i++) {
    roll -= weights[i];
    if (roll <= 0) return values[i];
  }
  return values[values.length - 1];
}

function dot(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) sum += a[i] * b[i];
  return sum;
}

// The corpus is text: hash its lines, not the checkout's line endings. A
// Windows clone with autocrlf would otherwise change the digest of content the
// model was fitted on and report drift that does not exist.
function sha256File(file) {
  const text = fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function round(value, places) {
  const f = Math.pow(10, places);
  return Math.round(value * f) / f;
}

// ----- corpus -----

function generateRows() {
  const rng = mulberry32(SEED);
  const rows = [];
  for (let i = 0; i < TOTAL_ROWS; i++) {
    // Every verification dimension is binary: 0 covers absent, failed and
    // unverifiable alike, mirroring engine/trust-score.cjs exactly.
    const signature = draw(rng, [0, 1], [0.25, 0.75]);
    const time = draw(rng, [0, 1], [0.55, 0.45]);
    const inclusion = draw(rng, [0, 1], [0.60, 0.40]);
    const witnessCount = draw(rng, [0, 1], [0.76, 0.24]);
    const witnessTier = witnessCount === 0 ? 0 : draw(rng, [0.5, 1], [0.70, 0.30]);
    const policy = draw(rng, [0, 1], [0.65, 0.35]);
    const ratification = witnessCount === 1 ? draw(rng, [0, 1], [0.30, 0.70]) : 0;
    const anchors = draw(rng, [0, 1], [0.50, 0.50]);
    const determination = draw(rng, [0, 1], [0.62, 0.38]);
    const ledger = draw(rng, [0, 1], [0.72, 0.28]);
    const missing = ((signature === 0 ? 1 : 0) + (time === 0 ? 1 : 0) +
      (inclusion === 0 ? 1 : 0) + (witnessCount === 0 ? 1 : 0) +
      (determination === 0 ? 1 : 0)) / 5;

    const x = [signature, time, inclusion, witnessCount, witnessTier, policy, ratification, anchors, determination, ledger, missing]
      .map(v => round(v, 2));
    const z = -3.20 +
      1.80 * signature +
      0.90 * time +
      0.70 * inclusion +
      1.10 * witnessCount +
      0.55 * witnessTier +
      0.70 * policy +
      0.50 * ratification +
      0.35 * anchors +
      0.80 * determination +
      0.60 * ledger -
      0.90 * missing;
    const label = rng() < sigmoid(z) ? 1 : 0;

    rows.push({ id: 'r' + String(i).padStart(4, '0'), features: x, label });
  }

  // Deterministic shuffle, then mark the first TRAIN_ROWS as the training split.
  const order = rows.map((_, i) => i);
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = order[i];
    order[i] = order[j];
    order[j] = tmp;
  }
  const shuffled = order.map(i => rows[i]);
  shuffled.forEach((row, i) => {
    row.split = i < TRAIN_ROWS ? 'train' : 'heldout';
  });
  return shuffled;
}

function corpusBytes(rows) {
  return rows.map(row => JSON.stringify({
    id: row.id,
    split: row.split,
    features: row.features,
    label: row.label,
  })).join('\n') + '\n';
}

function readCorpus() {
  const text = fs.readFileSync(CORPUS, 'utf8');
  return text.split('\n').filter(Boolean).map(line => JSON.parse(line));
}

// ----- model -----

function fit(rows, options) {
  const opts = Object.assign({}, TRAINING, options || {});
  const dim = FEATURES.length;
  const weights = new Array(dim).fill(0);
  let intercept = 0;
  const n = rows.length;

  for (let iteration = 0; iteration < opts.iterations; iteration++) {
    const gradW = new Array(dim).fill(0);
    let gradB = 0;
    for (const row of rows) {
      const p = sigmoid(intercept + dot(weights, row.features));
      const error = p - row.label;
      for (let j = 0; j < dim; j++) gradW[j] += error * row.features[j];
      gradB += error;
    }
    for (let j = 0; j < dim; j++) {
      weights[j] -= opts.learning_rate * (gradW[j] / n + opts.l2 * weights[j]);
    }
    intercept -= opts.learning_rate * (gradB / n);
  }

  return { intercept, weights };
}

function predict(parameters, features) {
  return sigmoid(parameters.intercept + dot(parameters.weights, features));
}

function medianAuc(pairs) {
  const positives = pairs.filter(p => p.label === 1);
  const negatives = pairs.filter(p => p.label === 0);
  if (positives.length === 0 || negatives.length === 0) return null;
  let wins = 0;
  for (const pos of positives) {
    for (const neg of negatives) {
      if (pos.p > neg.p) wins += 1;
      else if (pos.p === neg.p) wins += 0.5;
    }
  }
  return wins / (positives.length * negatives.length);
}

function evaluate(rows, parameters) {
  const pairs = rows.map(row => ({ p: predict(parameters, row.features), label: row.label }));
  const n = pairs.length;

  let brier = 0;
  let logLoss = 0;
  const bins = Array.from({ length: 10 }, (_, i) => ({
    lower: i / 10,
    upper: (i + 1) / 10,
    n: 0,
    sum_p: 0,
    sum_y: 0,
  }));

  for (const pair of pairs) {
    const p = Math.min(1 - 1e-12, Math.max(1e-12, pair.p));
    brier += (p - pair.label) * (p - pair.label);
    logLoss -= pair.label === 1 ? Math.log(p) : Math.log(1 - p);
    const index = Math.min(9, Math.floor(p * 10));
    bins[index].n += 1;
    bins[index].sum_p += p;
    bins[index].sum_y += pair.label;
  }

  let ece = 0;
  const reliability = bins.map(bin => {
    const meanPredicted = bin.n ? bin.sum_p / bin.n : 0;
    const observed = bin.n ? bin.sum_y / bin.n : 0;
    if (bin.n) ece += (bin.n / n) * Math.abs(meanPredicted - observed);
    return {
      lower: round(bin.lower, 2),
      upper: round(bin.upper, 2),
      n: bin.n,
      mean_predicted: round(meanPredicted, 6),
      observed_rate: round(observed, 6),
    };
  });

  return {
    brier: round(brier / n, 6),
    log_loss: round(logLoss / n, 6),
    ece: round(ece, 6),
    auc: round(medianAuc(pairs), 6),
    bins: reliability,
  };
}

function buildModel(rows) {
  const train = rows.filter(r => r.split === 'train');
  const heldout = rows.filter(r => r.split === 'heldout');
  if (train.length !== TRAIN_ROWS) throw new Error('corpus has ' + train.length + ' training rows, expected ' + TRAIN_ROWS);
  if (heldout.length !== TOTAL_ROWS - TRAIN_ROWS) throw new Error('corpus has ' + heldout.length + ' held-out rows');

  const parameters = fit(train);
  const metrics = evaluate(heldout, parameters);

  return {
    scheme: SCHEME,
    model_version: MODEL_VERSION,
    created_at: CREATED_AT,
    dataset: {
      path: 'engine/calibration/corpus.jsonl',
      sha256: sha256File(CORPUS),
      rows: rows.length,
      train_rows: train.length,
      heldout_rows: heldout.length,
      labels_origin: 'synthetic',
      label_rule: LABEL_RULE,
    },
    features: FEATURES.slice(),
    parameters: {
      intercept: parameters.intercept,
      weights: parameters.weights,
    },
    training: Object.assign({}, TRAINING),
    metrics,
    baseline: {
      method: 'hand-tuned-0-100',
      calibrated: false,
      note: 'Legacy trust score. It is a heuristic index, not a probability, and is not calibrated against any outcome data.',
    },
    fit_command: 'npm run calibrate',
  };
}

// ----- write and check -----

function writeAll() {
  const rows = generateRows();
  fs.writeFileSync(CORPUS, corpusBytes(rows));
  const model = buildModel(rows);
  fs.writeFileSync(MODEL, JSON.stringify(model, null, 2) + '\n');
  printSummary(model, 'wrote');
}

function printSummary(model, verb) {
  const m = model.metrics;
  console.log(SCHEME + ' ' + model.model_version + ' (' + verb + ')');
  console.log('dataset:    ' + model.dataset.sha256 + ' rows=' + model.dataset.rows +
    ' train=' + model.dataset.train_rows + ' heldout=' + model.dataset.heldout_rows +
    ' labels=' + model.dataset.labels_origin);
  console.log('held-out:   Brier=' + m.brier.toFixed(6) +
    ' ECE=' + m.ece.toFixed(6) +
    ' AUC=' + (m.auc === null ? 'n/a' : m.auc.toFixed(6)) +
    ' LogLoss=' + m.log_loss.toFixed(6));
}

function close(a, b, tolerance) {
  if (typeof a === 'number' && typeof b === 'number') return Math.abs(a - b) <= tolerance;
  return a === b;
}

function check() {
  if (!fs.existsSync(CORPUS) || !fs.existsSync(MODEL)) {
    console.error('calibrate: committed corpus or model is missing');
    process.exit(1);
  }
  const committed = JSON.parse(fs.readFileSync(MODEL, 'utf8'));
  const rows = readCorpus();
  const problems = [];

  const digest = sha256File(CORPUS);
  if (committed.dataset.sha256 !== digest) {
    problems.push('corpus digest ' + digest + ' does not match model dataset sha256 ' + committed.dataset.sha256);
  }
  if (committed.dataset.rows !== rows.length) problems.push('corpus row count differs from model');
  if (committed.training.seed !== SEED) problems.push('model training seed differs from this script');

  const fresh = buildModel(rows);
  if (committed.dataset.label_rule !== fresh.dataset.label_rule) {
    problems.push('documented label rule differs from this script');
  }
  if (JSON.stringify(committed.features) !== JSON.stringify(fresh.features)) {
    problems.push('feature order differs between model and script');
  }
  if (committed.dataset.labels_origin !== 'synthetic') {
    problems.push('model must declare synthetic labels until real outcomes exist');
  }
  const tolerance = 1e-9;
  if (!close(committed.parameters.intercept, fresh.parameters.intercept, tolerance)) {
    problems.push('intercept does not match a fresh fit');
  }
  for (let i = 0; i < FEATURES.length; i++) {
    if (!close(committed.parameters.weights[i], fresh.parameters.weights[i], tolerance)) {
      problems.push('weight ' + FEATURES[i] + ' does not match a fresh fit');
    }
  }
  for (const key of ['brier', 'log_loss', 'ece', 'auc']) {
    if (committed.metrics[key] !== fresh.metrics[key]) {
      problems.push('metric ' + key + ' does not match a fresh evaluation');
    }
  }

  if (problems.length) {
    console.error('calibrate: committed model does not reproduce:');
    for (const problem of problems) console.error('  - ' + problem);
    process.exit(1);
  }

  printSummary(committed, 'checked');
  if (process.argv.includes('--json')) {
    console.log(JSON.stringify({
      scheme: committed.scheme,
      model_version: committed.model_version,
      dataset_sha256: committed.dataset.sha256,
      metrics: committed.metrics,
    }));
  }
}

if (process.argv.includes('--write')) writeAll();
else check();

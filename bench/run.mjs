#!/usr/bin/env node
/**
 * Speed: crypto-js 4.2.0 vs the BUILT cryptolite package, same calls, same fixed inputs; plus the
 * cryptolite modern API. `cryptolite` is imported by package self-reference, so Node resolves it
 * through package.json "exports" to dist/index.js exactly as a consumer would (asserted below).
 *
 *   npm run build && npm run bench                    # build, then this file (5 runs, ~22 min) and size.mjs
 *   node bench/run.mjs --runs 5 --json out.json         # 5 runs per case, raw results to out.json
 *   node bench/run.mjs --filter 'SHA256|Base64'         # only cases whose "table title" matches
 *   node bench/run.mjs --in-process                     # one process for everything (fast, noisier)
 *   node bench/run.mjs --quick                          # smoke test; numbers NOT for publication
 *
 * Method (also in bench/RESULTS.md):
 * - Every case is first checked for identical output across the libraries (parent process).
 * - Each (case, library) is then measured in its own fresh `node --expose-gc` process, so the JIT
 *   state of one case cannot leak into another; this is repeated --runs times (default 5),
 *   interleaved (run 1 of every case, then run 2, ...), so machine drift spreads evenly.
 * - In each process: tinybench, sequential, hrtime clock, forced GC first. Calls cheaper than ~2 ms
 *   are batched: one sample = k back-to-back calls, k chosen from a ~150 ms calibration loop so one
 *   sample takes ~2 ms; ops/s = k * 1000 / mean sample latency.
 * - Within-run margin of error = tinybench's relative margin of error (95% CI, Student's t) of the
 *   mean sample latency. A run whose RME is >= 5% is repeated with 2x the budget, at most twice;
 *   if still >= 5% the table marks it (!).
 * - Reported ops/s = median over runs; "runs ±x%" = half the min-max range over runs, relative to
 *   the median. Speedup = median over runs of (cryptolite ops/s / crypto-js ops/s), pairing run i
 *   with run i, shown with its min-max over runs.
 */
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { Bench } from 'tinybench';
import CryptoJS from 'crypto-js';
import Cryptolite, { decrypt, encrypt, sha256 } from 'cryptolite';
import { argValue, environment, requireBuild, writeJson } from './env.mjs';
import {
  IV_HEX,
  KEY_HEX,
  MiB,
  OPENSSL_SALT_HEX,
  PASSWORD,
  SALT_HEX,
  SHORT,
  bytesToWords,
  fixedBytes,
  fixedText,
} from './inputs.mjs';

const build = requireBuild();
const resolved = import.meta.resolve('cryptolite');
if (!resolved.endsWith('/dist/index.js')) {
  throw new Error(`cryptolite resolved to ${resolved}, expected the built dist/index.js`);
}

const QUICK = process.argv.includes('--quick');
const FILTER = argValue('--filter') ? new RegExp(argValue('--filter'), 'i') : undefined;
const JSON_OUT = argValue('--json');
const IN_PROCESS = process.argv.includes('--in-process');
const RUNS = Number(argValue('--runs') ?? (QUICK ? 1 : 5));
const CHILD = argValue('--child'); // "<case index>:<label>" — internal, used by the parent
const RME_TARGET = 5;
const TARGET_SAMPLE_MS = 2;

// ---------------------------------------------------------------------------------------------
// Fixed inputs (bench/inputs.mjs) and per-library copies of them
// ---------------------------------------------------------------------------------------------
const BYTES_1MIB = fixedBytes(MiB);
const WORDS_1MIB = bytesToWords(BYTES_1MIB);
const TEXT_1MIB = fixedText(MiB);

function prepare(X) {
  return {
    wa1: X.lib.WordArray.create(WORDS_1MIB.slice(), MiB),
    key: X.enc.Hex.parse(KEY_HEX),
    iv: X.enc.Hex.parse(IV_HEX),
    salt: X.enc.Hex.parse(SALT_HEX),
    cbc: { mode: X.mode.CBC, padding: X.pad.Pkcs7 },
    // The same 1 MiB as 16 chunks of 64 KiB, for progressive hashing.
    chunks: Array.from({ length: 16 }, (_, i) => X.lib.WordArray.create(WORDS_1MIB.slice(i * 16384, (i + 1) * 16384), 65536)),
  };
}
const P = { 'crypto-js': prepare(CryptoJS), cryptolite: prepare(Cryptolite) };
// Reference ciphertexts and encodings come from crypto-js; each library parses its own copy.
const CT_1MIB_B64 = CryptoJS.enc.Base64.stringify(
  CryptoJS.AES.encrypt(P['crypto-js'].wa1, P['crypto-js'].key, { iv: P['crypto-js'].iv, ...P['crypto-js'].cbc })
    .ciphertext,
);
const B64_1MIB = CryptoJS.enc.Base64.stringify(P['crypto-js'].wa1);
const CT_PASS = CryptoJS.AES.encrypt(SHORT, PASSWORD, { salt: CryptoJS.enc.Hex.parse(OPENSSL_SALT_HEX) }).toString();
for (const [name, X] of [['crypto-js', CryptoJS], ['cryptolite', Cryptolite]]) {
  P[name].ct1 = X.lib.CipherParams.create({ ciphertext: X.enc.Base64.parse(CT_1MIB_B64) });
  P[name].textWA = X.enc.Utf8.parse(TEXT_1MIB);
}
const TOKEN = await encrypt(SHORT, PASSWORD); // modern cl1 token, 600k iterations

// Hides crypto.subtle so the modern API takes its pure-JS noble path (what React Native runs).
const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
const webCrypto = globalThis.crypto;
function hideSubtle() {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: { getRandomValues: (a) => webCrypto.getRandomValues(a) },
  });
}
function restoreSubtle() {
  Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
}

// ---------------------------------------------------------------------------------------------
// Cases. `fns` maps a column label to a zero-argument function; `out` normalises a result to a
// string so the libraries' outputs can be compared before anything is timed.
// ---------------------------------------------------------------------------------------------
const hex = (r) => r.toString();
const libs = (call) => ({
  'crypto-js': () => call(CryptoJS, P['crypto-js']),
  cryptolite: () => call(Cryptolite, P.cryptolite),
});

const HASHES = ['MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3'];
const cases = [
  ...HASHES.map((h) => ({
    table: 'compat',
    title: `${h} short (43 B string)`,
    call: `CryptoJS.${h}(str).toString()`,
    fns: libs((X) => X[h](SHORT).toString()),
    out: hex,
  })),
  ...HASHES.map((h) => ({
    table: 'compat',
    title: `${h} 1 MiB (WordArray)`,
    call: `CryptoJS.${h}(wordArray).toString()`,
    fns: libs((X, p) => X[h](p.wa1).toString()),
    out: hex,
  })),
  {
    table: 'compat',
    title: 'SHA256 progressive: create() + 16 × 64 KiB update() + finalize()',
    call: 'h = CryptoJS.algo.SHA256.create(); h.update(chunk) x16; h.finalize().toString()',
    fns: libs((X, p) => {
      const h = X.algo.SHA256.create();
      for (const chunk of p.chunks) h.update(chunk);
      return h.finalize().toString();
    }),
    out: hex,
    expect: CryptoJS.SHA256(P['crypto-js'].wa1).toString(), // same digest as the one-shot 1 MiB call
  },
  {
    table: 'compat',
    title: 'HmacSHA256 short',
    call: 'CryptoJS.HmacSHA256(str, key).toString()',
    fns: libs((X) => X.HmacSHA256(SHORT, PASSWORD).toString()),
    out: hex,
  },
  {
    table: 'compat',
    title: 'PBKDF2 SHA256, 10k iterations, keySize 8',
    call: 'CryptoJS.PBKDF2(pw, salt, { keySize: 8, iterations: 10000, hasher: CryptoJS.algo.SHA256 })',
    fns: libs((X, p) => X.PBKDF2(PASSWORD, p.salt, { keySize: 8, iterations: 10000, hasher: X.algo.SHA256 }).toString()),
    out: hex,
  },
  {
    table: 'compat',
    title: 'PBKDF2 crypto-js 4.2 defaults (SHA256, 250k, keySize 4)',
    call: 'CryptoJS.PBKDF2(pw, salt)',
    fns: libs((X, p) => X.PBKDF2(PASSWORD, p.salt).toString()),
    out: hex,
    // Seconds per call in crypto-js: a fixed number of samples, no extra warm-up (the 10k case
    // above has already warmed the same code).
    fixed: { iterations: 3, warmup: false },
  },
  {
    table: 'compat',
    title: 'AES passphrase encrypt + toString (short)',
    call: 'CryptoJS.AES.encrypt(str, passphrase).toString()',
    fns: libs((X) => X.AES.encrypt(SHORT, PASSWORD).toString()),
    // Random salt per call, so compare by decrypting each library's output with the other.
    out: (r, label) => {
      const other = label === 'crypto-js' ? Cryptolite : CryptoJS;
      return other.AES.decrypt(r, PASSWORD).toString(other.enc.Utf8);
    },
    expect: SHORT,
  },
  {
    table: 'compat',
    title: 'AES passphrase decrypt + toString(Utf8) (short)',
    call: 'CryptoJS.AES.decrypt(ciphertext, passphrase).toString(CryptoJS.enc.Utf8)',
    fns: libs((X) => X.AES.decrypt(CT_PASS, PASSWORD).toString(X.enc.Utf8)),
    out: (r) => r,
    expect: SHORT,
  },
  {
    table: 'compat',
    title: 'AES-256-CBC key+iv encrypt 1 MiB',
    call: 'CryptoJS.AES.encrypt(wordArray, key, { iv, mode: CBC, padding: Pkcs7 })',
    fns: libs((X, p) => X.AES.encrypt(p.wa1, p.key, { iv: p.iv, ...p.cbc })),
    out: (r) => r.ciphertext.toString(),
  },
  {
    table: 'compat',
    title: 'AES-256-CBC key+iv decrypt 1 MiB',
    call: 'CryptoJS.AES.decrypt(cipherParams, key, { iv, mode: CBC, padding: Pkcs7 })',
    fns: libs((X, p) => X.AES.decrypt(p.ct1, p.key, { iv: p.iv, ...p.cbc })),
    out: hex,
  },
  {
    table: 'compat',
    title: 'Base64 stringify 1 MiB',
    call: 'CryptoJS.enc.Base64.stringify(wordArray)',
    fns: libs((X, p) => X.enc.Base64.stringify(p.wa1)),
    out: (r) => r,
  },
  {
    table: 'compat',
    title: 'Base64 parse 1 MiB',
    call: 'CryptoJS.enc.Base64.parse(base64)',
    fns: libs((X) => X.enc.Base64.parse(B64_1MIB)),
    out: hex,
  },
  {
    table: 'compat',
    title: 'Utf8 parse 1 MiB',
    call: 'CryptoJS.enc.Utf8.parse(text)',
    fns: libs((X) => X.enc.Utf8.parse(TEXT_1MIB)),
    out: hex,
  },
  {
    table: 'compat',
    title: 'Utf8 stringify 1 MiB',
    call: 'CryptoJS.enc.Utf8.stringify(wordArray)',
    fns: libs((X, p) => X.enc.Utf8.stringify(p.textWA)),
    out: (r) => r,
  },

  // ---- modern API ----
  {
    table: 'modern',
    title: 'encrypt() short, Web Crypto path, 600k iterations',
    call: "encrypt(str, password)",
    fns: { cryptolite: () => encrypt(SHORT, PASSWORD) },
    async: true,
    out: () => 'n/a',
    verify: async (token) => (await decrypt(token, PASSWORD)) === SHORT,
  },
  {
    table: 'modern',
    title: 'decrypt() short, Web Crypto path, 600k iterations',
    call: 'decrypt(token, password)',
    fns: { cryptolite: () => decrypt(TOKEN, PASSWORD) },
    async: true,
    out: (r) => r,
    verify: async (r) => r === SHORT,
  },
  {
    table: 'modern',
    title: 'sha256() short (43 B string)',
    call: "sha256(str)  vs  CryptoJS.SHA256(str).toString()",
    fns: {
      'crypto-js': () => CryptoJS.SHA256(SHORT).toString(),
      cryptolite: () => sha256(SHORT),
    },
    out: (r) => r,
  },
  {
    table: 'modern',
    title: 'sha256() 1 MiB (Uint8Array; crypto-js: WordArray)',
    call: 'sha256(bytes)  vs  CryptoJS.SHA256(wordArray).toString()',
    fns: {
      'crypto-js': () => CryptoJS.SHA256(P['crypto-js'].wa1).toString(),
      cryptolite: () => sha256(BYTES_1MIB),
    },
    out: (r) => r,
  },

  // ---- supplementary measurements (not in the task list; labelled as such in RESULTS.md) ----
  {
    table: 'supplementary',
    title: 'encrypt() short, noble path (crypto.subtle hidden), 600k',
    call: 'encrypt(str, password) with globalThis.crypto.subtle removed',
    fns: { cryptolite: () => encrypt(SHORT, PASSWORD) },
    async: true,
    hooks: { beforeAll: hideSubtle, afterAll: restoreSubtle },
    fixed: { iterations: 5, warmupIterations: 1 },
    out: () => 'n/a',
    verify: async (token) => (await decrypt(token, PASSWORD)) === SHORT,
  },
  {
    table: 'supplementary',
    title: 'decrypt() short, noble path (crypto.subtle hidden), 600k',
    call: 'decrypt(token, password) with globalThis.crypto.subtle removed',
    fns: { cryptolite: () => decrypt(TOKEN, PASSWORD) },
    async: true,
    hooks: { beforeAll: hideSubtle, afterAll: restoreSubtle },
    fixed: { iterations: 5, warmupIterations: 1 },
    out: (r) => r,
    verify: async (r) => r === SHORT,
  },
  {
    table: 'supplementary',
    title: 'compat PBKDF2 SHA256, 600k, keySize 8 (sync noble)',
    call: 'CryptoJS.PBKDF2(pw, salt, { keySize: 8, iterations: 600000, hasher: CryptoJS.algo.SHA256 })',
    fns: {
      cryptolite: () =>
        Cryptolite.PBKDF2(PASSWORD, P.cryptolite.salt, { keySize: 8, iterations: 600000, hasher: Cryptolite.algo.SHA256 }),
    },
    fixed: { iterations: 5, warmupIterations: 1 },
    out: hex,
  },
  {
    table: 'supplementary',
    title: 'SHA256 of the 1 MiB UTF-8 text as a string',
    call: 'CryptoJS.SHA256(text).toString()  /  modern sha256(text)',
    fns: {
      'crypto-js': () => CryptoJS.SHA256(TEXT_1MIB).toString(),
      cryptolite: () => Cryptolite.SHA256(TEXT_1MIB).toString(),
      'cryptolite modern': () => sha256(TEXT_1MIB),
    },
    out: (r) => r,
  },
];

// ---------------------------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------------------------
let sink; // every result is stored here so no call can be optimised away
const gc = typeof globalThis.gc === 'function' ? globalThis.gc : () => {};

async function check(c) {
  const outs = {};
  for (const [label, fn] of Object.entries(c.fns)) {
    c.hooks?.beforeAll();
    try {
      const r = c.async ? await fn() : fn();
      if (c.verify && !(await c.verify(r))) throw new Error(`${c.title}: ${label} failed verification`);
      outs[label] = c.out(r, label);
    } finally {
      c.hooks?.afterAll();
    }
  }
  const values = Object.values(outs);
  if (values.some((v) => v !== values[0])) {
    throw new Error(`${c.title}: outputs differ between ${Object.keys(outs).join(' / ')}`);
  }
  if (c.expect !== undefined && values[0] !== c.expect) throw new Error(`${c.title}: unexpected output`);
}

/** ms per call from a short loop; also warms the JIT before tinybench's own warm-up. */
function estimate(fn) {
  let calls = 0;
  const start = performance.now();
  do {
    sink = fn();
    calls++;
  } while (performance.now() - start < 150);
  return (performance.now() - start) / calls;
}

function budgetFor(msPerCall) {
  if (msPerCall < 50) return { time: 2000, iterations: 30, warmupTime: 250, warmupIterations: 10 };
  if (msPerCall < 400) return { time: 3000, iterations: 15, warmupTime: 0, warmupIterations: 2 };
  return { time: 0, iterations: 8, warmupTime: 0, warmupIterations: 1 };
}

async function measure(c, label, fn) {
  let batch = 1;
  let budget;
  if (c.fixed) {
    budget = { time: 0, warmupTime: 0, warmupIterations: 0, ...c.fixed };
  } else if (c.async) {
    budget = { time: 4000, iterations: 30, warmupTime: 0, warmupIterations: 3 };
  } else {
    const ms = estimate(fn);
    batch = Math.max(1, Math.round(TARGET_SAMPLE_MS / ms));
    budget = budgetFor(ms);
  }
  if (QUICK) {
    budget = {
      ...budget,
      time: budget.time / 10,
      iterations: Math.min(budget.iterations, 3),
      warmupTime: budget.warmupTime / 10,
    };
  }
  const task = c.async
    ? async () => {
        sink = await fn();
      }
    : batch === 1
      ? () => {
          sink = fn();
        }
      : () => {
          for (let i = 0; i < batch; i++) sink = fn();
        };

  let attempt = 0;
  for (;;) {
    gc();
    const bench = new Bench({
      timestampProvider: 'hrtimeNow',
      throws: true,
      warmup: budget.warmup !== false && (budget.warmupIterations > 0 || budget.warmupTime > 0),
      time: budget.time,
      iterations: budget.iterations,
      warmupTime: budget.warmupTime,
      warmupIterations: budget.warmupIterations,
    });
    bench.add(`${c.title} [${label}]`, task, { async: Boolean(c.async), ...(c.hooks ?? {}) });
    await bench.run();
    const { latency } = bench.tasks[0].result;
    const result = {
      label,
      batch,
      samples: latency.samplesCount,
      msPerOp: latency.mean / batch,
      opsPerSec: (batch * 1000) / latency.mean,
      rme: latency.samplesCount > 1 ? latency.rme : null,
      attempts: attempt + 1,
    };
    const retryable = !c.fixed && !QUICK && result.rme !== null && result.rme >= RME_TARGET && attempt < 2;
    if (!retryable) return result;
    attempt++;
    budget = { ...budget, time: budget.time * 2, iterations: budget.iterations * 2 };
  }
}

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------
const sig3 = (x) =>
  x >= 100 ? Math.round(x).toLocaleString('en-US') : x.toLocaleString('en-US', { maximumSignificantDigits: 3 });
const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};
function opsCell(r) {
  if (!r) return '–';
  const within = r.rme === null ? `n=${r.samples}` : `±${r.rme.toFixed(1)}%${r.rme >= RME_TARGET ? ' (!)' : ''}`;
  const runs = r.runs && r.runs.length > 1 ? `, runs ±${r.spread.toFixed(0)}%` : '';
  return `${sig3(r.opsPerSec)} (${within}${runs})`;
}
function timeCell(r) {
  if (!r) return '–';
  const ms = r.msPerOp;
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  if (ms >= 1) return `${ms.toPrecision(3)} ms`;
  return `${(ms * 1000).toPrecision(3)} µs`;
}
function speedup(base, cand) {
  if (!base || !cand) return '–';
  if (base.runs && base.runs.length > 1) {
    const ratios = cand.runs.map((r, i) => r.opsPerSec / base.runs[i].opsPerSec);
    return `${median(ratios).toPrecision(3)}× (${Math.min(...ratios).toPrecision(3)}–${Math.max(...ratios).toPrecision(3)})`;
  }
  const x = cand.opsPerSec / base.opsPerSec;
  if (base.rme === null || cand.rme === null) return `${x.toPrecision(3)}×`;
  return `${x.toPrecision(3)}× (±${(x * Math.hypot(base.rme / 100, cand.rme / 100)).toPrecision(2)})`;
}

function table(rows, columns) {
  const lines = [
    `| Case | ${columns.map((c) => `${c} ops/s`).join(' | ')} | ${columns.map((c) => `${c} time/op`).join(' | ')} | Speedup vs crypto-js |`,
    `|---|${columns.map(() => '--:').join('|')}|${columns.map(() => '--:').join('|')}|--:|`,
  ];
  for (const row of rows) {
    const base = row.results['crypto-js'];
    const sp = columns
      .filter((col) => col !== 'crypto-js' && row.results[col] && base)
      .map((col) => (columns.length > 2 ? `${col}: ` : '') + speedup(base, row.results[col]));
    lines.push(
      `| ${row.title} | ${columns.map((col) => opsCell(row.results[col])).join(' | ')} | ${columns.map((col) => timeCell(row.results[col])).join(' | ')} | ${sp.join('; ') || '–'} |`,
    );
  }
  return lines.join('\n');
}

/** Median over runs; keeps every run for the JSON. */
function aggregate(runs) {
  const med = median(runs.map((r) => r.opsPerSec));
  const mid = runs.reduce((a, b) => (Math.abs(b.opsPerSec - med) < Math.abs(a.opsPerSec - med) ? b : a));
  const ops = runs.map((r) => r.opsPerSec);
  return {
    label: mid.label,
    opsPerSec: med,
    msPerOp: 1000 / med,
    rme: mid.rme, // within-run RME of the run closest to the median
    samples: mid.samples,
    batch: mid.batch,
    spread: ((Math.max(...ops) - Math.min(...ops)) / 2 / med) * 100,
    runs,
  };
}

// ---------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------
const selected = cases.filter((c) => !FILTER || FILTER.test(`${c.table} ${c.title}`)).filter((c) => !(QUICK && c.fixed));

if (CHILD) {
  // Child: measure one library on one case, print one JSON line.
  const [index, label] = [Number(CHILD.slice(0, CHILD.indexOf(':'))), CHILD.slice(CHILD.indexOf(':') + 1)];
  const c = cases[index];
  const result = await measure(c, label, c.fns[label]);
  process.stdout.write(`${JSON.stringify({ ...result, distSha256: build.sha256, sinkType: typeof sink })}\n`);
  process.exit(0);
}

const env = {
  ...environment(),
  build,
  cryptoliteResolvedTo: resolved,
  gcExposed: typeof globalThis.gc === 'function',
  mode: IN_PROCESS ? 'in-process' : `isolated, ${RUNS} run(s) per case`,
};
process.stderr.write(`${JSON.stringify(env)}\n`);
if (QUICK) process.stderr.write('QUICK MODE: budgets cut 10x, results are NOT for publication.\n');

for (const c of selected) await check(c);
process.stderr.write(`outputs identical across libraries for all ${selected.length} cases\n`);

const results = new Map(selected.map((c) => [c, Object.fromEntries(Object.keys(c.fns).map((l) => [l, []]))]));
const self = fileURLToPath(import.meta.url);
for (let run = 1; run <= (IN_PROCESS ? 1 : RUNS); run++) {
  for (const c of selected) {
    for (const [label, fn] of Object.entries(c.fns)) {
      let r;
      if (IN_PROCESS) {
        r = await measure(c, label, fn);
      } else {
        const args = ['--expose-gc', self, '--child', `${cases.indexOf(c)}:${label}`, ...(QUICK ? ['--quick'] : [])];
        const child = spawnSync(process.execPath, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 1 << 20 });
        if (child.status !== 0) throw new Error(`${c.title} [${label}] run ${run}: child exited with ${child.status}`);
        r = JSON.parse(child.stdout.trim().split('\n').pop());
        if (r.distSha256 !== build.sha256) throw new Error('dist/index.js changed during the benchmark; rebuild and rerun');
      }
      r.run = run;
      r.loadavg1m = os.loadavg()[0];
      results.get(c)[label].push(r);
      process.stderr.write(`run ${run}/${IN_PROCESS ? 1 : RUNS} ${c.title} [${label}]: ${opsCell(r)}, ${timeCell(r)}/op, n=${r.samples}x${r.batch}\n`);
    }
  }
}
const rows = selected.map((c) => ({
  table: c.table,
  title: c.title,
  call: c.call,
  results: Object.fromEntries(Object.entries(results.get(c)).map(([l, runs]) => [l, aggregate(runs)])),
}));
env.loadavg1mEnd = os.loadavg()[0];
env.finished = new Date().toISOString();

const sections = [
  ['compat', 'Compat API (same call on both libraries)', ['crypto-js', 'cryptolite']],
  ['modern', 'Modern API', ['crypto-js', 'cryptolite']],
  ['supplementary', 'Supplementary', ['crypto-js', 'cryptolite', 'cryptolite modern']],
];
for (const [key, heading, columns] of sections) {
  const sectionRows = rows.filter((r) => r.table === key);
  if (sectionRows.length === 0) continue;
  const used = columns.filter((col) => sectionRows.some((r) => r.results[col]));
  process.stdout.write(`\n### ${heading}\n\n${table(sectionRows, used)}\n`);
}
process.stdout.write(
  `\n(${env.mode}; dist/index.js sha256 ${build.sha256.slice(0, 12)}; load average 1m: ${env.loadavg1m.toFixed(2)} at start, ${env.loadavg1mEnd.toFixed(2)} at end)\n`,
);
if (JSON_OUT) writeJson(JSON_OUT, { env, quick: QUICK, rows });

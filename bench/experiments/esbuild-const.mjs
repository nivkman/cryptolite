#!/usr/bin/env node
// esbuild rewrites top-level `const` as `var` when bundling (all targets). For noble's hot loops,
// which read module-level tables (SHA256_W, SHA256_K, AES T-tables, ...), V8 can no longer treat
// them as constants. Diagnosis for bench/RESULTS.md "Opportunities": a temp copy of dist/index.js
// in which every top-level `var X =` that noble's own sources declare as `const X =` (and that is
// never assigned again in the bundle) is turned back into `const`. Outputs of both copies are
// compared, then key operations are timed in fresh processes (median of 15 windows of 200 ms,
// after 300 ms warm-up; 3 processes per variant). Nothing in dist/ or src/ is modified.
//
//   npm run build && node bench/experiments/esbuild-const.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { IV_HEX, KEY_HEX, MiB, PASSWORD, SALT_HEX, SHORT, bytesToWords, fixedBytes } from '../inputs.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const CASES = {
  'SHA256 1 MiB (compat)': (L, x) => L.SHA256(x.wa).toString(),
  'sha256() 1 MiB (modern)': (L, x) => L.sha256(x.bytes),
  'SHA512 1 MiB (compat)': (L, x) => L.SHA512(x.wa).toString(),
  'SHA3 1 MiB (compat)': (L, x) => L.SHA3(x.wa).toString(),
  'AES-256-CBC encrypt 1 MiB (compat)': (L, x) => L.AES.encrypt(x.wa, x.key, { iv: x.iv }).ciphertext,
  'PBKDF2 SHA256 10k keySize 8 (compat)': (L, x) =>
    L.PBKDF2(PASSWORD, x.salt, { keySize: 8, iterations: 10000, hasher: L.algo.SHA256 }).toString(),
  'SHA256 short (compat)': (L) => L.SHA256(SHORT).toString(),
};

async function load(file) {
  const L = (await import(pathToFileURL(file).href)).default;
  const bytes = fixedBytes(MiB);
  return {
    L,
    x: {
      bytes,
      wa: L.lib.WordArray.create(bytesToWords(bytes), MiB),
      key: L.enc.Hex.parse(KEY_HEX),
      iv: L.enc.Hex.parse(IV_HEX),
      salt: L.enc.Hex.parse(SALT_HEX),
    },
  };
}

if (process.argv[2] === '--child') {
  const { L, x } = await load(process.argv[3]);
  const fn = () => CASES[process.argv[4]](L, x);
  let sink;
  const w = performance.now();
  while (performance.now() - w < 300) sink = fn();
  const rates = [];
  for (let k = 0; k < 15; k++) {
    let n = 0;
    const s = performance.now();
    do {
      sink = fn();
      n++;
    } while (performance.now() - s < 200);
    rates.push((n / (performance.now() - s)) * 1000);
  }
  rates.sort((a, b) => a - b);
  process.stdout.write(`${rates[7]}${typeof sink === 'undefined' ? '?' : ''}\n`);
  process.exit(0);
}

// Top-level `const` names in noble's sources.
const nobleConsts = new Set();
for (const pkg of ['@noble/hashes', '@noble/ciphers']) {
  const dir = path.join(ROOT, 'node_modules', pkg);
  for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.js'))) {
    for (const m of fs.readFileSync(path.join(dir, f), 'utf8').matchAll(/^(?:export )?const ([A-Za-z_$][\w$]*)\s*=/gm)) {
      nobleConsts.add(m[1]);
    }
  }
}
const dist = fs.readFileSync(path.join(ROOT, 'dist', 'index.js'), 'utf8');
const restored = [];
const patched = dist.replace(/^var ([A-Za-z_$][\w$]*) = /gm, (all, name) => {
  if (!nobleConsts.has(name)) return all;
  const declarations = dist.match(new RegExp(`^var ${name.replace(/\$/g, '\\$')} = `, 'gm')).length;
  const assignments = dist.match(new RegExp(`(^|[^.\\w$])${name.replace(/\$/g, '\\$')}\\s*(=[^=>]|\\+=|-=|\\|=|&=|\\^=)`, 'gm')).length;
  if (declarations !== 1 || assignments !== 1) return all; // only the declaration itself
  restored.push(name);
  return `const ${name} = `;
});

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptolite-const-'));
process.on('exit', () => fs.rmSync(TMP, { recursive: true, force: true }));
fs.writeFileSync(path.join(TMP, 'package.json'), '{ "type": "module" }\n');
const patchedFile = path.join(TMP, 'index.js');
fs.writeFileSync(patchedFile, patched);
const variants = { 'dist/index.js (as shipped)': path.join(ROOT, 'dist', 'index.js'), 'dist with noble consts restored': patchedFile };

// Same outputs?
const a = await load(variants['dist/index.js (as shipped)']);
const b = await load(patchedFile);
const text = (v) => (typeof v === 'string' ? v : v.toString());
for (const [name, fn] of Object.entries(CASES)) {
  if (text(fn(a.L, a.x)) !== text(fn(b.L, b.x))) throw new Error(`${name}: patched bundle gives a different result`);
}
console.log(`restored ${restored.length} declarations to const: ${restored.join(', ')}`);
console.log(`outputs identical for all ${Object.keys(CASES).length} cases; load average 1m: ${os.loadavg()[0].toFixed(2)}`);
console.log('ops/s, median of 15 windows; 3 fresh processes per variant');

const self = fileURLToPath(import.meta.url);
for (const name of Object.keys(CASES)) {
  const medians = {};
  for (const [label, file] of Object.entries(variants)) {
    const runs = [1, 2, 3].map(() => {
      const r = spawnSync(process.execPath, [self, '--child', file, name], { encoding: 'utf8' });
      if (r.status !== 0) throw new Error(r.stderr);
      return Number(r.stdout.trim());
    });
    medians[label] = runs.sort((x, y) => x - y)[1];
    const fmt = (v) => (v >= 100 ? Math.round(v).toLocaleString('en-US') : v.toPrecision(3));
    console.log(`${name} | ${label} | ${runs.map(fmt).join(' | ')}`);
  }
  const [shipped, fixed] = Object.values(medians);
  console.log(`${name} | gain (median of 3) | ${(fixed / shipped).toFixed(2)}×`);
}

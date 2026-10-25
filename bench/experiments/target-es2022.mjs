#!/usr/bin/env node
// Cost of lowering class fields (tsup target es2020) — evidence for bench/RESULTS.md
// "Opportunities". Rebuilds src/index.ts the way tsup.config.ts does (esbuild, ESM, platform
// neutral, @noble bundled, every src/ module side-effectful) at target es2020 (control) and
// es2022, into os.tmpdir(), then times short calls against dist/ and both rebuilds. Each
// measurement is its own fresh process: 300 ms warm-up, then the median of 15 windows of 200 ms.
//
//   npm run build && node bench/experiments/target-es2022.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as esbuild from 'esbuild';
import { PASSWORD, SHORT } from '../inputs.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SRC = path.join(ROOT, 'src') + path.sep;

if (process.argv[2] === '--child') {
  const lib = (await import(process.argv[3])).default;
  const ct = lib.AES.encrypt(SHORT, PASSWORD).toString();
  const fns = {
    'CryptoJS.SHA256(str).toString()': () => lib.SHA256(SHORT).toString(),
    'sha256(str)': () => lib.sha256(SHORT),
    'CryptoJS.HmacSHA256(str, key).toString()': () => lib.HmacSHA256(SHORT, PASSWORD).toString(),
    'CryptoJS.AES.decrypt(ct, pass).toString(Utf8)': () => lib.AES.decrypt(ct, PASSWORD).toString(lib.enc.Utf8),
  };
  const fn = fns[process.argv[4]];
  let sink;
  const w = performance.now();
  while (performance.now() - w < 300) sink = fn();
  const rates = [];
  for (let k = 0; k < 15; k++) {
    let n = 0;
    const s = performance.now();
    while (performance.now() - s < 200) {
      sink = fn();
      n++;
    }
    rates.push((n / (performance.now() - s)) * 1000);
  }
  rates.sort((a, b) => a - b);
  process.stdout.write(`${Math.round(rates[7])}${typeof sink === 'undefined' ? '?' : ''}\n`);
  process.exit(0);
}

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptolite-target-'));
process.on('exit', () => fs.rmSync(TMP, { recursive: true, force: true }));
fs.writeFileSync(path.join(TMP, 'package.json'), '{ "type": "module" }\n');

const srcHasSideEffects = {
  name: 'se',
  setup(b) {
    b.onResolve({ filter: /^\./ }, async (a) => {
      if (a.pluginData === 'se') return undefined;
      const r = await b.resolve(a.path, { kind: a.kind, importer: a.importer, resolveDir: a.resolveDir, pluginData: 'se' });
      if (r.errors.length || !r.path.startsWith(SRC)) return undefined;
      return { path: r.path, sideEffects: true };
    });
  },
};
const variants = { 'dist/index.js': path.join(ROOT, 'dist', 'index.js') };
for (const target of ['es2020', 'es2022']) {
  const outfile = path.join(TMP, target, 'index.js');
  await esbuild.build({
    entryPoints: [path.join(SRC, 'index.ts')],
    outfile,
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    mainFields: ['module', 'main'],
    target,
    plugins: [srcHasSideEffects],
    logLevel: 'error',
  });
  const n = (fs.readFileSync(outfile, 'utf8').match(/__publicField\(/g) || []).length;
  variants[`rebuild ${target} (${n} __publicField calls)`] = outfile;
}

const self = fileURLToPath(import.meta.url);
console.log(`load average 1m: ${os.loadavg()[0].toFixed(2)}; ops/s, median of 15 windows, 3 fresh processes each`);
for (const name of ['CryptoJS.SHA256(str).toString()', 'sha256(str)', 'CryptoJS.HmacSHA256(str, key).toString()', 'CryptoJS.AES.decrypt(ct, pass).toString(Utf8)']) {
  for (const [label, file] of Object.entries(variants)) {
    const runs = [1, 2, 3].map(() => {
      const r = spawnSync(process.execPath, [self, '--child', pathToFileURL(file).href, name], { encoding: 'utf8' });
      if (r.status !== 0) throw new Error(r.stderr);
      return Number(r.stdout.trim()).toLocaleString('en-US');
    });
    console.log(`${name} | ${label} | ${runs.join(' | ')}`);
  }
}

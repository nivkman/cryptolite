#!/usr/bin/env node
// Where does the time go? Runs one case in a loop for 3 s under `node --cpu-prof` (in a child
// process, profile written to os.tmpdir()) and prints self time per function. dist/index.js is not
// minified, so names and line numbers point into it. Also times noble directly, as a ceiling.
// Evidence for bench/RESULTS.md "Opportunities"; profiler overhead inflates absolute times.
//
//   npm run build && node bench/experiments/profile.mjs [case ...]     # default: all cases
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { cbc } from '@noble/ciphers/aes.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import CL from 'cryptolite';
import { IV_HEX, KEY_HEX, MiB, SHORT, bytesToWords, fixedBytes } from '../inputs.mjs';

const bytes = fixedBytes(MiB);
const words = bytesToWords(bytes);
const wa = CL.lib.WordArray.create(words.slice(), MiB);
const chunks = Array.from({ length: 16 }, (_, i) => CL.lib.WordArray.create(words.slice(i * 16384, (i + 1) * 16384), 65536));
const key = CL.enc.Hex.parse(KEY_HEX);
const iv = CL.enc.Hex.parse(IV_HEX);
const cfg = { iv, mode: CL.mode.CBC, padding: CL.pad.Pkcs7 };
const ct = CL.lib.CipherParams.create({ ciphertext: CL.AES.encrypt(wa, key, cfg).ciphertext });
const b64 = CL.enc.Base64.stringify(wa);
const keyBytes = fixedBytes(32, 1);
const ivBytes = fixedBytes(16, 2);

const cases = {
  'sha256-progressive': () => {
    const h = CL.algo.SHA256.create();
    for (const c of chunks) h.update(c);
    return h.finalize().toString();
  },
  'sha256-short': () => CL.SHA256(SHORT).toString(),
  'aes-cbc-encrypt-1mib': () => CL.AES.encrypt(wa, key, cfg),
  'aes-cbc-decrypt-1mib': () => CL.AES.decrypt(ct, key, cfg),
  'base64-stringify-1mib': () => CL.enc.Base64.stringify(wa),
  'base64-parse-1mib': () => CL.enc.Base64.parse(b64),
  'noble-sha256-1mib (ceiling)': () => nobleSha256(bytes),
  'noble-cbc-encrypt-1mib (ceiling)': () => cbc(keyBytes, ivBytes).encrypt(bytes),
};

if (process.argv[2] === '--child') {
  const fn = cases[process.argv[3]];
  let sink;
  let n = 0;
  const end = performance.now() + 3000;
  while (performance.now() < end) {
    sink = fn();
    n++;
  }
  process.stdout.write(`${((3000 / n) * 1).toPrecision(3)} ms/call over ${n} calls${typeof sink === 'undefined' ? '?' : ''}\n`);
  process.exit(0);
}

function summarize(file, top = 8) {
  const prof = JSON.parse(fs.readFileSync(file, 'utf8'));
  const byId = new Map(prof.nodes.map((n) => [n.id, n]));
  const self = new Map();
  for (let i = 0; i < prof.samples.length; i++) {
    const cf = byId.get(prof.samples[i]).callFrame;
    const k = `${cf.functionName || '(anonymous)'} ${cf.url.split('/').slice(-2).join('/')}:${cf.lineNumber + 1}`;
    self.set(k, (self.get(k) ?? 0) + (prof.timeDeltas[i] ?? 0));
  }
  const total = [...self.values()].reduce((a, b) => a + b, 0);
  return [...self.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, top)
    .map(([k, v]) => `  ${((100 * v) / total).toFixed(1).padStart(5)}%  ${k}`)
    .join('\n');
}

const selected = process.argv.length > 2 ? process.argv.slice(2) : Object.keys(cases);
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptolite-prof-'));
process.on('exit', () => fs.rmSync(TMP, { recursive: true, force: true }));
for (const name of selected) {
  const dir = path.join(TMP, String(selected.indexOf(name)));
  const r = spawnSync(process.execPath, ['--cpu-prof', `--cpu-prof-dir=${dir}`, fileURLToPath(import.meta.url), '--child', name], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
  console.log(`== ${name}: ${r.stdout.trim()} (under the profiler)`);
  console.log(summarize(path.join(dir, fs.readdirSync(dir)[0])));
}

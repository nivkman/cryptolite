#!/usr/bin/env node
// Estimates behind bench/RESULTS.md "Opportunities" (NOT product code). The current algorithm is
// copied from src/compat/enc.ts; each candidate runs on the same fixed input and its output is
// asserted identical before timing. Without an argument, runs every case 3 times, each in a fresh
// process, and prints the median of 31 timed calls (after 15 warm-up calls) per process.
//
//   npm run build && node bench/experiments/encoders.mjs
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import CL from 'cryptolite';
import { MiB, bytesToWords, fixedBytes } from '../inputs.mjs';

const MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const bytes = fixedBytes(MiB);
const words = bytesToWords(bytes);

// --- stringify: current (src/compat/enc.ts stringifyWithMap after toBytes) ---
function stringifyCurrent(b, map) {
  const n = b.length;
  const chars = [];
  for (let k = 0; k < 64; k++) chars.push(map.charAt(k));
  let out = '';
  let i = 0;
  for (; i + 2 < n; i += 3) {
    const t = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    out += chars[(t >>> 18) & 0x3f] + chars[(t >>> 12) & 0x3f] + chars[(t >>> 6) & 0x3f] + chars[t & 0x3f];
  }
  let nChars = (i / 3) * 4;
  if (n - i === 1) { const t = b[i] << 16; out += chars[(t >>> 18) & 0x3f] + chars[(t >>> 12) & 0x3f]; nChars += 2; }
  else if (n - i === 2) { const t = (b[i] << 16) | (b[i + 1] << 8); out += chars[(t >>> 18) & 0x3f] + chars[(t >>> 12) & 0x3f] + chars[(t >>> 6) & 0x3f]; nChars += 3; }
  const pad = map.charAt(64);
  if (pad) while (nChars % 4) { out += pad; nChars++; }
  return out;
}
// --- stringify: candidate — char codes into a Uint16Array, converted in 32K-code chunks ---
function stringifyChunked(b, map) {
  const n = b.length;
  const codes = new Uint16Array(64);
  for (let k = 0; k < 64; k++) codes[k] = map.charCodeAt(k);
  const padCode = map.length > 64 ? map.charCodeAt(64) : -1;
  const full = Math.floor(n / 3);
  const rem = n - full * 3;
  const outLen = full * 4 + (rem ? (padCode >= 0 ? 4 : rem + 1) : 0);
  const out = new Uint16Array(outLen);
  let o = 0;
  let i = 0;
  for (; i + 2 < n; i += 3) {
    const t = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    out[o++] = codes[(t >>> 18) & 0x3f]; out[o++] = codes[(t >>> 12) & 0x3f]; out[o++] = codes[(t >>> 6) & 0x3f]; out[o++] = codes[t & 0x3f];
  }
  if (rem === 1) { const t = b[i] << 16; out[o++] = codes[(t >>> 18) & 0x3f]; out[o++] = codes[(t >>> 12) & 0x3f]; if (padCode >= 0) { out[o++] = padCode; out[o++] = padCode; } }
  else if (rem === 2) { const t = (b[i] << 16) | (b[i + 1] << 8); out[o++] = codes[(t >>> 18) & 0x3f]; out[o++] = codes[(t >>> 12) & 0x3f]; out[o++] = codes[(t >>> 6) & 0x3f]; if (padCode >= 0) out[o++] = padCode; }
  const parts = [];
  for (let k = 0; k < o; k += 0x8000) parts.push(String.fromCharCode.apply(null, out.subarray(k, Math.min(o, k + 0x8000))));
  return parts.join('');
}

// --- parse: current (src/compat/enc.ts parseLoop, padding already cut) ---
const rev = [];
for (let j = 0; j < MAP.length; j++) rev[MAP.charCodeAt(j)] = j;
function parseCurrent(s) {
  let len = s.length;
  const p = s.indexOf('=');
  if (p !== -1) len = p;
  const w = [];
  let nBytes = 0;
  for (let i = 0; i < len; i++) {
    if (i % 4) {
      const b1 = rev[s.charCodeAt(i - 1)] << ((i % 4) * 2);
      const b2 = rev[s.charCodeAt(i)] >>> (6 - (i % 4) * 2);
      w[nBytes >>> 2] |= (b1 | b2) << (24 - (nBytes % 4) * 8);
      nBytes++;
    }
  }
  return { words: w, sigBytes: nBytes };
}
// --- parse: candidate — validated input only: 4 chars -> 3 bytes into a Uint8Array, then words ---
const rev8 = new Int16Array(65536).fill(-1);
for (let j = 0; j < 64; j++) rev8[MAP.charCodeAt(j)] = j;
function parseFast(s) {
  let len = s.length;
  const p = s.indexOf('=');
  if (p !== -1) len = p;
  const nBytes = Math.floor((len * 3) / 4);
  const out = new Uint8Array(nBytes + 3);
  let o = 0;
  let i = 0;
  for (; i + 3 < len; i += 4) {
    const v = (rev8[s.charCodeAt(i)] << 18) | (rev8[s.charCodeAt(i + 1)] << 12) | (rev8[s.charCodeAt(i + 2)] << 6) | rev8[s.charCodeAt(i + 3)];
    if (v < 0) return undefined; // a char outside the alphabet: the real code would fall back to the verbatim loop
    out[o++] = v >>> 16; out[o++] = (v >>> 8) & 0xff; out[o++] = v & 0xff;
  }
  let v = 0;
  for (let k = 0; i < len; i++, k++) v |= rev8[s.charCodeAt(i)] << (18 - 6 * k);
  if (len % 4) { out[o++] = v >>> 16; if (len % 4 === 3) out[o++] = (v >>> 8) & 0xff; }
  const w = new Array((nBytes + 3) >>> 2);
  for (let k = 0, j = 0; k < w.length; k++, j += 4) w[k] = (out[j] << 24) | (out[j + 1] << 16) | (out[j + 2] << 8) | out[j + 3];
  return { words: w, sigBytes: nBytes };
}

// --- progressive SHA256: candidate — noble streaming update() per clean chunk ---
const chunkWords = Array.from({ length: 16 }, (_, i) => words.slice(i * 16384, (i + 1) * 16384));
function wordsToBytes(w, sigBytes) {
  const out = new Uint8Array(sigBytes);
  for (let i = 0, j = 0; j < sigBytes; i++, j += 4) { const x = w[i]; out[j] = x >>> 24; out[j + 1] = x >>> 16; out[j + 2] = x >>> 8; out[j + 3] = x; }
  return out;
}
const progressiveStreaming = () => {
  const h = sha256.create();
  for (const c of chunkWords) h.update(wordsToBytes(c, 65536));
  return CL.enc.Hex.stringify(CL.lib.WordArray.create(bytesToWords(h.digest()), 32));
};

const b64 = stringifyCurrent(bytes, MAP);
const cases = {
  'b64-stringify-current': () => stringifyCurrent(bytes, MAP),
  'b64-stringify-chunked': () => stringifyChunked(bytes, MAP),
  'b64-parse-current': () => parseCurrent(b64),
  'b64-parse-fast': () => parseFast(b64),
  'sha256-progressive-streaming': progressiveStreaming,
};
// correctness of the candidates
if (stringifyChunked(bytes, MAP) !== b64) throw new Error('stringify mismatch');
const a = parseCurrent(b64), b = parseFast(b64);
if (a.sigBytes !== b.sigBytes || a.words.some((x, k) => (x | 0) !== (b.words[k] | 0))) throw new Error('parse mismatch');
if (progressiveStreaming() !== CL.SHA256(CL.lib.WordArray.create(words.slice(), MiB)).toString()) throw new Error('digest mismatch');

if (!process.argv[2]) {
  for (const name of Object.keys(cases)) {
    const ms = [1, 2, 3].map(() => {
      const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), name], { encoding: 'utf8' });
      if (r.status !== 0) throw new Error(r.stderr);
      return r.stdout.trim();
    });
    console.log(`${name.padEnd(30)} ${ms.join(' | ')}`);
  }
  process.exit(0);
}
const fn = cases[process.argv[2]];
let sink;
for (let i = 0; i < 15; i++) sink = fn();
const t = [];
for (let i = 0; i < 31; i++) { const s = performance.now(); sink = fn(); t.push(performance.now() - s); }
t.sort((x, y) => x - y);
console.log(`${t[15].toFixed(1)} ms${typeof sink === 'undefined' ? '?' : ''}`);

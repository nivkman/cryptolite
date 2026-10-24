/*
 * Shared helpers for the compat differential suite: a seeded PRNG (so default runs are
 * deterministic and reproducible, and FUZZ=1 runs are reproducible by re-running with the
 * printed SEED), plus small utilities for comparing WordArrays/bytes between crypto-js and
 * cryptolite.
 *
 * Owned by: test/compat/** (qa-automation). Do not import from src outside src/compat/index.
 */
import { createRequire } from 'node:module';
import { randomBytes as nodeRandomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------------------------
// Libraries under comparison
// ---------------------------------------------------------------------------------------------

const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const RefCryptoJS: any = require('crypto-js');

// ---------------------------------------------------------------------------------------------
// Seed resolution: fixed by default (deterministic CI runs); FUZZ=1 picks a fresh random seed
// via node:crypto unless SEED is explicitly set. Always printed once, so any failure is
// reproducible with `SEED=<value> npx vitest run test/compat`.
// ---------------------------------------------------------------------------------------------

const DEFAULT_SEED = 0xc0ffee;

function resolveSeed(): number {
  const envSeed = process.env.SEED;
  if (envSeed !== undefined && envSeed !== '') {
    return Number(envSeed) >>> 0;
  }
  if (process.env.FUZZ) {
    return nodeRandomBytes(4).readUInt32BE(0);
  }
  return DEFAULT_SEED;
}

export const SEED = resolveSeed();
export const FUZZ = !!process.env.FUZZ;

// eslint-disable-next-line no-console
console.log(
  `[test/compat] SEED=${SEED}${FUZZ ? ' (FUZZ=1)' : ''} — rerun with SEED=${SEED} to reproduce.`,
);

/** mulberry32: small, fast, deterministic PRNG. */
export function makeRng(seed: number): () => number {
  let a = seed >>> 0;
  return function next(): number {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = makeRng(SEED);

export function randInt(min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

export function choice<T>(arr: readonly T[]): T {
  return arr[randInt(0, arr.length - 1)];
}

/** Deterministic pseudo-random bytes, derived from the seeded PRNG (not node:crypto). */
export function prngBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = Math.floor(rng() * 256);
  return out;
}

/** True cryptographically-random bytes (node:crypto), for cases where entropy quality matters
 * (e.g. real AES keys) and determinism comes from comparing both libraries within the same run. */
export function trueRandomBytes(n: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(n));
}

export function prngString(n: number): string {
  const bytes = prngBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** A representative, fast-to-run sample of lengths covering block-size edges (0..300). */
export const SAMPLE_LENGTHS = [
  0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 55, 56, 63, 64, 65, 100, 111, 127, 128, 129,
  191, 192, 200, 255, 256, 257, 300,
];

/** Full 0..300 sweep, only used under FUZZ=1. */
export const FULL_LENGTHS = Array.from({ length: 301 }, (_, i) => i);

/** Builds a WordArray (of the given CryptoJS-like namespace) from raw bytes. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function wordArrayFromBytes(CJS: any, bytes: Uint8Array): any {
  return CJS.lib.WordArray.create(bytes);
}

/** Reads sigBytes-worth of bytes out of a WordArray, matching crypto-js's own semantics. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function wordArrayToBytes(wa: any): Uint8Array {
  const sigBytes = wa.sigBytes;
  const words = wa.words;
  const out = new Uint8Array(Math.max(sigBytes, 0));
  for (let i = 0; i < sigBytes; i++) {
    out[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return out;
}

/** Resets the crypto-js-documented Base64url reverse-map cache so a test's outcome does not
 * depend on which other tests ran earlier in the process (both libraries carry this cache). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function resetBase64urlCache(CJS: any): void {
  delete CJS.enc.Base64url._reverseMap;
}

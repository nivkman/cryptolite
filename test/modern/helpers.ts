// Shared test utilities. Test data uses a seeded PRNG so every run is reproducible;
// cryptographic randomness in the code under test is untouched.
import { expect } from 'vitest';
import { CryptoliteError, type CryptoliteErrorCode } from '../../src/modern/index';

/** mulberry32: tiny deterministic PRNG for test data only. */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function randInt(rand: () => number, min: number, max: number): number {
  return min + Math.floor(rand() * (max - min + 1));
}

export function randBytes(rand: () => number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = Math.floor(rand() * 256);
  return out;
}

// Code point ranges that exercise every UTF-8 length plus RTL, combining marks and emoji.
const RANGES: Array<[number, number]> = [
  [0x20, 0x7e], // ASCII printable
  [0x00, 0x1f], // controls, incl. NUL
  [0x80, 0x7ff], // 2-byte (Latin-1 supplement, Greek, Cyrillic, Hebrew, Arabic)
  [0x05d0, 0x05ea], // Hebrew letters
  [0x0600, 0x06ff], // Arabic
  [0x0800, 0xd7ff], // 3-byte below surrogates
  [0xe000, 0xfffd], // 3-byte above surrogates (incl. BOM U+FEFF region)
  [0x10000, 0x10ffff], // 4-byte (supplementary planes)
  [0x1f300, 0x1faff], // emoji
];

/** A random well-formed string (never contains a lone surrogate). */
export function randString(rand: () => number, maxCodePoints: number): string {
  const n = randInt(rand, 0, maxCodePoints);
  let s = '';
  for (let i = 0; i < n; i++) {
    const [lo, hi] = RANGES[Math.floor(rand() * RANGES.length)]!;
    s += String.fromCodePoint(randInt(rand, lo, hi));
  }
  return s;
}

/** Asserts that `fn` throws (or rejects with) a CryptoliteError with the given code. */
export async function expectCode(fn: () => unknown, code: CryptoliteErrorCode): Promise<CryptoliteError> {
  let caught: unknown;
  try {
    await fn();
  } catch (err) {
    caught = err;
  }
  expect(caught, `expected ${code}`).toBeInstanceOf(CryptoliteError);
  expect((caught as CryptoliteError).code).toBe(code);
  return caught as CryptoliteError;
}

/** Synchronous variant for non-async functions. */
export function expectCodeSync(fn: () => unknown, code: CryptoliteErrorCode): CryptoliteError {
  let caught: unknown;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  expect(caught, `expected ${code}`).toBeInstanceOf(CryptoliteError);
  expect((caught as CryptoliteError).code).toBe(code);
  return caught as CryptoliteError;
}

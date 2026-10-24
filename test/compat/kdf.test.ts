import { describe, expect, it } from 'vitest';
import CryptoJS from '../../src/compat/index';
import { RefCryptoJS, prngBytes, prngString } from './_util';

const libs = { cryptolite: CryptoJS, 'crypto-js': RefCryptoJS } as const;
const libEntries = Object.entries(libs);

type HasherName = 'MD5' | 'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512' | 'SHA3' | 'RIPEMD160';
const HASHERS: HasherName[] = ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHA3', 'RIPEMD160'];

describe('PBKDF2', () => {
  it.each(HASHERS)('every hasher, keySize=4, iterations=2, string password/salt — %s', (hasherName) => {
    const outputs = libEntries.map(([, CJS]) =>
      CJS.PBKDF2('password', 'salt', { keySize: 4, iterations: 2, hasher: CJS.algo[hasherName] }).toString(),
    );
    expect(outputs[0]).toBe(outputs[1]);
  });

  it.each(HASHERS)('every hasher, WordArray password/salt — %s', (hasherName) => {
    const password = prngBytes(23);
    const salt = prngBytes(16);
    const outputs = libEntries.map(([, CJS]) =>
      CJS.PBKDF2(CJS.lib.WordArray.create(password), CJS.lib.WordArray.create(salt), {
        keySize: 4,
        iterations: 2,
        hasher: CJS.algo[hasherName],
      }).toString(),
    );
    expect(outputs[0]).toBe(outputs[1]);
  });

  const ITERATIONS = [1, 2, 1000, 0, -1, 1.5];
  it.each(ITERATIONS)('iterations=%s (edge cases included) with SHA256', (iterations) => {
    const outputs = libEntries.map(([, CJS]) =>
      CJS.PBKDF2('password', 'salt', { keySize: 4, iterations, hasher: CJS.algo.SHA256 }).toString(),
    );
    expect(outputs[0]).toBe(outputs[1]);
  });

  const KEY_SIZES = [1, 4, 5, 8, 16, 0, 2.5];
  it.each(KEY_SIZES)('keySize=%s (edge cases included) with SHA256', (keySize) => {
    const outputs = libEntries.map(([, CJS]) => {
      const r = CJS.PBKDF2('password', 'salt', { keySize, iterations: 2, hasher: CJS.algo.SHA256 });
      return { str: r.toString(), sigBytes: r.sigBytes };
    });
    expect(outputs[0]).toEqual(outputs[1]);
  });

  it('negative keySize produces negative sigBytes identically (documented crypto-js quirk)', () => {
    const outputs = libEntries.map(([, CJS]) => {
      const r = CJS.PBKDF2('password', 'salt', { keySize: -1, iterations: 1, hasher: CJS.algo.SHA256 });
      return { str: r.toString(), sigBytes: r.sigBytes };
    });
    expect(outputs[0]).toEqual(outputs[1]);
    expect(outputs[0].sigBytes).toBe(-4);
  });

  it(
    'crypto-js 4.2.0 defaults (SHA256, 250000 iterations, 128-bit key) — one run, matches the real ' +
      '250000-iteration reference implementation',
    () => {
      const outputs = libEntries.map(([, CJS]) => CJS.PBKDF2('password', 'salt').toString());
      expect(outputs[0]).toBe(outputs[1]);
    },
    15_000,
  );

  it('fast noble path (standard hasher+params) and generic fallback path agree at the boundary (keySize=2.5)', () => {
    // dkLen = 2.5 * 4 = 10 bytes: an integer byte count from a non-integer word count. Exercises
    // the fast-path dkLen check without being "iterations<1" or "non-integer dkLen".
    const outputs = libEntries.map(([, CJS]) =>
      CJS.PBKDF2('password', 'salt', { keySize: 2.5, iterations: 3, hasher: CJS.algo.SHA256 }).toString(),
    );
    expect(outputs[0]).toBe(outputs[1]);
  });
});

describe('EvpKDF', () => {
  it.each(HASHERS)('every hasher, keySize=4, iterations=1 (default) — %s', (hasherName) => {
    const outputs = libEntries.map(([, CJS]) =>
      CJS.EvpKDF('password', 'salt', { keySize: 4, hasher: CJS.algo[hasherName] }).toString(),
    );
    expect(outputs[0]).toBe(outputs[1]);
  });

  const ITERATIONS = [1, 3, 0, -1, 1.5];
  it.each(ITERATIONS)('iterations=%s (edge cases included)', (iterations) => {
    const outputs = libEntries.map(([, CJS]) => CJS.EvpKDF('password', 'salt', { keySize: 4, iterations }).toString());
    expect(outputs[0]).toBe(outputs[1]);
  });

  const KEY_SIZES = [1, 4, 8, 0, 2.5, -1];
  it.each(KEY_SIZES)('keySize=%s (edge cases included)', (keySize) => {
    const outputs = libEntries.map(([, CJS]) => {
      const r = CJS.EvpKDF('password', 'salt', { keySize });
      return { str: r.toString(), sigBytes: r.sigBytes };
    });
    expect(outputs[0]).toEqual(outputs[1]);
  });

  it('string password/salt vs WordArray password/salt agree between libraries', () => {
    const password = prngString(19);
    const salt = prngString(8);
    const outputs = libEntries.map(([, CJS]) => CJS.EvpKDF(password, salt, { keySize: 8 }).toString());
    expect(outputs[0]).toBe(outputs[1]);

    const outputsWA = libEntries.map(([, CJS]) =>
      CJS.EvpKDF(CJS.enc.Utf8.parse(password), CJS.enc.Utf8.parse(salt), { keySize: 8 }).toString(),
    );
    expect(outputsWA[0]).toBe(outputsWA[1]);
    expect(outputsWA[0]).toBe(outputs[0]);
  });

  it('default params (MD5, 1 iteration, 128-bit key)', () => {
    const outputs = libEntries.map(([, CJS]) => CJS.EvpKDF('password', 'salt').toString());
    expect(outputs[0]).toBe(outputs[1]);
  });
});

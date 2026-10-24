import { afterEach, describe, expect, it, vi } from 'vitest';
import { encrypt, randomBytes, upgrade } from '../../src/modern/index';
import { expectCode, expectCodeSync } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('randomBytes', () => {
  it('returns the requested number of bytes, including 0 and > 65536 (chunked)', () => {
    expect(randomBytes(0)).toEqual(new Uint8Array(0));
    expect(randomBytes(32)).toHaveLength(32);
    const big = randomBytes(200_000);
    expect(big).toHaveLength(200_000);
    expect(big.constructor).toBe(Uint8Array);
    // Every 64 KiB chunk was actually filled (an unfilled chunk would be all zeros).
    for (let i = 0; i < big.length; i += 65536) {
      expect(big.subarray(i, i + 65536).some((b) => b !== 0)).toBe(true);
    }
  });

  it('produces different output each call', () => {
    expect(Buffer.from(randomBytes(32)).equals(Buffer.from(randomBytes(32)))).toBe(false);
  });

  it('rejects invalid lengths with ERR_PARAMS', () => {
    for (const bad of [-1, 1.5, Number.NaN, Infinity, 2 ** 31, '16', null, undefined, 16n]) {
      expectCodeSync(() => randomBytes(bad as number), 'ERR_PARAMS');
    }
  });

  it('throws ERR_RANDOM, mentioning react-native-get-random-values, when getRandomValues is missing', async () => {
    vi.stubGlobal('crypto', undefined);
    expect(globalThis.crypto).toBeUndefined(); // the stub really took effect
    const err = expectCodeSync(() => randomBytes(16), 'ERR_RANDOM');
    expect(err.message).toContain('react-native-get-random-values');

    vi.stubGlobal('crypto', {}); // e.g. an object without getRandomValues
    expectCodeSync(() => randomBytes(16), 'ERR_RANDOM');

    // encrypt surfaces the same error (as a rejected promise).
    await expectCode(() => encrypt('x', 'pw', { iterations: 100_000 }), 'ERR_RANDOM');
  });

  it('works with a getRandomValues-only polyfill (React Native with react-native-get-random-values)', () => {
    const real = globalThis.crypto;
    vi.stubGlobal('crypto', { getRandomValues: real.getRandomValues.bind(real) });
    expect(randomBytes(70_000)).toHaveLength(70_000);
  });

  it('upgrade() validates arguments before needing randomness', async () => {
    vi.stubGlobal('crypto', undefined);
    await expectCode(() => upgrade('not a token', 'pw'), 'ERR_FORMAT');
  });
});

/**
 * Regression tests for the fixes in docs/reviews/security.md (M1, M2, L1, L2).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import CryptoJS from '../../src/compat/index';
import { CryptoliteError, decrypt, decryptBytes, encrypt, randomBytes, upgrade } from '../../src/modern/index';
import { platformEngine } from '../../src/modern/engine';

const PW = 'correct horse battery staple';

async function code(fn: () => unknown): Promise<string> {
  try {
    await fn();
  } catch (e) {
    expect(e).toBeInstanceOf(CryptoliteError);
    return (e as CryptoliteError).code;
  }
  throw new Error('expected a CryptoliteError');
}

describe('M1: Object.prototype pollution cannot change security defaults', () => {
  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).iterations;
    delete (Object.prototype as Record<string, unknown>).legacy;
    delete (Object.prototype as Record<string, unknown>).maxIterations;
  });

  it('a polluted iterations is ignored by encrypt (default stays 600000)', async () => {
    (Object.prototype as Record<string, unknown>).iterations = 100_000;
    const token = await encrypt('x', PW);
    expect(token.split('.')[1]).toBe('600000');
    const withEmptyOptions = await encrypt('x', PW, {});
    expect(withEmptyOptions.split('.')[1]).toBe('600000');
  });

  it('a polluted legacy does not enable legacy decryption', async () => {
    const legacy = CryptoJS.AES.encrypt('old secret', PW).toString();
    (Object.prototype as Record<string, unknown>).legacy = true;
    expect(await code(() => decrypt(legacy, PW))).toBe('ERR_LEGACY_NOT_ALLOWED');
    expect(await code(() => decrypt(legacy, PW, {}))).toBe('ERR_LEGACY_NOT_ALLOWED');
  });

  it('a polluted maxIterations does not lower the limit', async () => {
    const token = await encrypt('x', PW, { iterations: 100_000 });
    (Object.prototype as Record<string, unknown>).maxIterations = 10_000;
    expect(await decrypt(token, PW)).toBe('x');
  });
});

describe('M2: maxIterations', () => {
  it('refuses tokens above maxIterations with ERR_FORMAT and never derives a key', async () => {
    const token = await encrypt('x', PW, { iterations: 200_000 });
    const subtle = globalThis.crypto.subtle;
    const spy = vi.spyOn(subtle, 'deriveBits');
    try {
      expect(await code(() => decrypt(token, PW, { maxIterations: 199_999 }))).toBe('ERR_FORMAT');
      expect(await code(() => decryptBytes(token, PW, { maxIterations: 100_000 }))).toBe('ERR_FORMAT');
      expect(await code(() => upgrade(token, PW, { maxIterations: 150_000 }))).toBe('ERR_FORMAT');
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
    expect(await decrypt(token, PW, { maxIterations: 200_000 })).toBe('x');
  });

  it('validates maxIterations itself', async () => {
    const token = await encrypt('x', PW, { iterations: 100_000 });
    for (const bad of [9_999, 2_000_001, 1.5, '600000', null]) {
      expect(await code(() => decrypt(token, PW, { maxIterations: bad as number }))).toBe('ERR_PARAMS');
    }
  });

  it('upgrade applies iterations to the output and maxIterations to the input', async () => {
    const token = await encrypt('x', PW, { iterations: 100_000 });
    const up = await upgrade(token, PW, { iterations: 120_000, maxIterations: 100_000 });
    expect(up.split('.')[1]).toBe('120000');
    expect(await decrypt(up, PW)).toBe('x');
  });
});

describe('L1: a Web Crypto authentication failure does not fall back to noble', () => {
  it('wrong password: Web Crypto OperationError is final', async () => {
    const engine = platformEngine();
    expect(engine.name).toBe('webcrypto');
    const key = new Uint8Array(32).fill(1);
    const wrongKey = new Uint8Array(32).fill(2);
    const iv = new Uint8Array(12);
    const aad = new Uint8Array(0);
    const sealed = await engine.seal(key, iv, aad, new Uint8Array([1, 2, 3]));
    await expect(engine.open(wrongKey, iv, aad, sealed)).rejects.toMatchObject({ name: 'OperationError' });
  });
});

describe('L2: a throwing getRandomValues surfaces as ERR_RANDOM', () => {
  it('randomBytes', async () => {
    const spy = vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(() => {
      throw new DOMException('quota', 'QuotaExceededError');
    });
    try {
      expect(await code(() => randomBytes(16))).toBe('ERR_RANDOM');
      expect(await code(() => encrypt('x', PW, { iterations: 100_000 }))).toBe('ERR_RANDOM');
    } finally {
      spy.mockRestore();
    }
  });
});

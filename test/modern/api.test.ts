import CryptoJS from 'crypto-js';
import { describe, expect, it } from 'vitest';
import * as modern from '../../src/modern/index';
import { CryptoliteError } from '../../src/modern/index';

const PUBLIC_VALUES = [
  'CryptoliteError',
  'decrypt',
  'decryptBytes',
  'encrypt',
  'hmac',
  'isLegacy',
  'md5',
  'randomBytes',
  'sha1',
  'sha256',
  'sha384',
  'sha3_256',
  'sha3_512',
  'sha512',
  'upgrade',
];

describe('public surface', () => {
  it('src/modern/index exports exactly the public API (no internals, no test hooks)', () => {
    expect(Object.keys(modern).sort()).toEqual([...PUBLIC_VALUES].sort());
  });

  it('no export collides with a crypto-js top-level member (src/index.ts merges them with Object.assign)', () => {
    const cryptoJsKeys = new Set(Object.keys(CryptoJS));
    expect(cryptoJsKeys.size).toBeGreaterThan(20); // really the crypto-js object
    for (const name of PUBLIC_VALUES) expect(cryptoJsKeys.has(name), name).toBe(false);
  });

  it('every function is a named function', () => {
    for (const name of PUBLIC_VALUES) {
      const value = (modern as Record<string, unknown>)[name];
      expect(typeof value).toBe('function');
      expect((value as { name: string }).name).toBe(name);
    }
  });
});

describe('CryptoliteError', () => {
  it('is an Error with name, code and message, and a stack headed by its name', () => {
    const err = new CryptoliteError('ERR_FORMAT', 'bad token');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(CryptoliteError);
    expect(err.name).toBe('CryptoliteError');
    expect(err.code).toBe('ERR_FORMAT');
    expect(err.message).toBe('bad token');
    expect(String(err)).toBe('CryptoliteError: bad token');
    expect(err.stack?.startsWith('CryptoliteError: bad token')).toBe(true);
    expect(Object.keys(err)).toEqual(['code']); // name lives on the prototype
  });

  it('is what the API throws', async () => {
    await expect(modern.decrypt('nope', 'pw')).rejects.toBeInstanceOf(CryptoliteError);
    expect(() => modern.sha256(1 as never)).toThrow(CryptoliteError);
  });
});

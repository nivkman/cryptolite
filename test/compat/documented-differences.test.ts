/*
 * Asserts the behaviour documented in docs/DECISIONS.md D6: cryptolite deliberately diverges
 * from crypto-js for non-standard AES key sizes and for the unimplemented legacy ciphers,
 * throwing a clear error instead of silently producing non-standard or insecure output.
 *
 * These are NOT bugs — do not "fix" cryptolite to match crypto-js here.
 */
import { describe, expect, it } from 'vitest';
import CryptoJS from '../../src/compat/index';
import { RefCryptoJS, prngBytes } from './_util';

describe('Documented difference — AES key not 16/24/32 bytes', () => {
  it('crypto-js silently accepts a 10-byte key (sanity: confirms this really is a behaviour change)', () => {
    const key = RefCryptoJS.lib.WordArray.create(prngBytes(10));
    const iv = RefCryptoJS.lib.WordArray.create(prngBytes(16));
    expect(() => RefCryptoJS.AES.encrypt('hello', key, { iv }).toString()).not.toThrow();
  });

  it.each([1, 5, 10, 15, 17, 20, 23, 25, 31, 33, 40])(
    'cryptolite throws a clear error for a %i-byte key',
    (len) => {
      const key = CryptoJS.lib.WordArray.create(prngBytes(len));
      expect(() => CryptoJS.AES.encrypt('hello', key)).toThrow(/16, 24 or 32 bytes/);
    },
  );

  it('key-mode AES.decrypt with a non-standard key size also throws', () => {
    const key = CryptoJS.lib.WordArray.create(prngBytes(10));
    expect(() => CryptoJS.AES.decrypt('U2FsdGVkX1+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', key)).toThrow(
      /16, 24 or 32 bytes/,
    );
  });

  it('16/24/32-byte keys do not throw', () => {
    for (const len of [16, 24, 32]) {
      const key = CryptoJS.lib.WordArray.create(prngBytes(len));
      const iv = CryptoJS.lib.WordArray.create(prngBytes(16));
      expect(() => CryptoJS.AES.encrypt('hello', key, { iv })).not.toThrow();
    }
  });
});

describe('Documented difference — unimplemented legacy ciphers throw', () => {
  const CIPHERS = ['DES', 'TripleDES', 'RC4', 'RC4Drop', 'Rabbit', 'RabbitLegacy', 'Blowfish'] as const;

  it.each(CIPHERS)('crypto-js actually implements %s (sanity check on the reference)', (name) => {
    const ct = RefCryptoJS[name].encrypt('hello', '0123456789abcdef0123456789abcdef');
    expect(() => ct.toString()).not.toThrow();
  });

  it.each(CIPHERS)('cryptolite.%s.encrypt throws a clear "does not implement" error', (name) => {
    expect(() => CryptoJS[name].encrypt('hello', '0123456789abcdef0123456789abcdef')).toThrow(
      /does not implement/i,
    );
  });

  it.each(CIPHERS)('cryptolite.%s.decrypt throws a clear "does not implement" error', (name) => {
    expect(() => CryptoJS[name].decrypt('whatever', '0123456789abcdef0123456789abcdef')).toThrow(
      /does not implement/i,
    );
  });

  it.each(CIPHERS)('cryptolite.algo.%s.create()/.createEncryptor()/.createDecryptor() all throw', (name) => {
    expect(() => CryptoJS.algo[name].create()).toThrow(/does not implement/i);
    expect(() => CryptoJS.algo[name].createEncryptor()).toThrow(/does not implement/i);
    expect(() => CryptoJS.algo[name].createDecryptor()).toThrow(/does not implement/i);
  });
});

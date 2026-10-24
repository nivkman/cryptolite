import { describe, expect, it } from 'vitest';
import CryptoJS from '../../src/compat/index';
import { RefCryptoJS, prngBytes, prngString } from './_util';

const libs = { cryptolite: CryptoJS, 'crypto-js': RefCryptoJS } as const;
const libEntries = Object.entries(libs);

describe('AES passphrase mode (string key)', () => {
  it('default (random salt, default hasher MD5) — same-library round trip and OpenSSL framing', () => {
    for (const [, CJS] of libEntries) {
      const message = 'secret message here';
      const ct = CJS.AES.encrypt(message, 'my passphrase');
      expect(ct.toString().startsWith('U2FsdGVk')).toBe(true); // Base64 of "Salted__"
      expect(ct.salt.sigBytes).toBe(8);
      const pt = CJS.AES.decrypt(ct.toString(), 'my passphrase');
      expect(pt.toString(CJS.enc.Utf8)).toBe(message);
    }
  });

  it('explicit cfg.salt is honored and reflected in the OpenSSL framing', () => {
    const saltBytes = prngBytes(8);
    const message = prngString(30);
    for (const [, CJS] of libEntries) {
      const salt = CJS.lib.WordArray.create(saltBytes);
      const ct = CJS.AES.encrypt(message, 'pw', { salt });
      expect(ct.salt.toString()).toBe(salt.toString());
      const pt = CJS.AES.decrypt(ct.toString(), 'pw');
      expect(pt.toString(CJS.enc.Utf8)).toBe(message);
    }
  });

  it('explicit cfg.salt gives byte-identical ciphertext between libraries', () => {
    const saltBytes = prngBytes(8);
    const message = prngString(30);
    const outputs = libEntries.map(([, CJS]) =>
      CJS.AES.encrypt(message, 'pw', { salt: CJS.lib.WordArray.create(saltBytes) }).toString(),
    );
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('explicit cfg.hasher (SHA256 instead of default MD5) matches between libraries', () => {
    const saltBytes = prngBytes(8);
    const message = prngString(40);
    const outputs = libEntries.map(([, CJS]) =>
      CJS.AES.encrypt(message, 'pw', {
        salt: CJS.lib.WordArray.create(saltBytes),
        hasher: CJS.algo.SHA256,
      }).toString(),
    );
    expect(outputs[0]).toBe(outputs[1]);

    for (const [, CJS] of libEntries) {
      const ct = CJS.AES.encrypt(message, 'pw', {
        salt: CJS.lib.WordArray.create(saltBytes),
        hasher: CJS.algo.SHA256,
      });
      const pt = CJS.AES.decrypt(ct.toString(), 'pw', { hasher: CJS.algo.SHA256 });
      expect(pt.toString(CJS.enc.Utf8)).toBe(message);
    }
  });

  it('cfg.salt=false is falsy, so a random salt is still generated (not a real "disable" switch)', () => {
    // Documents crypto-js's actual `if (!salt)` check: `false` is indistinguishable from "omitted".
    for (const [, CJS] of libEntries) {
      const message = prngString(20);
      const ct = CJS.AES.encrypt(message, 'pw', { salt: false });
      expect(ct.salt).toBeTruthy();
      expect(ct.salt.sigBytes).toBe(8);
      const pt = CJS.AES.decrypt(ct.toString(), 'pw');
      expect(pt.toString(CJS.enc.Utf8)).toBe(message);
    }
  });

  for (const n of [1, 5, 20]) {
    it(`cross-decryption both directions on ${n} random message(s), default settings`, () => {
      for (let i = 0; i < n; i++) {
        const message = prngString((i * 7) % 200);
        const passphrase = prngString(10 + i);
        const saltBytes = prngBytes(8);

        // cryptolite encrypts, crypto-js decrypts.
        {
          const ct = CryptoJS.AES.encrypt(message, passphrase, { salt: CryptoJS.lib.WordArray.create(saltBytes) });
          const pt = RefCryptoJS.AES.decrypt(ct.toString(), passphrase);
          expect(pt.toString(RefCryptoJS.enc.Utf8)).toBe(message);
        }
        // crypto-js encrypts, cryptolite decrypts.
        {
          const ct = RefCryptoJS.AES.encrypt(message, passphrase, {
            salt: RefCryptoJS.lib.WordArray.create(saltBytes),
          });
          const pt = CryptoJS.AES.decrypt(ct.toString(), passphrase);
          expect(pt.toString(CryptoJS.enc.Utf8)).toBe(message);
        }
      }
    });
  }

  it('wrong passphrase produces identical garbage (or identical throw) on both libraries', () => {
    const saltBytes = prngBytes(8);
    const message = prngString(37);
    const results = libEntries.map(([, CJS]) => {
      const ct = CJS.AES.encrypt(message, 'correct passphrase', { salt: CJS.lib.WordArray.create(saltBytes) });
      const pt = CJS.AES.decrypt(ct.toString(), 'wrong passphrase');
      try {
        return { threw: false, value: pt.toString(CJS.enc.Utf8) };
      } catch (e) {
        return { threw: true, value: (e as Error).message };
      }
    });
    expect(results[0]).toEqual(results[1]);
  });
});

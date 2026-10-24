import CryptoJS from 'crypto-js';
import { describe, expect, it } from 'vitest';
import { decrypt, decryptBytes, encrypt, isLegacy, upgrade } from '../../src/modern/index';
import { expectCode, prng, randBytes, randInt, randString } from './helpers';

const FAST = { iterations: 100_000 };

/** Real crypto-js 4.2.0 passphrase-mode output. */
function legacyEncrypt(text: string, passphrase: string): string {
  return CryptoJS.AES.encrypt(text, passphrase).toString();
}

function wordArray(bytes: Uint8Array): CryptoJS.lib.WordArray {
  return CryptoJS.enc.Hex.parse(Buffer.from(bytes).toString('hex'));
}

describe('legacy crypto-js ciphertexts', () => {
  it('decrypts real CryptoJS.AES.encrypt(text, pass).toString() output for many random inputs', async () => {
    const rand = prng(40);
    const cases: Array<[string, string]> = [
      ['', 'pw'],
      ['hello world', 'secret'],
      ['שלום עולם', 'סיסמה'],
      ['😀👩‍👩‍👧‍👦', '🔑'],
      ['﻿bom first', 'p'],
      ['x'.repeat(10_000), 'long'],
    ];
    for (let i = 0; i < 300; i++) cases.push([randString(rand, 60), randString(rand, 16) || 'fallback']);
    for (const [text, pass] of cases) {
      const ct = legacyEncrypt(text, pass);
      expect(ct.startsWith('U2FsdGVkX1')).toBe(true);
      expect(isLegacy(ct)).toBe(true);
      expect(await decrypt(ct, pass, { legacy: true })).toBe(text);
      expect(Buffer.from(await decryptBytes(ct, pass, { legacy: true })).equals(Buffer.from(text, 'utf8'))).toBe(true);
    }
  });

  it('decrypts binary (WordArray) legacy plaintexts with decryptBytes', async () => {
    const rand = prng(41);
    for (let i = 0; i < 50; i++) {
      const bytes = randBytes(rand, randInt(rand, 0, 100));
      const ct = CryptoJS.AES.encrypt(wordArray(bytes), 'binary-pass').toString();
      expect(await decryptBytes(ct, 'binary-pass', { legacy: true })).toEqual(bytes);
    }
  });

  it('is rejected without { legacy: true } (ERR_LEGACY_NOT_ALLOWED) with an actionable message', async () => {
    const ct = legacyEncrypt('needs opt-in', 'pw');
    const e = await expectCode(() => decrypt(ct, 'pw'), 'ERR_LEGACY_NOT_ALLOWED');
    expect(e.message).toContain('{ legacy: true }');
    expect(e.message).toContain('upgrade(');
    await expectCode(() => decryptBytes(ct, 'pw'), 'ERR_LEGACY_NOT_ALLOWED');
    await expectCode(() => decrypt(ct, 'pw', { legacy: false }), 'ERR_LEGACY_NOT_ALLOWED');
    // Detected before the password is used: a wrong password gives the same answer.
    await expectCode(() => decrypt(ct, 'wrong'), 'ERR_LEGACY_NOT_ALLOWED');
  });

  it('wrong password → ERR_DECRYPT', async () => {
    const rand = prng(42);
    for (let i = 0; i < 50; i++) {
      const ct = legacyEncrypt(randString(rand, 40), 'right');
      await expectCode(() => decrypt(ct, `wrong-${i}`, { legacy: true }), 'ERR_DECRYPT');
    }
  });

  it('a wrong password that passes the padding check: decryptBytes yields garbage, decrypt/upgrade report ERR_DECRYPT', async () => {
    // Fixed salt makes this deterministic. About 1 in 256 wrong passwords produce valid PKCS#7
    // padding, which is why legacy ciphertexts are documented as unauthenticated.
    const salt = CryptoJS.enc.Hex.parse('0011223344556677');
    const text = 'the original legacy plaintext';
    const ct = CryptoJS.AES.encrypt(text, 'right', { salt }).toString();
    let found: string | undefined;
    for (let i = 0; i < 20_000 && !found; i++) {
      try {
        await decryptBytes(ct, `guess-${i}`, { legacy: true });
        found = `guess-${i}`;
      } catch {
        // padding rejected, as for most wrong passwords
      }
    }
    expect(found).toBeDefined();
    const garbage = await decryptBytes(ct, found!, { legacy: true });
    expect(Buffer.from(garbage).toString('utf8')).not.toBe(text);
    await expectCode(() => decrypt(ct, found!, { legacy: true }), 'ERR_DECRYPT');
    await expectCode(() => upgrade(ct, found!, FAST), 'ERR_DECRYPT');
  });

  it('isLegacy is strict and never throws', async () => {
    const ct = legacyEncrypt('abc', 'pw');
    const raw = Buffer.from(ct, 'base64');
    const b64 = (b: Buffer) => b.toString('base64');
    const notLegacy: unknown[] = [
      await encrypt('x', 'pw', FAST),
      '',
      'U2FsdGVkX1',
      'U2FsdGVkX18=', // "Salted__" only
      b64(raw.subarray(0, 16)), // header without ciphertext
      b64(raw.subarray(0, 31)), // ciphertext not a whole block
      b64(Buffer.concat([raw, Buffer.alloc(1)])), // extra byte
      ct.replace(/=+$/, ''), // padding stripped
      ` ${ct}`, `${ct}\n`, // whitespace
      ct.replace(/\+/g, '-').replace(/\//g, '_'), // base64url alphabet (if it had + or /)
      b64(Buffer.concat([Buffer.from('Salted_!'), raw.subarray(8)])), // wrong magic
      Buffer.from(raw).toString('hex'),
      null, undefined, 42, {}, raw,
    ].filter((v) => v !== ct);
    for (const v of notLegacy) expect(isLegacy(v as string), String(v)).toBe(false);
    expect(isLegacy(ct)).toBe(true);
  });

  it('non-legacy, non-cl1 input is ERR_FORMAT even with { legacy: true }', async () => {
    const ct = legacyEncrypt('abc', 'pw');
    await expectCode(() => decrypt(ct.replace(/=+$/, '') || 'x', 'pw', { legacy: true }), 'ERR_FORMAT');
    await expectCode(() => decrypt('U2FsdGVkX18=', 'pw', { legacy: true }), 'ERR_FORMAT');
  });
});

describe('upgrade()', () => {
  it('turns legacy ciphertexts into cl1 tokens with the same plaintext', async () => {
    const rand = prng(43);
    for (let i = 0; i < 8; i++) {
      const text = i === 0 ? '' : randString(rand, 40);
      const pass = `pass-${i}-שלום`;
      const ct = legacyEncrypt(text, pass);
      const token = await upgrade(ct, pass, FAST);
      expect(token.startsWith('cl1.100000.')).toBe(true);
      expect(isLegacy(token)).toBe(false);
      expect(await decrypt(token, pass)).toBe(text); // no legacy flag needed any more
    }
  });

  it('re-encrypts cl1 tokens with fresh salt/iv and the requested iterations, preserving bytes', async () => {
    const bytes = new Uint8Array([0, 255, 1, 254, 0xc3]);
    const old = await encrypt(bytes, 'pw', FAST);
    const next = await upgrade(old, 'pw', { iterations: 120_000 });
    expect(next.startsWith('cl1.120000.')).toBe(true);
    expect(next.split('.')[2]).not.toBe(old.split('.')[2]);
    expect(await decryptBytes(next, 'pw')).toEqual(bytes);
  });

  it('rejects wrong passwords, bad input and bad options', async () => {
    const ct = legacyEncrypt('abc', 'pw');
    await expectCode(() => upgrade(ct, 'wrong', FAST), 'ERR_DECRYPT');
    const cl1 = await encrypt('x', 'pw', FAST);
    await expectCode(() => upgrade(cl1, 'wrong', FAST), 'ERR_DECRYPT');
    await expectCode(() => upgrade('nonsense', 'pw', FAST), 'ERR_FORMAT');
    await expectCode(() => upgrade(ct, '', FAST), 'ERR_PARAMS');
    await expectCode(() => upgrade(ct, 'pw', { iterations: 1000 }), 'ERR_PARAMS');
    await expectCode(() => upgrade(ct, 'pw', { legacy: true } as never), 'ERR_PARAMS');
    await expectCode(() => upgrade(42 as never, 'pw'), 'ERR_PARAMS');
  });

  it('refuses legacy binary plaintexts (they cannot be told apart from a wrong password)', async () => {
    const ct = CryptoJS.AES.encrypt(wordArray(new Uint8Array([0xff, 0xfe, 0x00, 0x80])), 'pw').toString();
    await expectCode(() => upgrade(ct, 'pw', FAST), 'ERR_DECRYPT');
    // The documented alternative works:
    const bytes = await decryptBytes(ct, 'pw', { legacy: true });
    const token = await encrypt(bytes, 'pw', FAST);
    expect(await decryptBytes(token, 'pw')).toEqual(new Uint8Array([0xff, 0xfe, 0x00, 0x80]));
  });
});

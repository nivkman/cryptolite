import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes as nodeRandomBytes } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { decrypt, decryptBytes, encrypt, isLegacy } from '../../src/modern/index';
import { expectCode, prng, randBytes } from './helpers';

const PW = 'correct horse battery staple';
const FAST = { iterations: 100_000 }; // the minimum encrypt() allows
const TOKEN_RE = /^cl1\.(\d+)\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{22,})$/;

/** Builds a cl1 token with node:crypto (OpenSSL), independently of the code under test. */
function nodeSeal(plaintext: Uint8Array, password: string, iterations: number, salt: Buffer, iv: Buffer): string {
  const header = `cl1.${iterations}.${salt.toString('base64url')}.${iv.toString('base64url')}`;
  const key = pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(header, 'ascii'));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return `${header}.${ct.toString('base64url')}`;
}

/** Opens a cl1 token with node:crypto, independently of the code under test. */
function nodeOpen(token: string, password: string): Buffer {
  const [, it, s, v, c] = token.split('.') as [string, string, string, string, string];
  const header = token.slice(0, token.lastIndexOf('.'));
  const key = pbkdf2Sync(Buffer.from(password, 'utf8'), Buffer.from(s, 'base64url'), Number(it), 32, 'sha256');
  const sealed = Buffer.from(c, 'base64url');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(v, 'base64url'));
  decipher.setAAD(Buffer.from(header, 'ascii'));
  decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - 16)), decipher.final()]);
}

describe('encrypt / decrypt round trips', () => {
  const strings = [
    '',
    'hello',
    'שלום עולם! זה טקסט בעברית', // RTL Hebrew
    'مرحبا بالعالم', // RTL Arabic
    'mixed: שלום + hello + 123',
    '😀👩‍👩‍👧‍👦🏳️‍🌈🇮🇱', // emoji incl. ZWJ sequences and flags
    '﻿starts with a BOM',
    'nul\u0000inside',
    '\u{10FFFF}\u{10000}ࠀ߿\u0080\u007F', // UTF-8 length boundaries
    'x'.repeat(100_000),
  ];

  it.each(strings.map((s) => [s.length > 40 ? `${s.slice(0, 20)}… (${s.length} chars)` : JSON.stringify(s), s]))(
    'string %s',
    async (_label, text) => {
      const token = await encrypt(text, PW, FAST);
      const m = TOKEN_RE.exec(token);
      expect(m).not.toBeNull();
      expect(m![1]).toBe('100000');
      // ciphertext = UTF-8 length + 16-byte tag
      expect(Buffer.from(m![4]!, 'base64url').length).toBe(Buffer.byteLength(text, 'utf8') + 16);
      expect(await decrypt(token, PW)).toBe(text);
      expect(Buffer.from(await decryptBytes(token, PW)).equals(Buffer.from(text, 'utf8'))).toBe(true);
    },
  );

  it('binary plaintexts of many lengths, including empty and invalid UTF-8', async () => {
    const rand = prng(20);
    for (const len of [0, 1, 15, 16, 17, 255, 4096]) {
      const bytes = randBytes(rand, len);
      bytes[0] = 0xff; // never valid UTF-8 (when non-empty)
      const copy = bytes.slice();
      const token = await encrypt(bytes, PW, FAST);
      expect(bytes).toEqual(copy); // input untouched
      const out = await decryptBytes(token, PW);
      expect(out).toEqual(len === 0 ? new Uint8Array(0) : copy);
      if (len > 0) await expectCode(() => decrypt(token, PW), 'ERR_UTF8');
    }
  });

  it('accepts Buffer and cross-realm Uint8Array plaintexts', async () => {
    const buf = Buffer.from('buffer plaintext');
    expect(await decrypt(await encrypt(buf, PW, FAST), PW)).toBe('buffer plaintext');
    const foreign = runInNewContext('new Uint8Array([104, 105])') as Uint8Array;
    expect(await decrypt(await encrypt(foreign, PW, FAST), PW)).toBe('hi');
  });

  it('unicode passwords (emoji, Hebrew) are UTF-8 encoded', async () => {
    const pw = 'סיסמה🔑';
    const token = await encrypt('secret', pw, FAST);
    expect(await decrypt(token, pw)).toBe('secret');
    expect(nodeOpen(token, pw).toString()).toBe('secret');
    await expectCode(() => decrypt(token, 'סיסמה'), 'ERR_DECRYPT');
  });

  it('every call uses a fresh salt and IV', async () => {
    const a = await encrypt('same', PW, FAST);
    const b = await encrypt('same', PW, FAST);
    expect(a).not.toBe(b);
    expect(a.split('.')[2]).not.toBe(b.split('.')[2]);
    expect(a.split('.')[3]).not.toBe(b.split('.')[3]);
  });

  it('uses 600000 iterations by default (the one default-cost test)', async () => {
    const token = await encrypt('default cost', PW);
    expect(token.startsWith('cl1.600000.')).toBe(true);
    expect(await decrypt(token, PW)).toBe('default cost');
  });

  it('isLegacy is false for cl1 tokens', async () => {
    expect(isLegacy(await encrypt('x', PW, FAST))).toBe(false);
  });
});

describe('token format matches the spec (independent node:crypto implementation)', () => {
  it('node:crypto decrypts our tokens using the header as AAD', async () => {
    const rand = prng(21);
    for (const len of [0, 5, 64]) {
      const bytes = randBytes(rand, len);
      const token = await encrypt(bytes, PW, FAST);
      expect(nodeOpen(token, PW).equals(Buffer.from(bytes))).toBe(true);
    }
  });

  it('we decrypt tokens built by node:crypto, at any iteration count in [10000, 2000000]', async () => {
    for (const iterations of [10_000, 12_345, 100_000]) {
      const token = nodeSeal(Buffer.from('from openssl'), PW, iterations, nodeRandomBytes(16), nodeRandomBytes(12));
      expect(await decrypt(token, PW)).toBe('from openssl');
    }
  });

  it('a token whose AAD was not the header does not decrypt', async () => {
    // Same key, IV and ciphertext layout, but sealed with an empty AAD.
    const salt = nodeRandomBytes(16);
    const iv = nodeRandomBytes(12);
    const header = `cl1.10000.${salt.toString('base64url')}.${iv.toString('base64url')}`;
    const key = pbkdf2Sync(PW, salt, 10_000, 32, 'sha256');
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update('no aad'), cipher.final(), cipher.getAuthTag()]);
    await expectCode(() => decrypt(`${header}.${ct.toString('base64url')}`, PW), 'ERR_DECRYPT');
  });
});

describe('failures', () => {
  it('wrong password → ERR_DECRYPT with one generic message', async () => {
    const token = await encrypt('secret', PW, FAST);
    const e1 = await expectCode(() => decrypt(token, PW + '!'), 'ERR_DECRYPT');
    const e2 = await expectCode(() => decryptBytes(token, 'x'), 'ERR_DECRYPT');
    const tampered = token.slice(0, -2) + (token.endsWith('A') ? 'B' : 'A') + token.slice(-1);
    const e3 = await expectCode(() => decrypt(tampered, PW), 'ERR_DECRYPT');
    expect(e1.message).toBe(e2.message);
    expect(e1.message).toBe(e3.message);
    expect(e1.message).not.toContain(PW);
  });

  it('unrecognized input → ERR_FORMAT', async () => {
    for (const bad of ['', 'hello', 'cl1', 'cl1.', 'CL1.600000.a.b.c', 'cl2.600000.a.b.c', 'U2FsdGVkX1', '{"ct":"..."}']) {
      await expectCode(() => decrypt(bad, PW), 'ERR_FORMAT');
      await expectCode(() => decryptBytes(bad, PW, { legacy: true }), 'ERR_FORMAT');
    }
  });

  it('invalid arguments → ERR_PARAMS, as rejected promises (never synchronous throws)', async () => {
    const token = await encrypt('x', PW, FAST);
    const bad: Array<() => Promise<unknown>> = [
      () => encrypt(123 as never, PW),
      () => encrypt(null as never, PW),
      () => encrypt(new ArrayBuffer(4) as never, PW),
      () => encrypt(new Uint16Array(2) as never, PW),
      () => encrypt([1, 2] as never, PW),
      () => encrypt('x', ''),
      () => encrypt('x', undefined as never),
      () => encrypt('x', new Uint8Array(4) as never),
      () => encrypt('x', PW, null as never),
      () => encrypt('x', PW, [] as never),
      () => encrypt('x', PW, 'fast' as never),
      () => encrypt('x', PW, { iteration: 200_000 } as never), // typo is not silently ignored
      () => encrypt('x', PW, { legacy: true } as never),
      () => encrypt('x', PW, { iterations: 99_999 }),
      () => encrypt('x', PW, { iterations: 10_000_001 }),
      () => encrypt('x', PW, { iterations: 150_000.5 }),
      () => encrypt('x', PW, { iterations: Number.NaN }),
      () => encrypt('x', PW, { iterations: Infinity }),
      () => encrypt('x', PW, { iterations: '200000' as never }),
      () => decrypt(token, ''),
      () => decrypt(token, 42 as never),
      () => decrypt(42 as never, PW),
      () => decrypt(undefined as never, PW),
      () => decrypt(token, PW, { legacy: 'yes' as never }),
      () => decrypt(token, PW, { legacy: 1 as never }),
      () => decrypt(token, PW, { iterations: 100_000 } as never),
      () => decryptBytes(token, PW, null as never),
      () => decryptBytes(Buffer.from(token) as never, PW),
    ];
    for (const call of bad) {
      let promise: Promise<unknown> | undefined;
      expect(() => {
        promise = call();
      }).not.toThrow();
      expect(promise).toBeInstanceOf(Promise);
      await expectCode(() => promise, 'ERR_PARAMS');
    }
  });

  it('error messages name the problem without echoing secrets', async () => {
    const e = await expectCode(() => encrypt('x', PW, { iterations: 5 }), 'ERR_PARAMS');
    expect(e.message).toContain('iterations');
    expect(e.message).toContain('100000');
    const u = await expectCode(() => encrypt('x', 'hunter2\uD800zz'), 'ERR_UTF8');
    expect(u.message).toContain('password');
    expect(u.message).not.toContain('hunter2');
    const p = await expectCode(() => encrypt('my secret \uDC00', PW, FAST), 'ERR_UTF8');
    expect(p.message).toContain('plaintext');
    expect(p.message).not.toContain('secret');
  });

  it('snapshots byte input at call time (mutating it during key derivation has no effect)', async () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const pending = encrypt(bytes, PW, FAST);
    bytes.fill(9); // while PBKDF2 is still running
    const token = await pending;
    expect(Array.from(await decryptBytes(token, PW))).toEqual([1, 2, 3, 4]);
    expect(Array.from(bytes)).toEqual([9, 9, 9, 9]); // and never wiped by encrypt
  });

  it('rejects plaintexts over 256 MiB with ERR_PARAMS instead of an engine RangeError', async () => {
    const huge = new Uint8Array(256 * 1024 * 1024 + 1); // zero pages, never touched
    const e = await expectCode(() => encrypt(huge, PW, FAST), 'ERR_PARAMS');
    expect(e.message).toContain('too large');
  });

  it('decrypt reports binary plaintext as ERR_UTF8 and points to decryptBytes', async () => {
    const token = await encrypt(new Uint8Array([0xc3, 0x28]), PW, FAST);
    const e = await expectCode(() => decrypt(token, PW), 'ERR_UTF8');
    expect(e.message).toContain('decryptBytes');
  });
});

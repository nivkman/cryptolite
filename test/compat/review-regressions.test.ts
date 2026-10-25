/**
 * Regression tests for docs/reviews/code-review.md (H1, H2, M1-M3, L1-L3): inputs the original
 * suite never produced — WordArrays with bytes beyond `sigBytes`, fractional `sigBytes`,
 * non-WordArray arguments, and reused cipher/hasher objects. Every case runs the same input
 * through crypto-js 4.2.0 and cryptolite and requires identical results (or identical throws).
 */
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import L from '../../src/compat/index';

const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const R: any = require('crypto-js');
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const Lx: any = L;

/** Runs `fn` with one library; returns a comparable outcome (value, or thrown error type). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function run(C: any, fn: (C: any) => unknown): string {
  try {
    const v = fn(C);
    if (v && typeof v === 'object' && Array.isArray((v as { words?: unknown }).words)) {
      const wa = v as { words: number[]; sigBytes: number };
      return `WA ${wa.sigBytes} ${C.enc.Hex.stringify(wa)} words=${wa.words.map((w) => w | 0).join(',')}`;
    }
    return `V ${typeof v} ${String(v)}`;
  } catch (e) {
    return `THROW ${(e as Error)?.constructor?.name}`;
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function same(fn: (C: any) => unknown): void {
  expect(run(Lx, fn)).toBe(run(R, fn));
}

/** A WordArray of `bytes` whose last word carries `garbage` beyond sigBytes. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function dirty(C: any, bytes: number[], garbage = 0xa5): any {
  const words: number[] = [];
  for (let i = 0; i < bytes.length; i++) words[i >>> 2] |= bytes[i] << (24 - (i % 4) * 8);
  const r = bytes.length % 4;
  if (r) {
    for (let i = r; i < 4; i++) words[bytes.length >>> 2] |= garbage << (24 - i * 8);
  }
  return C.lib.WordArray.create(words, bytes.length);
}

const range = (n: number, seed = 7): number[] => Array.from({ length: n }, (_, i) => (i * 31 + seed) & 0xff);
const HASHERS = ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHA3', 'RIPEMD160'];
const KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const IV_HEX = 'f0e0d0c0b0a090807060504030201000';

describe('H1: bytes beyond sigBytes leak into crypto-js padding — reproduced', () => {
  it.each(HASHERS)('%s of a dirty WordArray, lengths 0..70', (h) => {
    for (let n = 0; n <= 70; n++) same((C) => C[h](dirty(C, range(n))));
  });

  it.each(HASHERS)('%s straight from AES.decrypt (key and passphrase modes)', (h) => {
    for (let n = 0; n <= 40; n++) {
      const msg = 'x'.repeat(n);
      same((C) => {
        const key = C.enc.Hex.parse(KEY_HEX);
        const iv = C.enc.Hex.parse(IV_HEX);
        return C[h](C.AES.decrypt(C.AES.encrypt(msg, key, { iv }).toString(), key, { iv }));
      });
      const ct = R.AES.encrypt(msg, 'pass', { salt: R.enc.Hex.parse('0102030405060708') }).toString();
      same((C) => C[h](C.AES.decrypt(ct, 'pass')));
    }
  });

  it('truncated digests, WordArray.create with a short sigBytes, SHA3 output lengths', () => {
    same((C) => {
      const h = C.SHA256('abc');
      h.sigBytes = 10;
      return C.MD5(h);
    });
    same((C) => C.SHA256(C.lib.WordArray.create([0x41424344], 2)));
    for (const outputLength of [224, 256, 384, 512]) {
      same((C) => C.SHA3(dirty(C, range(13)), { outputLength }));
    }
  });

  it('HMAC with dirty messages and dirty keys longer than the block', () => {
    for (const h of HASHERS) {
      same((C) => C[`Hmac${h}`](dirty(C, range(21)), 'key'));
      same((C) => C[`Hmac${h}`]('message', dirty(C, range(150))));
      same((C) => C[`Hmac${h}`]('message', dirty(C, range(9))));
    }
  });

  it('PBKDF2 and EvpKDF with dirty passwords and salts', () => {
    for (const h of ['SHA1', 'SHA256', 'SHA512', 'MD5']) {
      same((C) => C.PBKDF2(dirty(C, range(150)), 'salt', { hasher: C.algo[h], iterations: 3, keySize: 8 }));
      same((C) => C.PBKDF2('pw', dirty(C, range(11)), { hasher: C.algo[h], iterations: 3, keySize: 8 }));
      same((C) => C.EvpKDF(dirty(C, range(7)), 'salt', { hasher: C.algo[h], keySize: 12 }));
      same((C) => C.EvpKDF('pw', dirty(C, range(7)), { hasher: C.algo[h], keySize: 12 }));
      same((C) => C.EvpKDF(dirty(C, range(7)), '', { hasher: C.algo[h], keySize: 12 }));
    }
  });

  it('progressive hashing where the last update is dirty, and where a later update clears it', () => {
    for (const h of HASHERS) {
      same((C) => C.algo[h].create().update('ab').update(dirty(C, range(5))).finalize());
      same((C) => C.algo[h].create().update(dirty(C, range(5))).update('cd').finalize());
      same((C) => C.algo[h].create().update(dirty(C, range(5))).finalize(dirty(C, range(6))));
    }
  });

  it('digest and derived-key word layout matches (SHA-224/384, SHA3-224, PBKDF2 keySize 5)', () => {
    same((C) => C.SHA224('abc'));
    same((C) => C.SHA384('abc'));
    same((C) => C.HmacSHA224('abc', 'k'));
    same((C) => C.SHA3('abc', { outputLength: 224 }));
    same((C) => C.PBKDF2('pw', 'salt', { keySize: 5, iterations: 2 }));
    same((C) => C.PBKDF2('pw', 'salt', { keySize: 7, iterations: 2, hasher: C.algo.SHA1 }));
  });
});

describe('H2: fractional sigBytes (odd-length Hex.parse)', () => {
  it('hashes, HMAC and KDFs', () => {
    for (const hex of ['a', 'abc', 'abcde', '414', '0102030']) {
      for (const h of HASHERS) same((C) => C[h](C.enc.Hex.parse(hex)));
      same((C) => C.HmacSHA256(C.enc.Hex.parse(hex), 'key'));
      same((C) => C.PBKDF2('pw', C.enc.Hex.parse(hex), { iterations: 2 }));
      same((C) => C.EvpKDF('pw', C.enc.Hex.parse(hex)));
      same((C) => C.AES.encrypt('m', 'pw', { salt: C.enc.Hex.parse(hex) }).toString());
    }
  });

  it('encoders', () => {
    for (const hex of ['a', 'abc', 'abcde', '414', '0102030', 'ffffff0']) {
      for (const e of ['Hex', 'Latin1', 'Base64', 'Base64url', 'Utf16', 'Utf16LE']) {
        same((C) => C.enc[e].stringify(C.enc.Hex.parse(hex)));
      }
      same((C) => C.enc.Utf8.stringify(C.enc.Hex.parse(hex)));
    }
  });
});

describe('M1: non-WordArray arguments behave like crypto-js', () => {
  it('Buffers and numbers', () => {
    same((C) => C.PBKDF2(Buffer.from('pw'), 'salt', { iterations: 2 }));
    same((C) => C.PBKDF2('pw', Buffer.from('salt'), { iterations: 2 }));
    same((C) => C.EvpKDF(123, 'salt'));
    same((C) => C.SHA256(Buffer.from('abc')));
    same((C) => C.MD5(Buffer.from('xyz')));
    same((C) => C.HmacSHA256(Buffer.from('abc'), 'key'));
    same((C) => C.HmacSHA256('abc', Buffer.from('key')));
  });

  it('Utf8.stringify of a string reads nothing (crypto-js returns "")', () => {
    same((C) => C.enc.Utf8.stringify('hello'));
  });
});

describe('M2: reused and modified cipher objects', () => {
  it('a second finalize() on one encryptor continues the CBC chain', () => {
    same((C) => {
      const e = C.algo.AES.createEncryptor(C.enc.Hex.parse(KEY_HEX), { iv: C.enc.Hex.parse(IV_HEX) });
      const a = e.finalize('first message');
      const b = e.finalize('second message');
      return a.toString() + ':' + b.toString();
    });
  });

  it('a second finalize() on one decryptor', () => {
    const key = R.enc.Hex.parse(KEY_HEX);
    const iv = R.enc.Hex.parse(IV_HEX);
    const ct1 = R.AES.encrypt('one', key, { iv }).ciphertext.toString();
    const ct2 = R.AES.encrypt('two', key, { iv }).ciphertext.toString();
    same((C) => {
      const d = C.algo.AES.createDecryptor(C.enc.Hex.parse(KEY_HEX), { iv: C.enc.Hex.parse(IV_HEX) });
      return d.finalize(C.enc.Hex.parse(ct1)).toString() + ':' + d.finalize(C.enc.Hex.parse(ct2)).toString();
    });
  });

  it('replacing cfg.iv after creation does not change the IV used', () => {
    same((C) => {
      const e = C.algo.AES.createEncryptor(C.enc.Hex.parse(KEY_HEX), { iv: C.enc.Hex.parse(IV_HEX) });
      e.cfg.iv = C.enc.Hex.parse('00'.repeat(16));
      return e.finalize('message');
    });
  });

  it('process() then finalize(), and reset() between messages', () => {
    for (const mode of ['CBC', 'ECB']) {
      same((C) => {
        const e = C.algo.AES.createEncryptor(C.enc.Hex.parse(KEY_HEX), { iv: C.enc.Hex.parse(IV_HEX), mode: C.mode[mode] });
        const a = e.process('0123456789abcdef0123').toString();
        const b = e.finalize('tail').toString();
        e.reset();
        return `${a}:${b}:${e.finalize('again').toString()}`;
      });
    }
  });

  it('an AES subclass that overrides encryptBlock is honoured', () => {
    same((C) => {
      const X = C.algo.AES.extend({
        encryptBlock(this: unknown, M: number[], offset: number) {
          C.algo.AES.encryptBlock.call(this, M, offset);
          M[offset] ^= 1;
        },
      });
      const helper = C.lib.BlockCipher._createHelper(X);
      return helper.encrypt('message', C.enc.Hex.parse(KEY_HEX), { iv: C.enc.Hex.parse(IV_HEX) }).toString();
    });
  });
});

describe('M3: hashers and HMAC used after finalize()', () => {
  it.each(HASHERS)('%s: finalize twice, update after finalize', (h) => {
    same((C) => {
      const x = C.algo[h].create();
      x.update('abc');
      const a = x.finalize().toString();
      const b = x.finalize().toString();
      x.update('more');
      return `${a}:${b}:${x.finalize('end').toString()}`;
    });
  });

  it('HMAC object finalize twice', () => {
    same((C) => {
      const m = C.algo.HMAC.create(C.algo.SHA256, 'key');
      return m.finalize('a').toString() + ':' + m.finalize('b').toString();
    });
  });
});

describe('L1/L2: Utf8.parse of non-strings; WordArray.random words', () => {
  it('Utf8.parse(undefined | null | number) matches', () => {
    for (const v of [undefined, null, 42]) same((C) => C.enc.Utf8.parse(v));
  });

  it('WordArray.random words are unsigned 32-bit integers, crypto-js word count', () => {
    for (const n of [0, 1, 3, 4, 5, 16, 33, 1.5, -1]) {
      const r = Lx.lib.WordArray.random(n);
      expect(r.words.length).toBe(R.lib.WordArray.random(n).words.length);
      for (const w of r.words) {
        expect(Number.isInteger(w) && w >= 0 && w <= 0xffffffff).toBe(true);
      }
    }
  });
});


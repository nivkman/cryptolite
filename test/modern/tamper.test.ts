import { describe, expect, it } from 'vitest';
import { base64UrlDecode, base64UrlEncode } from '../../src/internal/base64';
import { CryptoliteError } from '../../src/internal/errors';
import { MAX_ITERATIONS, openCl1, parseCl1, sealCl1 } from '../../src/modern/cl1';
import { getSubtle, webCryptoEngine, type Cl1Engine } from '../../src/modern/engine';
import { decrypt, decryptBytes } from '../../src/modern/index';
import { expectCode, expectCodeSync } from './helpers';

const PW = 'tamper-test-password';
const PW_BYTES = new TextEncoder().encode(PW);
const URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const OTHER_CHARS = ['.', '=', '+', '/', ' ', '\n', '\t', '\u0000', 'é', 'א', '😀'];

const web = webCryptoEngine(getSubtle()!);

/** The real Web Crypto engine, memoising PBKDF2 so thousands of tampered tokens stay fast. */
function cachingEngine(inner: Cl1Engine): Cl1Engine {
  const cache = new Map<string, Promise<Uint8Array>>();
  return {
    ...inner,
    async deriveKey(password, salt, iterations) {
      const id = `${Buffer.from(password).toString('hex')}|${Buffer.from(salt).toString('hex')}|${iterations}`;
      let p = cache.get(id);
      if (!p) cache.set(id, (p = inner.deriveKey(password, salt, iterations)));
      return (await p).slice(); // openCl1 wipes its copy
    },
  };
}

/** What public decryptBytes does for a cl1 token, but with an injectable engine. */
async function outcome(engine: Cl1Engine, token: string): Promise<string> {
  try {
    await openCl1(engine, parseCl1(token), PW_BYTES);
    return 'OK';
  } catch (err) {
    if (err instanceof CryptoliteError) return err.code;
    throw err;
  }
}

async function makeToken(plaintext = 'attack at dawn', iterations = 10_000): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return sealCl1(web, new TextEncoder().encode(plaintext), PW_BYTES, iterations, salt, iv);
}

function replaceAt(s: string, i: number, ch: string): string {
  return s.slice(0, i) + ch + s.slice(i + 1);
}

describe('strict parsing rejects non-canonical tokens (ERR_FORMAT)', () => {
  it('accepts the canonical token', async () => {
    const token = await makeToken();
    expect(await decrypt(token, PW)).toBe('attack at dawn');
  });

  it('rejects every non-canonical variant', async () => {
    const token = await makeToken();
    const [v, it, salt, iv, ct] = token.split('.') as [string, string, string, string, string];
    const join = (...p: string[]) => p.join('.');
    const variants = [
      ` ${token}`, `${token} `, `${token}\n`, `\t${token}`, // surrounding whitespace
      join(v, it, salt + '==', iv, ct), join(v, it, salt, iv + '=', ct), join(v, it, salt, iv, ct + '='), // padding
      join(v, it, salt.replace(/[A-Za-z0-9]/, '+'), iv, ct), join(v, it, salt, iv, ct.replace(/[A-Za-z0-9]/, '/')), // std alphabet
      join(v, `0${it}`, salt, iv, ct), join(v, `+${it}`, salt, iv, ct), join(v, '1e4', salt, iv, ct), // iteration syntax
      join(v, ` ${it}`, salt, iv, ct), join(v, `${it}.0`, salt, iv, ct), join(v, '0x2710', salt, iv, ct),
      join(v, it, salt, iv), join(v, it, salt, iv, ct, ''), join(v, it, salt, iv, ct, 'x'), `${token}.`, // part count
      join('CL1', it, salt, iv, ct), join('cl2', it, salt, iv, ct), join('cl1 ', it, salt, iv, ct), // version
      join(v, it, salt.slice(1), iv, ct), join(v, it, salt + 'A', iv, ct), // salt length
      join(v, it, salt, iv.slice(1), ct), join(v, it, salt, iv + 'A', ct), // iv length
      join(v, it, salt, iv, ct.slice(0, 21)), join(v, it, salt, iv, ''), // ciphertext shorter than the tag
      join(v, it, salt, iv, ct + 'A'.repeat(ct.length % 4 === 0 ? 1 : 5 - (ct.length % 4))), // impossible length
    ];
    for (const bad of variants) {
      expect(bad).not.toBe(token);
      await expectCode(() => decrypt(bad, PW), 'ERR_FORMAT');
    }
  });

  it('rejects non-zero unused bits in the final base64url character', async () => {
    const token = await makeToken();
    const [v, it, salt, iv, ct] = token.split('.') as [string, string, string, string, string];
    // 16-byte salt → 22 chars; the last char carries 2 data bits and 4 must-be-zero bits.
    const lastIdx = URL_ALPHABET.indexOf(salt[21]!);
    const nonCanonical = URL_ALPHABET[lastIdx | 1]!;
    expect(nonCanonical).not.toBe(salt[21]);
    const bad = [v, it, salt.slice(0, 21) + nonCanonical, iv, ct].join('.');
    // A lenient decoder would decode this to the very same salt and the token would decrypt.
    expect(Buffer.from(salt.slice(0, 21) + nonCanonical, 'base64url').equals(Buffer.from(salt, 'base64url'))).toBe(true);
    await expectCode(() => decrypt(bad, PW), 'ERR_FORMAT');
  });
});

describe('iteration bounds on decrypt', () => {
  it('rejects tokens below 10000 or above 10000000 without deriving a key', async () => {
    const token = await makeToken();
    const rest = token.split('.').slice(2).join('.');
    for (const it of ['9999', '1', '10000001', '99999999', '100000000', '4294967296', '9'.repeat(400)]) {
      const e = await expectCode(() => decrypt(`cl1.${it}.${rest}`, PW), 'ERR_FORMAT');
      expect(e.message).toContain('outside the accepted range');
      expect(e.message).not.toContain('Infinity');
    }
  });

  it('accepts exactly 10000 and 10000000 (the latter checked at the parser, not run)', async () => {
    const token = await makeToken('lower bound', 10_000);
    expect(await decrypt(token, PW)).toBe('lower bound');
    const rest = token.split('.').slice(2).join('.');
    expect(parseCl1(`cl1.${MAX_ITERATIONS}.${rest}`).iterations).toBe(10_000_000);
    expect(parseCl1(`cl1.10000.${rest}`).iterations).toBe(10_000);
  });
});

describe('header tampering fails authentication (ERR_DECRYPT)', () => {
  it('changing iterations, salt or iv to other valid values fails', async () => {
    const token = await makeToken();
    const other = await makeToken();
    const [v, it, salt, iv, ct] = token.split('.') as [string, string, string, string, string];
    const [, , salt2, iv2] = other.split('.') as [string, string, string, string, string];
    const tampered = [
      [v, '10001', salt, iv, ct],
      [v, '20000', salt, iv, ct],
      [v, it, salt2, iv, ct],
      [v, it, salt, iv2, ct],
      [v, it, salt2, iv2, ct],
    ];
    for (const parts of tampered) await expectCode(() => decrypt(parts.join('.'), PW), 'ERR_DECRYPT');
  });

  it('flipping any bit of the decoded salt, iv or ciphertext‖tag fails', async () => {
    const engine = cachingEngine(web);
    const token = await makeToken();
    const parts = token.split('.') as [string, string, string, string, string];
    const checks: Array<Promise<void>> = [];
    for (const partIndex of [2, 3, 4]) {
      const bytes = base64UrlDecode(parts[partIndex]!);
      for (let i = 0; i < bytes.length; i++) {
        for (let bit = 0; bit < 8; bit++) {
          const copy = bytes.slice();
          copy[i]! ^= 1 << bit;
          const p = parts.slice();
          p[partIndex] = base64UrlEncode(copy);
          checks.push(outcome(engine, p.join('.')).then((r) => expect(r, `part ${partIndex} byte ${i} bit ${bit}`).toBe('ERR_DECRYPT')));
        }
      }
    }
    await Promise.all(checks);
    expect(checks.length).toBe((16 + 12 + 14 + 16) * 8);
  }, 60_000);
});

describe('every single-character tamper is rejected', () => {
  it('substituting every position with every alphabet and non-alphabet character → ERR_DECRYPT or ERR_FORMAT', async () => {
    const engine = cachingEngine(web);
    const token = await makeToken();
    expect(await outcome(engine, token)).toBe('OK');
    const results = new Map<string, number>();
    const pending: Array<Promise<void>> = [];
    let count = 0;
    const check = (t: string) => {
      count++;
      pending.push(
        outcome(engine, t).then((r) => {
          if (r !== 'ERR_DECRYPT' && r !== 'ERR_FORMAT') throw new Error(`tampered token ${JSON.stringify(t)} gave ${r}`);
          results.set(r, (results.get(r) ?? 0) + 1);
        }),
      );
    };
    for (let i = 0; i < token.length; i++) {
      for (const ch of [...URL_ALPHABET, ...OTHER_CHARS, ...'cl'.split('')]) {
        if (ch !== token[i]) check(replaceAt(token, i, ch));
      }
      check(token.slice(0, i) + token.slice(i + 1)); // deletion
      check(token.slice(0, i) + 'A' + token.slice(i)); // insertion
      check(token.slice(0, i)); // truncation
    }
    check(token + 'A');
    check(token + '.');
    // Run concurrently: Web Crypto PBKDF2 (for salt/iteration tampers) uses the libuv thread pool.
    await Promise.all(pending);
    expect(count).toBeGreaterThan(token.length * 70);
    expect(results.get('ERR_DECRYPT')).toBeGreaterThan(1000); // most tampers reach authentication
    expect(results.get('ERR_FORMAT')).toBeGreaterThan(100);
  }, 120_000);

  it('the public decrypt() agrees on one substitution per position', async () => {
    const token = await makeToken();
    for (let i = 0; i < token.length; i++) {
      const ch = token[i] === 'A' ? 'B' : 'A';
      let err: unknown;
      try {
        await decryptBytes(replaceAt(token, i, ch), PW);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(CryptoliteError);
      expect(['ERR_DECRYPT', 'ERR_FORMAT']).toContain((err as CryptoliteError).code);
    }
  }, 60_000);
});

describe('internal sealCl1 guards', () => {
  it('refuses parameters that would produce an unparseable token', async () => {
    const salt = new Uint8Array(16);
    const iv = new Uint8Array(12);
    const pt = new Uint8Array(1);
    for (const [it, s, v] of [
      [9_999, salt, iv],
      [10_000_001, salt, iv],
      [10_000.5, salt, iv],
      [10_000, new Uint8Array(15), iv],
      [10_000, salt, new Uint8Array(16)],
    ] as const) {
      await expectCode(() => sealCl1(web, pt, PW_BYTES, it, s, v), 'ERR_PARAMS');
    }
    expectCodeSync(() => parseCl1('cl1.10000.x.y.z'), 'ERR_FORMAT');
  });
});

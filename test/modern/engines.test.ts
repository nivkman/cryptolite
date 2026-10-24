import { createCipheriv, pbkdf2Sync } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { openCl1, parseCl1, sealCl1 } from '../../src/modern/cl1';
import { getSubtle, nobleEngine, platformEngine, webCryptoEngine, type SubtleLike } from '../../src/modern/engine';
import { decrypt, decryptBytes, encrypt, upgrade } from '../../src/modern/index';
import { expectCode, prng, randBytes, randInt, randString } from './helpers';

const realCrypto = globalThis.crypto;
const realSubtle = getSubtle()!;
const web = webCryptoEngine(realSubtle);
const utf8 = (s: string) => new Uint8Array(Buffer.from(s, 'utf8'));

afterEach(() => {
  vi.unstubAllGlobals();
});

/** node:crypto reference token for fixed inputs, independent of both engines. */
function referenceToken(pt: Uint8Array, pw: string, iterations: number, salt: Uint8Array, iv: Uint8Array): string {
  const header = `cl1.${iterations}.${Buffer.from(salt).toString('base64url')}.${Buffer.from(iv).toString('base64url')}`;
  const key = pbkdf2Sync(Buffer.from(pw, 'utf8'), salt, iterations, 32, 'sha256');
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(header));
  return `${header}.${Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]).toString('base64url')}`;
}

describe('Web Crypto and noble engines are interchangeable', () => {
  it('Node exposes a complete crypto.subtle (so the Web Crypto path is really exercised)', () => {
    expect(getSubtle()).toBeDefined();
    expect(platformEngine().name).toBe('webcrypto');
  });

  it('produce byte-identical tokens for fixed salt/iv, equal to a node:crypto reference', async () => {
    const rand = prng(30);
    const lengths = [0, 1, 15, 16, 17, 31, 32, 33, 1000, 65_536 + 3];
    for (let i = 0; i < lengths.length; i++) {
      const pt = randBytes(rand, lengths[i]!);
      const pwText = i % 2 === 0 ? `pw-${i}` : randString(rand, 12) || 'x';
      const pw = utf8(pwText);
      const salt = randBytes(rand, 16);
      const iv = randBytes(rand, 12);
      const iterations = 10_000 + randInt(rand, 0, 5000);
      const a = await sealCl1(web, pt, pw, iterations, salt, iv);
      const b = await sealCl1(nobleEngine, pt, pw, iterations, salt, iv);
      expect(a).toBe(b);
      expect(a).toBe(referenceToken(pt, pwText, iterations, salt, iv));
      // Each opens the other's output.
      expect(await openCl1(nobleEngine, parseCl1(a), pw)).toEqual(pt);
      expect(await openCl1(web, parseCl1(b), pw)).toEqual(pt);
    }
  }, 60_000);

  it('both reject the same wrong password and tampering with ERR_DECRYPT', async () => {
    const pt = utf8('same failures');
    const salt = new Uint8Array(16).fill(7);
    const iv = new Uint8Array(12).fill(9);
    const token = await sealCl1(web, pt, utf8('right'), 10_000, salt, iv);
    const tampered = token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A');
    for (const engine of [web, nobleEngine]) {
      await expectCode(() => openCl1(engine, parseCl1(token), utf8('wrong')), 'ERR_DECRYPT');
      await expectCode(() => openCl1(engine, parseCl1(tampered), utf8('right')), 'ERR_DECRYPT');
    }
  });

  it('the AAD is the header: opening with a different AAD fails on both engines', async () => {
    const key = new Uint8Array(32).fill(1);
    const iv = new Uint8Array(12).fill(2);
    for (const engine of [web, nobleEngine]) {
      const sealed = await engine.seal(key, iv, utf8('cl1.10000.a.b'), utf8('payload'));
      await expect(engine.open(key, iv, utf8('cl1.10001.a.b'), sealed)).rejects.toThrow();
      expect(await engine.open(key, iv, utf8('cl1.10000.a.b'), sealed)).toEqual(utf8('payload'));
    }
  });
});

describe('platform engine selection and fallback', () => {
  it('uses noble when crypto.subtle is missing (React Native), and tokens interoperate', async () => {
    vi.stubGlobal('crypto', { getRandomValues: realCrypto.getRandomValues.bind(realCrypto) });
    expect(getSubtle()).toBeUndefined();
    expect(platformEngine().name).toBe('noble');
    const token = await encrypt('made by noble', 'pw', { iterations: 100_000 });
    expect(await decrypt(token, 'pw')).toBe('made by noble');
    await expectCode(() => decrypt(token, 'wrong'), 'ERR_DECRYPT');
    vi.unstubAllGlobals();
    expect(platformEngine().name).toBe('webcrypto');
    expect(await decrypt(token, 'pw')).toBe('made by noble'); // opened by Web Crypto
    const back = await encrypt('made by web crypto', 'pw', { iterations: 100_000 });
    vi.stubGlobal('crypto', { getRandomValues: realCrypto.getRandomValues.bind(realCrypto) });
    expect(await decrypt(back, 'pw')).toBe('made by web crypto'); // opened by noble
  }, 30_000);

  it('treats a partial subtle (missing a method) as absent', () => {
    const partial = { importKey: realSubtle.importKey.bind(realSubtle), deriveBits: realSubtle.deriveBits.bind(realSubtle) };
    vi.stubGlobal('crypto', { getRandomValues: realCrypto.getRandomValues.bind(realCrypto), subtle: partial });
    expect(getSubtle()).toBeUndefined();
    expect(platformEngine().name).toBe('noble');
  });

  it('falls back to noble when Web Crypto rejects PBKDF2 parameters (e.g. an iteration cap)', async () => {
    let rejected = 0;
    const capped: SubtleLike = {
      importKey: (...a) => realSubtle.importKey(...a),
      deriveBits: async (alg, key, len) => {
        if (alg.iterations > 50_000) {
          rejected++;
          throw new DOMException('iteration counts above 50000 are not supported', 'NotSupportedError');
        }
        return realSubtle.deriveBits(alg, key, len);
      },
      encrypt: (...a) => realSubtle.encrypt(...a),
      decrypt: (...a) => realSubtle.decrypt(...a),
    };
    vi.stubGlobal('crypto', { getRandomValues: realCrypto.getRandomValues.bind(realCrypto), subtle: capped });
    const token = await encrypt('capped runtime', 'pw', { iterations: 100_000 });
    expect(await decrypt(token, 'pw')).toBe('capped runtime');
    await expectCode(() => decrypt(token, 'wrong'), 'ERR_DECRYPT');
    expect(rejected).toBe(3); // every derivation hit the cap and was retried in noble
    vi.unstubAllGlobals();
    expect(await decrypt(token, 'pw')).toBe('capped runtime');
  }, 30_000);

  it('falls back to noble when Web Crypto AES-GCM throws, without masking real failures', async () => {
    const broken: SubtleLike = {
      importKey: (...a) => realSubtle.importKey(...a),
      deriveBits: (...a) => realSubtle.deriveBits(...a),
      encrypt: async () => {
        throw new DOMException('not supported', 'NotSupportedError');
      },
      decrypt: async () => {
        throw new DOMException('not supported', 'NotSupportedError');
      },
    };
    vi.stubGlobal('crypto', { getRandomValues: realCrypto.getRandomValues.bind(realCrypto), subtle: broken });
    const token = await encrypt(new Uint8Array([1, 2, 3]), 'pw', { iterations: 100_000 });
    expect(await decryptBytes(token, 'pw')).toEqual(new Uint8Array([1, 2, 3]));
    await expectCode(() => decrypt(token, 'nope'), 'ERR_DECRYPT');
    const upgraded = await upgrade(token, 'pw', { iterations: 100_000 });
    vi.unstubAllGlobals();
    expect(await decryptBytes(upgraded, 'pw')).toEqual(new Uint8Array([1, 2, 3]));
  }, 30_000);
});

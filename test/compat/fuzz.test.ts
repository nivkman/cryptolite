/*
 * Heavy fuzz coverage, off by default to keep `npx vitest run test/compat` fast (< ~30s).
 * Run explicitly with: FUZZ=1 npx vitest run test/compat/fuzz.test.ts
 *
 * Deterministic: seeded by SEED (see ./_util), which FUZZ=1 picks fresh via node:crypto unless
 * SEED is also set — the resolved seed is always printed, so a failure found here is
 * reproducible with `SEED=<value> FUZZ=1 npx vitest run test/compat/fuzz.test.ts`.
 */
import { describe, expect, it } from 'vitest';
import CryptoJS from '../../src/compat/index';
import { FUZZ, RefCryptoJS, avoidZeroPaddingTrap, prngBytes, prngString, randInt } from './_util';

const libs = { cryptolite: CryptoJS, 'crypto-js': RefCryptoJS } as const;
const libEntries = Object.entries(libs);

const describeFuzz = FUZZ ? describe : describe.skip;

describeFuzz('FUZZ=1 — AES key-mode matrix, many random trials per combo', () => {
  const KEY_SIZES_BYTES = [16, 24, 32];
  const MODES = ['CBC', 'CFB', 'CTR', 'CTRGladman', 'OFB', 'ECB'] as const;
  const PADDINGS = ['Pkcs7', 'AnsiX923', 'Iso97971', 'ZeroPadding'] as const;
  const TRIALS_PER_COMBO = 8;

  for (const keySizeBytes of KEY_SIZES_BYTES) {
    for (const mode of MODES) {
      for (const padding of PADDINGS) {
        it(`key=${keySizeBytes * 8}-bit mode=${mode} padding=${padding}: ${TRIALS_PER_COMBO} random messages`, () => {
          for (let i = 0; i < TRIALS_PER_COMBO; i++) {
            const key = prngBytes(keySizeBytes);
            const iv = prngBytes(16);
            // ZeroPadding cannot distinguish a real trailing 0x00 byte from padding (see
            // avoidZeroPaddingTrap) — not a cryptolite bug, so trials avoid that trap byte.
            const rawMessage = prngString(randInt(0, 300));
            const message = padding === 'ZeroPadding' ? avoidZeroPaddingTrap(rawMessage) : rawMessage;
            const outputs = libEntries.map(([, CJS]) => {
              const cfg = {
                mode: CJS.mode[mode],
                padding: CJS.pad[padding],
                iv: CJS.lib.WordArray.create(iv),
              };
              const ct = CJS.AES.encrypt(message, CJS.lib.WordArray.create(key), cfg);
              const pt = CJS.AES.decrypt(ct, CJS.lib.WordArray.create(key), cfg);
              return { ciphertextHex: ct.ciphertext.toString(), plaintext: pt.toString(CJS.enc.Utf8) };
            });
            expect(outputs[0]).toEqual(outputs[1]);
            expect(outputs[0].plaintext).toBe(message);
          }
        });
      }
    }
  }
});

describeFuzz('FUZZ=1 — WordArray stress: many random concats/clamps/clones', () => {
  it('a long chain of random-length concats matches crypto-js byte for byte', () => {
    for (let trial = 0; trial < 20; trial++) {
      const chunks: Uint8Array[] = [];
      const chunkCount = randInt(2, 12);
      for (let i = 0; i < chunkCount; i++) chunks.push(prngBytes(randInt(0, 40)));

      const outputs = libEntries.map(([, CJS]) => {
        let wa = CJS.lib.WordArray.create();
        for (const chunk of chunks) wa = wa.concat(CJS.lib.WordArray.create(chunk));
        return wa.toString();
      });
      expect(outputs[0]).toBe(outputs[1]);
    }
  });

  it('clone-then-diverge never lets the clone see later mutations', () => {
    for (let trial = 0; trial < 20; trial++) {
      const base = prngBytes(randInt(1, 50));
      const extra = prngBytes(randInt(1, 50));
      const outputs = libEntries.map(([, CJS]) => {
        const wa = CJS.lib.WordArray.create(base);
        const clone = wa.clone();
        wa.concat(CJS.lib.WordArray.create(extra));
        return { original: wa.toString(), clone: clone.toString() };
      });
      expect(outputs[0]).toEqual(outputs[1]);
    }
  });
});

describeFuzz('FUZZ=1 — PBKDF2/EvpKDF over a wide random parameter sweep', () => {
  const HASHERS = ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHA3', 'RIPEMD160'] as const;

  it('PBKDF2: random hasher/iterations/keySize/password/salt, 30 trials', () => {
    for (let i = 0; i < 30; i++) {
      const hasherName = HASHERS[randInt(0, HASHERS.length - 1)];
      const iterations = randInt(1, 500);
      const keySize = randInt(1, 16);
      const password = prngString(randInt(0, 40));
      const salt = prngBytes(randInt(0, 32));
      const outputs = libEntries.map(([, CJS]) =>
        CJS.PBKDF2(password, CJS.lib.WordArray.create(salt), {
          hasher: CJS.algo[hasherName],
          iterations,
          keySize,
        }).toString(),
      );
      expect(outputs[0]).toBe(outputs[1]);
    }
  });

  it('EvpKDF: random hasher/iterations/keySize/password/salt, 30 trials', () => {
    for (let i = 0; i < 30; i++) {
      const hasherName = HASHERS[randInt(0, HASHERS.length - 1)];
      const iterations = randInt(1, 20);
      const keySize = randInt(1, 16);
      const password = prngString(randInt(0, 40));
      const salt = prngBytes(randInt(0, 32));
      const outputs = libEntries.map(([, CJS]) =>
        CJS.EvpKDF(password, CJS.lib.WordArray.create(salt), {
          hasher: CJS.algo[hasherName],
          iterations,
          keySize,
        }).toString(),
      );
      expect(outputs[0]).toBe(outputs[1]);
    }
  });
});

describeFuzz('FUZZ=1 — HMAC over a wide range of key lengths', () => {
  const HELPERS = [
    'HmacMD5',
    'HmacSHA1',
    'HmacSHA224',
    'HmacSHA256',
    'HmacSHA384',
    'HmacSHA512',
    'HmacSHA3',
    'HmacRIPEMD160',
  ] as const;

  it('random key length 0..300, random message length 0..300, 40 trials', () => {
    for (let i = 0; i < 40; i++) {
      const helper = HELPERS[randInt(0, HELPERS.length - 1)];
      const key = prngString(randInt(0, 300));
      const message = prngString(randInt(0, 300));
      const outputs = libEntries.map(([, CJS]) => CJS[helper](message, key).toString());
      expect(outputs[0]).toBe(outputs[1]);
    }
  });
});

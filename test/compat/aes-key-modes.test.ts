import { describe, expect, it } from 'vitest';
import CryptoJS from '../../src/compat/index';
import { RefCryptoJS, avoidZeroPaddingTrap, bytesToHex, prngBytes, prngString, wordArrayToBytes } from './_util';

const libs = { cryptolite: CryptoJS, 'crypto-js': RefCryptoJS } as const;
const libEntries = Object.entries(libs);

const KEY_SIZES_BYTES = [16, 24, 32];
const MODES = ['CBC', 'CFB', 'CTR', 'CTRGladman', 'OFB', 'ECB'] as const;
// Padding names that produce fully deterministic ciphertext (no internal randomness).
const DETERMINISTIC_PADDINGS = ['Pkcs7', 'AnsiX923', 'Iso97971', 'ZeroPadding'] as const;
const RANDOM_PADDING = 'Iso10126'; // random padding bytes: decrypt-interop only, per spec.

function sameBytesConfig(keySizeBytes: number) {
  const key = prngBytes(keySizeBytes);
  const iv = prngBytes(16);
  return { key, iv };
}

describe('AES key mode — exact ciphertext matrix (deterministic paddings)', () => {
  for (const keySizeBytes of KEY_SIZES_BYTES) {
    for (const mode of MODES) {
      for (const padding of DETERMINISTIC_PADDINGS) {
        it(`key=${keySizeBytes * 8}-bit, mode=${mode}, padding=${padding}`, () => {
          const { key, iv } = sameBytesConfig(keySizeBytes);
          // Deliberately not a multiple of the block size. ZeroPadding cannot distinguish a real
          // trailing 0x00 byte from padding (see avoidZeroPaddingTrap) — not a cryptolite bug.
          const message =
            padding === 'ZeroPadding' ? avoidZeroPaddingTrap(prngString(37)) : prngString(37);
          const outputs = libEntries.map(([, CJS]) => {
            const cfg = { mode: CJS.mode[mode], padding: CJS.pad[padding], iv: CJS.lib.WordArray.create(iv) };
            const ct = CJS.AES.encrypt(message, CJS.lib.WordArray.create(key), cfg);
            const pt = CJS.AES.decrypt(ct, CJS.lib.WordArray.create(key), cfg);
            return { ciphertextHex: ct.ciphertext.toString(), plaintext: pt.toString(CJS.enc.Utf8) };
          });
          expect(outputs[0]).toEqual(outputs[1]);
          expect(outputs[0].plaintext).toBe(message);
        });
      }
    }
  }
});

describe('AES key mode — NoPadding (valid block-aligned lengths only)', () => {
  for (const keySizeBytes of KEY_SIZES_BYTES) {
    for (const mode of MODES) {
      it(`key=${keySizeBytes * 8}-bit, mode=${mode}, padding=NoPadding`, () => {
        const { key, iv } = sameBytesConfig(keySizeBytes);
        const messageBytes = prngBytes(32); // 2 full 16-byte blocks
        const outputs = libEntries.map(([, CJS]) => {
          const cfg = { mode: CJS.mode[mode], padding: CJS.pad.NoPadding, iv: CJS.lib.WordArray.create(iv) };
          const ct = CJS.AES.encrypt(CJS.lib.WordArray.create(messageBytes), CJS.lib.WordArray.create(key), cfg);
          const pt = CJS.AES.decrypt(ct, CJS.lib.WordArray.create(key), cfg);
          return { ciphertextHex: ct.ciphertext.toString(), plaintextHex: pt.toString() };
        });
        expect(outputs[0]).toEqual(outputs[1]);
        expect(outputs[0].plaintextHex).toBe(bytesToHex(messageBytes));
      });
    }
  }
});

describe('AES key mode — Iso10126 (random padding): decrypt interop only', () => {
  for (const keySizeBytes of KEY_SIZES_BYTES) {
    for (const mode of MODES) {
      it(`key=${keySizeBytes * 8}-bit, mode=${mode}: ciphertext made by either library decrypts correctly on the other`, () => {
        const { key, iv } = sameBytesConfig(keySizeBytes);
        const message = prngString(29);
        for (const [, EncLib] of libEntries) {
          const cfgEnc = {
            mode: EncLib.mode[mode],
            padding: EncLib.pad[RANDOM_PADDING],
            iv: EncLib.lib.WordArray.create(iv),
          };
          const ct = EncLib.AES.encrypt(message, EncLib.lib.WordArray.create(key), cfgEnc);
          for (const [, DecLib] of libEntries) {
            const cfgDec = {
              mode: DecLib.mode[mode],
              padding: DecLib.pad[RANDOM_PADDING],
              iv: DecLib.lib.WordArray.create(iv),
            };
            const pt = DecLib.AES.decrypt(ct.toString(), DecLib.lib.WordArray.create(key), cfgDec);
            expect(pt.toString(DecLib.enc.Utf8)).toBe(message);
          }
        }
      });
    }
  }
});

describe('AES — CipherParams fields', () => {
  it('ciphertext, key, iv, algorithm, mode, padding, blockSize, formatter are all populated consistently', () => {
    const keyBytes = prngBytes(16);
    const ivBytes = prngBytes(16);
    for (const [, CJS] of libEntries) {
      const key = CJS.lib.WordArray.create(keyBytes);
      const iv = CJS.lib.WordArray.create(ivBytes);
      const ct = CJS.AES.encrypt('cipher params test', key, { iv });
      expect(ct.ciphertext).toBeTruthy();
      expect(ct.key).toBe(key);
      expect(ct.iv.toString()).toBe(iv.toString());
      expect(ct.algorithm).toBe(CJS.algo.AES);
      expect(ct.mode).toBe(CJS.mode.CBC);
      expect(ct.padding).toBe(CJS.pad.Pkcs7);
      expect(ct.blockSize).toBe(4);
      expect(ct.formatter).toBe(CJS.format.OpenSSL);
    }
  });

  it('toString() with OpenSSL (default) and Hex formatters matches crypto-js', () => {
    const keyBytes = prngBytes(16);
    const ivBytes = prngBytes(16);
    const outputs = libEntries.map(([, CJS]) => {
      const key = CJS.lib.WordArray.create(keyBytes);
      const iv = CJS.lib.WordArray.create(ivBytes);
      const ct = CJS.AES.encrypt('formatter test message', key, { iv });
      return {
        openssl: ct.toString(),
        openSSLExplicit: ct.toString(CJS.format.OpenSSL),
        hex: ct.toString(CJS.format.Hex),
      };
    });
    expect(outputs[0]).toEqual(outputs[1]);
  });

  it('decrypting a CipherParams object behaves the same as decrypting its string form', () => {
    const keyBytes = prngBytes(16);
    const ivBytes = prngBytes(16);
    for (const [, CJS] of libEntries) {
      const key = CJS.lib.WordArray.create(keyBytes);
      const iv = CJS.lib.WordArray.create(ivBytes);
      const ct = CJS.AES.encrypt('cipher params object vs string', key, { iv });

      const fromObject = CJS.AES.decrypt(ct, key, { iv }).toString(CJS.enc.Utf8);
      const fromString = CJS.AES.decrypt(ct.toString(), key, { iv }).toString(CJS.enc.Utf8);
      expect(fromObject).toBe('cipher params object vs string');
      expect(fromString).toBe('cipher params object vs string');
    }
  });
});

describe('AES — progressive createEncryptor API', () => {
  it('CryptoJS.algo.AES.createEncryptor(key, cfg).process(...).finalize() matches one-shot encrypt', () => {
    const keyBytes = prngBytes(32);
    const ivBytes = prngBytes(16);
    const message = prngString(50);

    const outputs = libEntries.map(([, CJS]) => {
      const key = CJS.lib.WordArray.create(keyBytes);
      const iv = CJS.lib.WordArray.create(ivBytes);
      const encryptor = CJS.algo.AES.createEncryptor(key, { iv });
      const part1 = encryptor.process(message.slice(0, 20));
      const part2 = encryptor.process(message.slice(20, 35));
      const part3 = encryptor.finalize(message.slice(35));
      const progressive = part1.concat(part2).concat(part3);

      const oneShot = CJS.AES.encrypt(message, key, { iv });
      return { progressiveHex: progressive.toString(), oneShotHex: oneShot.ciphertext.toString() };
    });
    expect(outputs[0]).toEqual(outputs[1]);
    expect(outputs[0].progressiveHex).toBe(outputs[0].oneShotHex);
  });

  it('createDecryptor progressive matches one-shot decrypt', () => {
    const keyBytes = prngBytes(24);
    const ivBytes = prngBytes(16);
    const message = prngString(64);

    const outputs = libEntries.map(([, CJS]) => {
      const key = CJS.lib.WordArray.create(keyBytes);
      const iv = CJS.lib.WordArray.create(ivBytes);
      const ct = CJS.AES.encrypt(message, key, { iv });
      const ctBytes = wordArrayToBytes(ct.ciphertext);

      const decryptor = CJS.algo.AES.createDecryptor(key, { iv });
      const half = Math.floor(ctBytes.length / 2);
      const p1 = decryptor.process(CJS.lib.WordArray.create(ctBytes.slice(0, half)));
      const p2 = decryptor.finalize(CJS.lib.WordArray.create(ctBytes.slice(half)));
      return p1.concat(p2).toString(CJS.enc.Utf8);
    });
    expect(outputs[0]).toBe(outputs[1]);
    expect(outputs[0]).toBe(message);
  });
});

describe('AES — wrong-key decrypt behaviour is bit-identical (garbage in, garbage out)', () => {
  it('decrypting with the wrong key produces the same garbage bytes on both libraries (Pkcs7)', () => {
    const correctKey = prngBytes(16);
    const wrongKey = prngBytes(16);
    const ivBytes = prngBytes(16);
    const message = prngString(45);

    const outputs = libEntries.map(([, CJS]) => {
      const iv = CJS.lib.WordArray.create(ivBytes);
      const ct = CJS.AES.encrypt(message, CJS.lib.WordArray.create(correctKey), { iv });
      const decrypted = CJS.AES.decrypt(ct, CJS.lib.WordArray.create(wrongKey), { iv });
      return { hex: decrypted.toString(), sigBytes: decrypted.sigBytes };
    });
    expect(outputs[0]).toEqual(outputs[1]);
  });

  it('wrong-key garbage that is not valid UTF-8 throws the identical message on both libraries', () => {
    const correctKey = prngBytes(16);
    const wrongKey = prngBytes(16);
    const ivBytes = prngBytes(16);
    const message = prngString(45);

    const messages = libEntries.map(([, CJS]) => {
      const iv = CJS.lib.WordArray.create(ivBytes);
      const ct = CJS.AES.encrypt(message, CJS.lib.WordArray.create(correctKey), { iv });
      const decrypted = CJS.AES.decrypt(ct, CJS.lib.WordArray.create(wrongKey), { iv });
      try {
        decrypted.toString(CJS.enc.Utf8);
        return null;
      } catch (e) {
        return (e as Error).message;
      }
    });
    // Either both throw the same message, or both happen to decode (exceedingly unlikely with
    // real AES garbage, but assert equality either way so the test isn't flaky-looking).
    expect(messages[0]).toBe(messages[1]);
  });
});

describe('AES — CTR counter wrap behaviour', () => {
  it('CTR: IV ending in ffffffff wraps the last 32-bit word with no carry into earlier words', () => {
    const keyBytes = prngBytes(16);
    // IV whose last word is 0xffffffff: the first block consumes it, the second block's counter
    // increment must wrap 0xffffffff -> 0x00000000 in that word only (crypto-js CTR quirk).
    const ivWords = [0x00000000, 0x00000000, 0x00000000, 0xffffffff];
    const message = prngBytes(48); // 3 blocks: exercises the wrap on block 2.

    const outputs = libEntries.map(([, CJS]) => {
      const key = CJS.lib.WordArray.create(keyBytes);
      const iv = CJS.lib.WordArray.create(ivWords, 16);
      const ct = CJS.AES.encrypt(CJS.lib.WordArray.create(message), key, {
        mode: CJS.mode.CTR,
        padding: CJS.pad.NoPadding,
        iv,
      });
      return ct.ciphertext.toString();
    });
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('CTRGladman: IV ending in ffffffff cascades the carry into byte-reversed earlier bytes', () => {
    const keyBytes = prngBytes(16);
    const ivWords = [0x00000000, 0x00000000, 0x00000000, 0xffffffff];
    const message = prngBytes(48);

    const outputs = libEntries.map(([, CJS]) => {
      const key = CJS.lib.WordArray.create(keyBytes);
      const iv = CJS.lib.WordArray.create(ivWords, 16);
      const ct = CJS.AES.encrypt(CJS.lib.WordArray.create(message), key, {
        mode: CJS.mode.CTRGladman,
        padding: CJS.pad.NoPadding,
        iv,
      });
      return ct.ciphertext.toString();
    });
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('CTRGladman: IV ending in 0xffffffff in the second-to-last word also wraps correctly', () => {
    const keyBytes = prngBytes(24);
    const ivWords = [0x00000000, 0x00000000, 0xffffffff, 0xffffffff];
    const message = prngBytes(64);

    const outputs = libEntries.map(([, CJS]) => {
      const key = CJS.lib.WordArray.create(keyBytes);
      const iv = CJS.lib.WordArray.create(ivWords, 16);
      const ct = CJS.AES.encrypt(CJS.lib.WordArray.create(message), key, {
        mode: CJS.mode.CTRGladman,
        padding: CJS.pad.NoPadding,
        iv,
      });
      return ct.ciphertext.toString();
    });
    expect(outputs[0]).toBe(outputs[1]);
  });
});

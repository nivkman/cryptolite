import { describe, expect, it } from 'vitest';
import CryptoJS from '../../src/compat/index';
import { RefCryptoJS, prngBytes, prngString, randInt } from './_util';

const libs = { cryptolite: CryptoJS, 'crypto-js': RefCryptoJS } as const;
const libEntries = Object.entries(libs);

type HmacHelperName =
  | 'HmacMD5'
  | 'HmacSHA1'
  | 'HmacSHA224'
  | 'HmacSHA256'
  | 'HmacSHA384'
  | 'HmacSHA512'
  | 'HmacSHA3'
  | 'HmacRIPEMD160';

type AlgoName = 'MD5' | 'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512' | 'SHA3' | 'RIPEMD160';

// blockSize in 32-bit words for each hasher (used to pick shorter/equal/longer-than-block keys).
// SHA3's default (outputLength 512) has a rate-derived blockSize of 18 words (72 bytes).
const HELPERS: Array<{ helper: HmacHelperName; algo: AlgoName; blockWords: number }> = [
  { helper: 'HmacMD5', algo: 'MD5', blockWords: 16 },
  { helper: 'HmacSHA1', algo: 'SHA1', blockWords: 16 },
  { helper: 'HmacSHA224', algo: 'SHA224', blockWords: 16 },
  { helper: 'HmacSHA256', algo: 'SHA256', blockWords: 16 },
  { helper: 'HmacSHA384', algo: 'SHA384', blockWords: 32 },
  { helper: 'HmacSHA512', algo: 'SHA512', blockWords: 32 },
  { helper: 'HmacSHA3', algo: 'SHA3', blockWords: 18 },
  { helper: 'HmacRIPEMD160', algo: 'RIPEMD160', blockWords: 16 },
];

describe.each(HELPERS)('$helper', ({ helper, algo, blockWords }) => {
  const blockBytes = blockWords * 4;

  it.each([
    ['shorter than block size', blockBytes - 5],
    ['equal to block size', blockBytes],
    ['longer than block size', blockBytes + 17],
  ] as const)('%s key, string key and message', (_label, keyLen) => {
    const key = prngString(keyLen);
    const message = prngString(randInt(0, 200));
    const outputs = libEntries.map(([, CJS]) => CJS[helper](message, key).toString());
    expect(outputs[0]).toBe(outputs[1]);
  });

  it.each([
    ['shorter than block size', blockBytes - 5],
    ['equal to block size', blockBytes],
    ['longer than block size', blockBytes + 17],
  ] as const)('%s key, WordArray key and message', (_label, keyLen) => {
    const keyBytes = prngBytes(keyLen);
    const msgBytes = prngBytes(randInt(0, 200));
    const outputs = libEntries.map(([, CJS]) =>
      CJS[helper](CJS.lib.WordArray.create(msgBytes), CJS.lib.WordArray.create(keyBytes)).toString(),
    );
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('CryptoJS.algo.HMAC.create(hasher, key) — progressive update/finalize matches the helper', () => {
    const key = prngString(blockBytes + 3);
    const message = prngString(120);
    const split = randInt(1, 119);

    const progressive = libEntries.map(([, CJS]) => {
      const hmac = CJS.algo.HMAC.create(CJS.algo[algo], key);
      hmac.update(message.slice(0, split));
      return hmac.finalize(message.slice(split)).toString();
    });
    expect(progressive[0]).toBe(progressive[1]);

    const oneShot = libEntries.map(([, CJS]) => CJS[helper](message, key).toString());
    expect(progressive[0]).toBe(oneShot[0]);
  });

  it('CryptoJS.algo.HMAC.create — reset() replays from the inner-key state', () => {
    const key = prngString(blockBytes - 1);
    const messageA = prngString(50);
    const messageB = prngString(70);

    const outputs = libEntries.map(([, CJS]) => {
      const hmac = CJS.algo.HMAC.create(CJS.algo[algo], key);
      hmac.update(messageA);
      hmac.reset();
      return hmac.finalize(messageB).toString();
    });
    expect(outputs[0]).toBe(outputs[1]);

    const direct = libEntries.map(([, CJS]) => CJS[helper](messageB, key).toString());
    expect(outputs[0]).toBe(direct[0]);
  });
});

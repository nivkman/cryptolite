import { describe, expect, it } from 'vitest';
import CryptoJS from '../../src/compat/index';
import { FULL_LENGTHS, FUZZ, RefCryptoJS, SAMPLE_LENGTHS, prngBytes, randInt } from './_util';

const libs = { cryptolite: CryptoJS, 'crypto-js': RefCryptoJS } as const;
const libEntries = Object.entries(libs);

type HelperName =
  | 'MD5'
  | 'SHA1'
  | 'SHA224'
  | 'SHA256'
  | 'SHA384'
  | 'SHA512'
  | 'RIPEMD160';

const SIMPLE_HELPERS: HelperName[] = ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'RIPEMD160'];

const LENGTHS = FUZZ ? FULL_LENGTHS : SAMPLE_LENGTHS;

describe.each(SIMPLE_HELPERS)('%s helper', (name) => {
  it.each(LENGTHS)('matches crypto-js for random string input of length %i', (len) => {
    const s = Array.from(prngBytes(len), (b) => String.fromCharCode(b)).join('');
    const outputs = libEntries.map(([, CJS]) => CJS[name](s).toString());
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('matches crypto-js for a random WordArray input', () => {
    const bytes = prngBytes(randInt(0, 300));
    const outputs = libEntries.map(([, CJS]) => CJS[name](CJS.lib.WordArray.create(bytes)).toString());
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('matches crypto-js on a large input (100000 bytes)', () => {
    const bytes = prngBytes(100_000);
    const outputs = libEntries.map(([, CJS]) => CJS[name](CJS.lib.WordArray.create(bytes)).toString());
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('progressive update/finalize at random split points matches a single-shot digest', () => {
    const bytes = prngBytes(randInt(50, 300));
    const splitCount = randInt(1, 5);
    const splits: number[] = [];
    for (let i = 0; i < splitCount; i++) splits.push(randInt(0, bytes.length));
    splits.sort((a, b) => a - b);

    const outputs = libEntries.map(([, CJS]) => {
      const hasher = CJS.algo[name].create();
      let prev = 0;
      for (const point of splits) {
        hasher.update(CJS.lib.WordArray.create(bytes.slice(prev, point)));
        prev = point;
      }
      return hasher.finalize(CJS.lib.WordArray.create(bytes.slice(prev))).toString();
    });
    expect(outputs[0]).toBe(outputs[1]);
    const oneShot = libEntries.map(([, CJS]) => CJS[name](CJS.lib.WordArray.create(bytes)).toString());
    expect(outputs[0]).toBe(oneShot[0]);
  });

  it('reset() returns the hasher to its initial state', () => {
    const bytes = prngBytes(40);
    const outputs = libEntries.map(([, CJS]) => {
      const hasher = CJS.algo[name].create();
      hasher.update(CJS.lib.WordArray.create(bytes));
      hasher.reset();
      return hasher.finalize(CJS.lib.WordArray.create(bytes)).toString();
    });
    expect(outputs[0]).toBe(outputs[1]);
    const freshOneShot = libEntries.map(([, CJS]) => CJS[name](CJS.lib.WordArray.create(bytes)).toString());
    expect(outputs[0]).toBe(freshOneShot[0]);
  });

  it('clone() produces an independent hasher that can diverge from the original', () => {
    const first = prngBytes(30);
    const second = prngBytes(30);
    const outputs = libEntries.map(([, CJS]) => {
      const hasher = CJS.algo[name].create();
      hasher.update(CJS.lib.WordArray.create(first));
      const cloned = hasher.clone();

      const originalResult = hasher.finalize(CJS.lib.WordArray.create(second)).toString();
      const clonedResult = cloned.finalize().toString(); // only `first` was fed in
      return { originalResult, clonedResult };
    });
    expect(outputs[0].originalResult).toBe(outputs[1].originalResult);
    expect(outputs[0].clonedResult).toBe(outputs[1].clonedResult);
    expect(outputs[0].originalResult).not.toBe(outputs[0].clonedResult);
  });

  it('CryptoJS.algo.X.create() API is usable directly', () => {
    const outputs = libEntries.map(([, CJS]) => new CJS.algo[name].init().finalize('hello').toString());
    expect(outputs[0]).toBe(outputs[1]);
  });
});

describe('SHA3 — configurable outputLength', () => {
  const OUTPUT_LENGTHS = [224, 256, 384, 512, 160]; // 160 is non-standard

  it.each(OUTPUT_LENGTHS)('outputLength=%i matches crypto-js for random input', (outputLength) => {
    const bytes = prngBytes(randInt(0, 300));
    const outputs = libEntries.map(([, CJS]) =>
      CJS.SHA3(CJS.lib.WordArray.create(bytes), { outputLength }).toString(),
    );
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('default outputLength is 512', () => {
    const outputs = libEntries.map(([, CJS]) => CJS.SHA3('abc').toString());
    expect(outputs[0]).toBe(outputs[1]);
    expect(outputs[0]).toHaveLength(128); // 512 bits = 64 bytes = 128 hex chars
  });

  it('progressive hashing at a random split point, non-default outputLength', () => {
    const bytes = prngBytes(randInt(60, 300));
    const split = randInt(1, bytes.length - 1);
    const outputs = libEntries.map(([, CJS]) => {
      const hasher = CJS.algo.SHA3.create({ outputLength: 256 });
      hasher.update(CJS.lib.WordArray.create(bytes.slice(0, split)));
      return hasher.finalize(CJS.lib.WordArray.create(bytes.slice(split))).toString();
    });
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('clone() with a non-default outputLength stays independent', () => {
    const outputs = libEntries.map(([, CJS]) => {
      const hasher = CJS.algo.SHA3.create({ outputLength: 224 });
      hasher.update('part-one-');
      const cloned = hasher.clone();
      const a = hasher.finalize('tail-a').toString();
      const b = cloned.finalize('tail-b').toString();
      return [a, b];
    });
    expect(outputs[0]).toEqual(outputs[1]);
    expect(outputs[0][0]).not.toBe(outputs[0][1]);
  });
});

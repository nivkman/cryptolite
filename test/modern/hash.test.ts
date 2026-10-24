import { createHash, createHmac } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import CryptoJS from 'crypto-js';
import { describe, expect, it } from 'vitest';
import {
  hmac,
  md5,
  sha1,
  sha256,
  sha384,
  sha3_256,
  sha3_512,
  sha512,
  type Encoding,
  type HashFunction,
  type HmacAlgorithm,
} from '../../src/modern/index';
import { expectCodeSync, prng, randBytes, randInt, randString } from './helpers';

const HASHES: Array<[string, HashFunction, string]> = [
  ['md5', md5, 'md5'],
  ['sha1', sha1, 'sha1'],
  ['sha256', sha256, 'sha256'],
  ['sha384', sha384, 'sha384'],
  ['sha512', sha512, 'sha512'],
  ['sha3_256', sha3_256, 'sha3-256'],
  ['sha3_512', sha3_512, 'sha3-512'],
];
const HMACS: HmacAlgorithm[] = ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];
const STRING_ENCODINGS = ['hex', 'base64', 'base64url'] as const;

/** Inputs around every block size (64 and 128 bytes; SHA3 rates 136 and 72) plus random text. */
function inputs(seed: number): Array<string | Uint8Array> {
  const rand = prng(seed);
  const out: Array<string | Uint8Array> = ['', 'abc', 'שלום', '😀', '﻿'];
  for (const len of [0, 1, 55, 56, 63, 64, 65, 71, 72, 73, 111, 112, 127, 128, 129, 135, 136, 137, 1000]) {
    out.push(randBytes(rand, len));
  }
  for (let i = 0; i < 100; i++) out.push(i % 2 ? randBytes(rand, randInt(rand, 0, 300)) : randString(rand, 50));
  return out;
}

function nodeInput(data: string | Uint8Array): Buffer {
  return typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
}

describe('hash functions match node:crypto', () => {
  for (const [name, fn, nodeName] of HASHES) {
    it(`${name} ≡ node '${nodeName}' for random inputs in every encoding`, () => {
      for (const data of inputs(name.length * 7 + nodeName.charCodeAt(3))) {
        const expected = createHash(nodeName).update(nodeInput(data)).digest();
        expect(fn(data)).toBe(expected.toString('hex')); // default encoding
        for (const enc of STRING_ENCODINGS) expect(fn(data, enc)).toBe(expected.toString(enc));
        const bytes = fn(data, 'bytes');
        expect(bytes).toBeInstanceOf(Uint8Array);
        expect(Buffer.from(bytes).equals(expected)).toBe(true);
      }
    });
  }

  it('hash a 5 MB input', () => {
    const big = randBytes(prng(50), 5_000_000);
    expect(sha256(big)).toBe(createHash('sha256').update(big).digest('hex'));
    expect(sha3_512(big, 'base64')).toBe(createHash('sha3-512').update(big).digest('base64'));
  });

  it('JSDoc examples are correct', () => {
    expect(md5('hello')).toBe('5d41402abc4b2a76b9719d911017c592');
    expect(sha1('hello')).toBe('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d');
    expect(sha256('hello')).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    expect(sha3_256('')).toBe('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
    expect(sha256('hello', 'bytes')).toHaveLength(32);
  });

  it('sha3_* are FIPS 202 SHA-3, not crypto-js Keccak "SHA3"', () => {
    // FIPS 202 test vector for "abc".
    expect(sha3_256('abc')).toBe('3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
    expect(sha3_256('abc')).not.toBe(CryptoJS.SHA3('abc', { outputLength: 256 }).toString());
    expect(sha3_512('abc')).not.toBe(CryptoJS.SHA3('abc', { outputLength: 512 }).toString());
  });

  it('accept Buffer and cross-realm Uint8Array without modifying them', () => {
    const buf = Buffer.from('buffer input');
    const copy = Buffer.from(buf);
    expect(sha256(buf)).toBe(createHash('sha256').update(copy).digest('hex'));
    expect(buf.equals(copy)).toBe(true);
    const foreign = runInNewContext('new Uint8Array([1, 2, 3])') as Uint8Array;
    expect(sha1(foreign)).toBe(createHash('sha1').update(Buffer.from([1, 2, 3])).digest('hex'));
  });

  it('reject bad input with ERR_PARAMS / ERR_UTF8', () => {
    for (const bad of [42, null, undefined, {}, [1, 2], new ArrayBuffer(4), new Uint16Array(2), new DataView(new ArrayBuffer(1))]) {
      expectCodeSync(() => sha256(bad as never), 'ERR_PARAMS');
    }
    for (const enc of ['HEX', 'binary', 'utf8', 'latin1', null, 1, '']) {
      expectCodeSync(() => md5('x', enc as never), 'ERR_PARAMS');
    }
    expectCodeSync(() => sha256('lone \uD800 surrogate'), 'ERR_UTF8');
  });
});

describe('hmac matches node:crypto', () => {
  for (const algorithm of HMACS) {
    it(`hmac('${algorithm}') for random keys (empty, short, longer than a block, text) and data`, () => {
      const rand = prng(60 + algorithm.length);
      const keys: Array<string | Uint8Array> = ['', 'key', 'מפתח🔑', new Uint8Array(0), randBytes(rand, 200), randBytes(rand, 64), randBytes(rand, 128)];
      for (let i = 0; i < 20; i++) keys.push(i % 2 ? randBytes(rand, randInt(rand, 1, 150)) : randString(rand, 30));
      const datas = inputs(70 + algorithm.length).slice(0, 40);
      for (const key of keys) {
        for (const data of datas) {
          const expected = createHmac(algorithm, nodeInput(key)).update(nodeInput(data)).digest();
          expect(hmac(algorithm, key, data)).toBe(expected.toString('hex'));
          for (const enc of STRING_ENCODINGS) expect(hmac(algorithm, key, data, enc)).toBe(expected.toString(enc));
          expect(Buffer.from(hmac(algorithm, key, data, 'bytes')).equals(expected)).toBe(true);
        }
      }
    });
  }

  it('does not wipe or modify a caller-supplied key or data', () => {
    const key = new Uint8Array([1, 2, 3, 4]);
    const data = new Uint8Array([5, 6]);
    hmac('sha256', key, data);
    expect(Array.from(key)).toEqual([1, 2, 3, 4]);
    expect(Array.from(data)).toEqual([5, 6]);
  });

  it('rejects unknown algorithms (including prototype keys), bad keys/data and encodings', () => {
    for (const alg of ['sha3_256', 'SHA256', 'sha-256', 'sha224', 'ripemd160', 'constructor', '__proto__', 'toString', '', null]) {
      expectCodeSync(() => hmac(alg as never, 'k', 'd'), 'ERR_PARAMS');
    }
    expectCodeSync(() => hmac('sha256', 42 as never, 'd'), 'ERR_PARAMS');
    expectCodeSync(() => hmac('sha256', 'k', null as never), 'ERR_PARAMS');
    expectCodeSync(() => hmac('sha256', 'k', 'd', 'binary' as never), 'ERR_PARAMS');
    expectCodeSync(() => hmac('sha256', 'k\uDC00', 'd'), 'ERR_UTF8');
  });
});

describe('typed overloads', () => {
  it('bytes → Uint8Array, otherwise string (checked by tsc on this file)', () => {
    const s: string = sha256('x');
    const s2: string = sha512('x', 'base64url');
    const b: Uint8Array = sha256('x', 'bytes');
    const h: Uint8Array = hmac('sha256', 'k', 'd', 'bytes');
    const hs: string = hmac('sha1', 'k', 'd');
    const enc = 'hex' as Encoding;
    const either: string | Uint8Array = md5('x', enc);
    // @ts-expect-error a string result is not assignable to Uint8Array
    const wrong: Uint8Array = sha256('x');
    // @ts-expect-error 'bytes' does not return a string
    const wrong2: string = hmac('sha256', 'k', 'd', 'bytes');
    // @ts-expect-error unknown algorithm (and rejected at runtime too)
    expectCodeSync(() => hmac('sha3_256', 'k', 'd'), 'ERR_PARAMS');
    for (const v of [s, s2, hs, either, wrong]) expect(typeof v).toBe('string');
    for (const v of [b, h, wrong2]) expect(v).toBeInstanceOf(Uint8Array);
  });
});

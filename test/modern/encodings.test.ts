import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { base64Decode, base64Encode, base64UrlDecode, base64UrlEncode } from '../../src/internal/base64';
import { charCodesToString, concatBytes, isBytes, plainBytes } from '../../src/internal/bytes';
import { hexDecode, hexEncode } from '../../src/internal/hex';
import { expectCodeSync, prng, randBytes, randInt } from './helpers';

describe('base64 / base64url', () => {
  it('encode and decode match Buffer for random lengths 0..300', () => {
    const rand = prng(10);
    for (let len = 0; len <= 300; len++) {
      const bytes = randBytes(rand, len);
      const buf = Buffer.from(bytes);
      const std = base64Encode(bytes);
      const url = base64UrlEncode(bytes);
      expect(std).toBe(buf.toString('base64'));
      expect(url).toBe(buf.toString('base64url'));
      expect(Buffer.from(base64Decode(std)).equals(buf)).toBe(true);
      expect(Buffer.from(base64UrlDecode(url)).equals(buf)).toBe(true);
    }
  });

  it('handles large inputs', () => {
    const bytes = randBytes(prng(11), 1_000_003);
    const buf = Buffer.from(bytes);
    expect(base64Encode(bytes)).toBe(buf.toString('base64'));
    expect(Buffer.from(base64UrlDecode(base64UrlEncode(bytes))).equals(buf)).toBe(true);
  });

  it('standard base64 decoding is strict and canonical', () => {
    const bad = [
      'QQ', 'QQ=', 'QUI', // missing padding
      'QR==', 'QUJ=', // non-zero unused bits
      'Q===', '====', 'QQ==QQ==', 'Q=Q=', // misplaced padding
      ' QQ==', 'QQ== ', 'QU\nI=', 'QUJD\n', // whitespace
      'QUJ-', 'QUJ_', // base64url alphabet
      'QUJé', 'QUJ\u0000', 'Q', 'QUJDR', // non-alphabet / bad length
    ];
    for (const s of bad) expectCodeSync(() => base64Decode(s), 'ERR_FORMAT');
    expect(base64Decode('')).toEqual(new Uint8Array(0));
    expect(Array.from(base64Decode('QQ=='))).toEqual([0x41]);
    expect(Array.from(base64Decode('+/+/'))).toEqual([0xfb, 0xff, 0xbf]);
  });

  it('base64url decoding is strict and canonical', () => {
    const bad = [
      'QQ==', 'QQ=', // padding
      'QR', 'QUJ', // non-zero unused bits ('QUI' is canonical, 'QUJ' is not)
      'Q', 'QUJDR', // impossible lengths
      '+/+/', 'QUI+', 'QUI/', // standard alphabet
      ' QUI', 'QUI ', 'Q UI', 'QUI\n', // whitespace
      'QUI.', 'QUIé',
    ];
    for (const s of bad) expectCodeSync(() => base64UrlDecode(s), 'ERR_FORMAT');
    expect(Array.from(base64UrlDecode('-_-_'))).toEqual([0xfb, 0xff, 0xbf]);
    expect(Array.from(base64UrlDecode('QUI'))).toEqual([0x41, 0x42]);
  });

  it('exactly one encoding is accepted per byte string (exhaustive over 1- and 2-byte inputs)', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let accepted = 0;
    for (const a of alphabet) {
      for (const b of alphabet) {
        // Two characters encode one byte: only 1/16 of pairs are canonical.
        try {
          const bytes = base64UrlDecode(a + b);
          expect(base64UrlEncode(bytes)).toBe(a + b);
          accepted++;
        } catch {
          // rejected as non-canonical
        }
      }
    }
    expect(accepted).toBe(256);
  });
});

describe('hex', () => {
  it('matches Buffer and round-trips', () => {
    const rand = prng(12);
    for (let i = 0; i < 200; i++) {
      const bytes = randBytes(rand, randInt(rand, 0, 100));
      const hex = hexEncode(bytes);
      expect(hex).toBe(Buffer.from(bytes).toString('hex'));
      expect(hexDecode(hex)).toEqual(bytes);
      expect(hexDecode(hex.toUpperCase())).toEqual(bytes);
    }
  });

  it('rejects malformed hex', () => {
    for (const s of ['0', 'abc', '0g', 'zz', '0x00', ' 00', '00 ', '0-']) expectCodeSync(() => hexDecode(s), 'ERR_FORMAT');
    expect(hexDecode('')).toEqual(new Uint8Array(0));
  });
});

describe('byte helpers', () => {
  it('isBytes accepts Uint8Array, Buffer and cross-realm Uint8Arrays only', () => {
    const foreign = runInNewContext('new Uint8Array([1, 2, 3])') as Uint8Array;
    expect(foreign instanceof Uint8Array).toBe(false); // really from another realm
    expect(isBytes(new Uint8Array(2))).toBe(true);
    expect(isBytes(Buffer.from('ab'))).toBe(true);
    expect(isBytes(foreign)).toBe(true);
    for (const v of [new Uint16Array(2), new Int8Array(2), new Uint8ClampedArray(2), new DataView(new ArrayBuffer(2)), new ArrayBuffer(2), [1, 2], 'ab', null, undefined, { length: 2, 0: 1, 1: 2 }]) {
      expect(isBytes(v)).toBe(false);
    }
    // A plain object pretending to be a Uint8Array is not one.
    expect(isBytes({ [Symbol.toStringTag]: 'Uint8Array', buffer: new ArrayBuffer(1), byteLength: 1 })).toBe(false);
  });

  it('plainBytes returns a same-realm plain view without copying', () => {
    const buf = Buffer.from([1, 2, 3, 4]);
    const view = plainBytes(buf.subarray(1, 3));
    expect(view.constructor).toBe(Uint8Array);
    expect(Array.from(view)).toEqual([2, 3]);
    view[0] = 9;
    expect(buf[1]).toBe(9); // same memory
    const foreign = runInNewContext('new Uint8Array([5, 6])') as Uint8Array;
    expect(plainBytes(foreign) instanceof Uint8Array).toBe(true);
    const plain = new Uint8Array(1);
    expect(plainBytes(plain)).toBe(plain);
  });

  it('concatBytes and charCodesToString', () => {
    expect(Array.from(concatBytes(new Uint8Array([1]), new Uint8Array(0), new Uint8Array([2, 3])))).toEqual([1, 2, 3]);
    const codes = new Uint16Array(50_000).map((_, i) => 0x41 + (i % 26));
    const s = charCodesToString(codes);
    expect(s.length).toBe(50_000);
    expect(s.slice(0, 3)).toBe('ABC');
    expect(charCodesToString(codes, 2)).toBe('AB');
  });
});

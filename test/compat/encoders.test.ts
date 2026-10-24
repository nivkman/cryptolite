import { describe, expect, it } from 'vitest';
import CryptoJS from '../../src/compat/index';
import {
  RefCryptoJS,
  SAMPLE_LENGTHS,
  bytesToHex,
  prngBytes,
  prngString,
  resetBase64urlCache,
} from './_util';

const libs = { cryptolite: CryptoJS, 'crypto-js': RefCryptoJS } as const;
const libEntries = Object.entries(libs);

// Hex/Latin1/Base64 operate on individual bytes, so round-tripping any length is lossless.
const BYTE_GRANULAR_ENCODERS = ['Hex', 'Latin1', 'Base64'] as const;
// Utf16 family operates on 2-byte code units: an odd-length input round-trips to the next even
// length (a trailing zero byte is folded into the last code unit) — expected, not a bug, as long
// as both libraries agree.
const UTF16_ENCODERS = ['Utf16', 'Utf16BE', 'Utf16LE'] as const;

describe('Encoders — stringify/parse round trips match crypto-js byte for byte', () => {
  it.each(SAMPLE_LENGTHS)('length %i, byte-granular encoders', (len) => {
    const bytes = prngBytes(len);
    for (const encName of BYTE_GRANULAR_ENCODERS) {
      const serialized = libEntries.map(([, CJS]) => CJS.lib.WordArray.create(bytes).toString(CJS.enc[encName]));
      expect(serialized[0]).toBe(serialized[1]);

      const roundTripped = libEntries.map(([, CJS]) => CJS.enc[encName].parse(serialized[0]).toString(CJS.enc.Hex));
      expect(roundTripped[0]).toBe(roundTripped[1]);
      expect(roundTripped[0]).toBe(bytesToHex(bytes));
    }
  });

  it.each(SAMPLE_LENGTHS)('length %i, Utf16/Utf16BE/Utf16LE (library parity, even-padded round trip)', (len) => {
    const bytes = prngBytes(len);
    for (const encName of UTF16_ENCODERS) {
      const serialized = libEntries.map(([, CJS]) => CJS.lib.WordArray.create(bytes).toString(CJS.enc[encName]));
      expect(serialized[0]).toBe(serialized[1]);

      const roundTripped = libEntries.map(([, CJS]) => CJS.enc[encName].parse(serialized[0]).toString(CJS.enc.Hex));
      expect(roundTripped[0]).toBe(roundTripped[1]);
      // Lossless for even lengths; for odd lengths the trailing byte round-trips as byte,0x00.
      const expectedHex = len % 2 === 0 ? bytesToHex(bytes) : bytesToHex(bytes) + '00';
      expect(roundTripped[0]).toBe(expectedHex);
    }
  });
});

describe('Utf8 — stringify/parse', () => {
  it.each(SAMPLE_LENGTHS.filter((n) => n > 0))('round trips ASCII length %i', (len) => {
    const s = prngString(len).replace(/[\u0080-￿]/g, 'x'); // keep ASCII-only for a clean baseline
    const outputs = libEntries.map(([, CJS]) => CJS.enc.Utf8.parse(s).toString(CJS.enc.Hex));
    expect(outputs[0]).toBe(outputs[1]);
    const back = libEntries.map(([, CJS]) => CJS.enc.Utf8.stringify(CJS.enc.Utf8.parse(s)));
    expect(back[0]).toBe(s);
    expect(back[1]).toBe(s);
  });

  it('round trips multi-byte UTF-8 (accents, CJK, emoji)', () => {
    const s = 'héllo 世界 🚀 éè end';
    const hex = libEntries.map(([, CJS]) => CJS.enc.Utf8.parse(s).toString(CJS.enc.Hex));
    expect(hex[0]).toBe(hex[1]);
    for (const [, CJS] of libEntries) {
      expect(CJS.enc.Utf8.stringify(CJS.enc.Utf8.parse(s))).toBe(s);
    }
  });

  it('BOM is preserved through parse/stringify', () => {
    const s = '﻿hello';
    for (const [, CJS] of libEntries) {
      const wa = CJS.enc.Utf8.parse(s);
      expect(CJS.enc.Utf8.stringify(wa)).toBe(s);
    }
  });

  it('parse throws on a lone surrogate (both libraries, same native error)', () => {
    const lone = String.fromCharCode(0xd800);
    const errors = libEntries.map(([, CJS]) => {
      try {
        CJS.enc.Utf8.parse(lone);
        return null;
      } catch (e) {
        return (e as Error).message;
      }
    });
    expect(errors[0]).not.toBeNull();
    expect(errors[0]).toBe(errors[1]);
  });

  it("stringify throws 'Malformed UTF-8 data' on invalid UTF-8 byte sequences", () => {
    // 0xFF is never valid in UTF-8.
    const invalid = CryptoJS.lib.WordArray.create(new Uint8Array([0xff, 0x01, 0x02]));
    const invalidRef = RefCryptoJS.lib.WordArray.create(new Uint8Array([0xff, 0x01, 0x02]));
    expect(() => CryptoJS.enc.Utf8.stringify(invalid)).toThrow('Malformed UTF-8 data');
    expect(() => RefCryptoJS.enc.Utf8.stringify(invalidRef)).toThrow('Malformed UTF-8 data');
  });

  it('a lone continuation byte also throws identically on both libraries', () => {
    const bytes = new Uint8Array([0x61, 0x80, 0x62]);
    const messages = libEntries.map(([, CJS]) => {
      try {
        CJS.enc.Utf8.stringify(CJS.lib.WordArray.create(bytes));
        return null;
      } catch (e) {
        return (e as Error).message;
      }
    });
    expect(messages[0]).toBe('Malformed UTF-8 data');
    expect(messages[0]).toBe(messages[1]);
  });
});

describe('Hex — malformed input', () => {
  it('odd-length hex strings parse the same way crypto-js does (no validation)', () => {
    for (const odd of ['a', 'abc', 'fffff', '1']) {
      const outputs = libEntries.map(([, CJS]) => CJS.enc.Hex.parse(odd).toString());
      expect(outputs[0]).toBe(outputs[1]);
    }
  });
});

describe('Base64 — malformed input', () => {
  it('missing padding is tolerated identically', () => {
    for (const s of ['YWJj', 'YWJjZA', 'YQ', 'YQ=']) {
      const outputs = libEntries.map(([, CJS]) => CJS.enc.Base64.parse(s).toString(CJS.enc.Hex));
      expect(outputs[0]).toBe(outputs[1]);
    }
  });

  it('invalid characters are tolerated identically (undefined reverse-map entries)', () => {
    for (const s of ['a!cd', '####', 'ab\ncd', 'a b c d']) {
      const outputs = libEntries.map(([, CJS]) => CJS.enc.Base64.parse(s).toString(CJS.enc.Hex));
      expect(outputs[0]).toBe(outputs[1]);
    }
  });
});

describe('Base64url — urlSafe true/false', () => {
  it('stringify: default urlSafe (true) uses -_ and matches crypto-js', () => {
    const bytes = prngBytes(30);
    for (const [, CJS] of libEntries) resetBase64urlCache(CJS);
    const outputs = libEntries.map(([, CJS]) => CJS.enc.Base64url.stringify(CJS.lib.WordArray.create(bytes)));
    expect(outputs[0]).toBe(outputs[1]);
    expect(outputs[0]).not.toMatch(/[+/]/);
  });

  it('stringify: urlSafe=false uses +/ and padding, matches crypto-js', () => {
    const bytes = prngBytes(30);
    for (const [, CJS] of libEntries) resetBase64urlCache(CJS);
    const outputs = libEntries.map(([, CJS]) => CJS.enc.Base64url.stringify(CJS.lib.WordArray.create(bytes), false));
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('round trips both ways when reset between uses', () => {
    const bytes = prngBytes(21);
    for (const urlSafe of [true, false]) {
      for (const [, CJS] of libEntries) resetBase64urlCache(CJS);
      const outputs = libEntries.map(([, CJS]) => {
        const s = CJS.enc.Base64url.stringify(CJS.lib.WordArray.create(bytes), urlSafe);
        for (const [, cjs2] of libEntries) resetBase64urlCache(cjs2);
        return CJS.enc.Base64url.parse(s, urlSafe).toString(CJS.enc.Hex);
      });
      expect(outputs[0]).toBe(outputs[1]);
      expect(outputs[0]).toBe(bytesToHex(bytes));
    }
  });

  it(
    'documented quirk: the reverse map is cached from whichever alphabet parse() saw first, ' +
      'so a later parse() with a different urlSafe can silently reuse the wrong map',
    () => {
      // A string that is known to contain '+' and '/' when encoded with the non-safe alphabet.
      for (const [, CJS] of libEntries) resetBase64urlCache(CJS);
      const nonSafeStr = libEntries.map(([, CJS]) =>
        CJS.enc.Base64url.stringify(CJS.enc.Utf8.parse('a>>?b??'), false),
      );
      expect(nonSafeStr[0]).toBe(nonSafeStr[1]);
      expect(nonSafeStr[0]).toBe('YT4+P2I/Pw==');
      expect(nonSafeStr[0]).toMatch(/[+/]/);

      // Prime the cache with urlSafe=true (the default) on both libraries...
      for (const [, CJS] of libEntries) {
        resetBase64urlCache(CJS);
        CJS.enc.Base64url.parse('AAAA', true);
      }
      // ...then parse the +/ string with urlSafe=false: the stale (safe-alphabet) reverse map
      // is reused, so '+' and '/' resolve to `undefined`, producing identical garbage/NaN-masked
      // output on both libraries instead of throwing.
      const outputs = libEntries.map(([, CJS]) => CJS.enc.Base64url.parse(nonSafeStr[0], false).toString(CJS.enc.Hex));
      expect(outputs[0]).toBe(outputs[1]);
    },
  );
});

describe('Base64url — exact outputs for a fixed vector (sanity against hand-computed expectation)', () => {
  it('"a>>?b??" through the non-safe alphabet', () => {
    for (const [, CJS] of libEntries) resetBase64urlCache(CJS);
    const wa = CryptoJS.enc.Utf8.parse('a>>?b??');
    const s = CryptoJS.enc.Base64url.stringify(wa, false);
    expect(s).toBe('YT4+P2I/Pw==');
  });
});

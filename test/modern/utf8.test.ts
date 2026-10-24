import { describe, expect, it } from 'vitest';
import { utf8Decode, utf8Encode } from '../../src/internal/utf8';
import { CryptoliteError } from '../../src/internal/errors';
import { prng, randBytes, randInt, randString } from './helpers';

const fatal = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Reference: TextDecoder in fatal mode, BOM kept. Returns undefined where it throws. */
function refDecode(bytes: Uint8Array): string | undefined {
  try {
    return fatal.decode(bytes);
  } catch {
    return undefined;
  }
}

function ourDecode(bytes: Uint8Array): string | undefined {
  try {
    return utf8Decode(bytes);
  } catch (err) {
    // Plain check, not expect(): this runs hundreds of thousands of times.
    if (!(err instanceof CryptoliteError) || err.code !== 'ERR_UTF8') throw err;
    return undefined;
  }
}

function sameAsReference(bytes: Uint8Array): void {
  const ours = ourDecode(bytes);
  const ref = refDecode(bytes);
  if (ours !== ref) {
    throw new Error(`mismatch for ${Buffer.from(bytes).toString('hex')}: ours=${JSON.stringify(ours)} ref=${JSON.stringify(ref)}`);
  }
}

function allScalarValues(): string {
  const parts: string[] = [];
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    parts.push(String.fromCodePoint(cp));
  }
  return parts.join('');
}

describe('utf8Encode', () => {
  it('matches Buffer for every Unicode scalar value (U+0000..U+10FFFF minus surrogates)', () => {
    const s = allScalarValues();
    expect(Buffer.from(utf8Encode(s)).equals(Buffer.from(s, 'utf8'))).toBe(true);
  });

  it('matches Buffer for random strings, emoji, RTL Hebrew and empty', () => {
    const rand = prng(1);
    const fixed = ['', 'שלום עולם', '👩‍👩‍👧‍👦🏳️‍🌈', '﻿bom', 'a\u0000b', 'עברית mixed English 123'];
    for (const s of fixed) expect(Buffer.from(utf8Encode(s)).equals(Buffer.from(s, 'utf8'))).toBe(true);
    for (let i = 0; i < 2000; i++) {
      const s = randString(rand, 40);
      expect(Buffer.from(utf8Encode(s)).equals(Buffer.from(s, 'utf8'))).toBe(true);
    }
  });

  it('throws ERR_UTF8 exactly where encodeURIComponent throws (lone surrogates)', () => {
    const rand = prng(2);
    const surrogates = [0xd800, 0xdbff, 0xdc00, 0xdfff, 0xd834, 0xdd1e];
    const cases = ['\uD800', '\uDC00', 'a\uD800', '\uD800a', '\uDC00\uD800', '\uD800𐀀', 'x\uDFFF'];
    for (let i = 0; i < 3000; i++) {
      let s = randString(rand, 6);
      const k = randInt(rand, 0, 2);
      for (let j = 0; j < k; j++) {
        const at = randInt(rand, 0, s.length);
        s = s.slice(0, at) + String.fromCharCode(surrogates[randInt(rand, 0, surrogates.length - 1)]!) + s.slice(at);
      }
      cases.push(s);
    }
    let throwing = 0;
    for (const s of cases) {
      let refThrows = false;
      try {
        encodeURIComponent(s);
      } catch {
        refThrows = true;
      }
      let ourError: unknown;
      try {
        utf8Encode(s);
      } catch (err) {
        ourError = err;
      }
      expect(ourError !== undefined, JSON.stringify(s)).toBe(refThrows);
      if (ourError) {
        throwing++;
        expect((ourError as CryptoliteError).code).toBe('ERR_UTF8');
      }
    }
    expect(throwing).toBeGreaterThan(100); // the generator really produced invalid strings
  });
});

describe('utf8Decode', () => {
  it('matches Buffer for every Unicode scalar value', () => {
    const s = allScalarValues();
    const bytes = Buffer.from(s, 'utf8');
    expect(utf8Decode(new Uint8Array(bytes))).toBe(s);
  });

  it('matches Buffer for random valid UTF-8', () => {
    const rand = prng(3);
    for (let i = 0; i < 2000; i++) {
      const s = randString(rand, 40);
      const bytes = Buffer.from(s, 'utf8');
      expect(utf8Decode(bytes)).toBe(bytes.toString('utf8'));
    }
  });

  it('keeps a leading byte-order mark', () => {
    expect(utf8Decode(new Uint8Array([0xef, 0xbb, 0xbf, 0x61]))).toBe('﻿a');
    expect(utf8Decode(new Uint8Array([0xef, 0xbb, 0xbf]))).toBe('﻿');
  });

  it('rejects overlongs, surrogates, > U+10FFFF, invalid bytes and truncation', () => {
    const invalid = [
      [0xc0, 0x80], [0xc1, 0xbf], // overlong 2-byte
      [0xe0, 0x80, 0x80], [0xe0, 0x9f, 0xbf], // overlong 3-byte
      [0xf0, 0x80, 0x80, 0x80], [0xf0, 0x8f, 0xbf, 0xbf], // overlong 4-byte
      [0xed, 0xa0, 0x80], [0xed, 0xbf, 0xbf], // encoded surrogates
      [0xed, 0xa0, 0xbd, 0xed, 0xb2, 0xa9], // CESU-8 surrogate pair
      [0xf4, 0x90, 0x80, 0x80], [0xf5, 0x80, 0x80, 0x80], [0xf7, 0xbf, 0xbf, 0xbf], // > U+10FFFF
      [0xf8, 0x88, 0x80, 0x80, 0x80], [0xfc, 0x84, 0x80, 0x80, 0x80, 0x80], // 5/6-byte forms
      [0xfe], [0xff], [0x80], [0xbf], [0x61, 0x80], // invalid / stray continuation bytes
      [0xe2, 0x82], [0xf0, 0x9f, 0x98], [0xc3], [0xe2], // truncated
      [0xe2, 0x28, 0xa1], [0xc3, 0x28], [0xf0, 0x28, 0x8c, 0xbc], // bad continuation
    ];
    for (const bytes of invalid) {
      const u8 = new Uint8Array(bytes);
      expect(refDecode(u8), `reference should reject ${bytes}`).toBeUndefined();
      expect(() => utf8Decode(u8)).toThrow(CryptoliteError);
    }
    // Boundaries that ARE valid.
    expect(utf8Decode(new Uint8Array([0xc2, 0x80]))).toBe('\u0080');
    expect(utf8Decode(new Uint8Array([0xe0, 0xa0, 0x80]))).toBe('ࠀ');
    expect(utf8Decode(new Uint8Array([0xed, 0x9f, 0xbf]))).toBe('퟿');
    expect(utf8Decode(new Uint8Array([0xee, 0x80, 0x80]))).toBe('');
    expect(utf8Decode(new Uint8Array([0xf0, 0x90, 0x80, 0x80]))).toBe('\u{10000}');
    expect(utf8Decode(new Uint8Array([0xf4, 0x8f, 0xbf, 0xbf]))).toBe('\u{10FFFF}');
  });

  it('agrees with TextDecoder({ fatal: true }) on every 1- and 2-byte sequence', () => {
    for (let a = 0; a < 256; a++) {
      sameAsReference(new Uint8Array([a]));
      for (let b = 0; b < 256; b++) sameAsReference(new Uint8Array([a, b]));
    }
  });

  it('agrees with TextDecoder({ fatal: true }) on 3- and 4-byte sequences around every boundary', () => {
    // Every lead byte from C0 and every second byte, with third/fourth bytes at each range edge.
    const edges = [0x00, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xff];
    const fourth = [0x7f, 0x80, 0xbf, 0xc0];
    const fourByteLeads = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf7, 0xf8, 0xff];
    for (let a = 0xc0; a < 256; a++) {
      for (let b = 0; b < 256; b++) {
        for (const c of edges) {
          sameAsReference(new Uint8Array([a, b, c]));
          if (fourByteLeads.includes(a)) for (const d of fourth) sameAsReference(new Uint8Array([a, b, c, d]));
        }
      }
    }
  }, 120_000);

  it('agrees with TextDecoder({ fatal: true }) on random mutations of valid text', () => {
    const rand = prng(4);
    let rejected = 0;
    for (let i = 0; i < 20000; i++) {
      const bytes = new Uint8Array(Buffer.from(randString(rand, 12), 'utf8'));
      let mutated: Uint8Array = bytes;
      const op = randInt(rand, 0, 3);
      if (op === 0 && bytes.length > 0) {
        mutated = bytes.slice();
        mutated[randInt(rand, 0, bytes.length - 1)] = randInt(rand, 0, 255);
      } else if (op === 1 && bytes.length > 0) {
        mutated = bytes.subarray(0, randInt(rand, 0, bytes.length - 1));
      } else if (op === 2) {
        const at = randInt(rand, 0, bytes.length);
        mutated = new Uint8Array([...bytes.subarray(0, at), randInt(rand, 0x80, 0xff), ...bytes.subarray(at)]);
      } else {
        mutated = randBytes(rand, randInt(rand, 1, 8));
      }
      if (refDecode(mutated) === undefined) rejected++;
      sameAsReference(mutated);
    }
    expect(rejected).toBeGreaterThan(1000);
  });

  it('handles inputs far larger than its internal chunk size', () => {
    const rand = prng(5);
    let s = '';
    while (s.length < 200_000) s += randString(rand, 50);
    const bytes = Buffer.from(s, 'utf8');
    expect(utf8Decode(bytes)).toBe(s);
    expect(Buffer.from(utf8Encode(s)).equals(bytes)).toBe(true);
    // A 4-byte sequence straddling the flush point is still decoded correctly.
    const straddle = 'a'.repeat(0x2000 - 1) + '😀' + 'b';
    expect(utf8Decode(Buffer.from(straddle, 'utf8'))).toBe(straddle);
  });
});

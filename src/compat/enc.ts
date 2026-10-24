/*
 * crypto-js encoders: Utf16 (BE), Utf16LE, Base64, Base64url — ported verbatim for identical
 * output, including lenient parsing of malformed input.
 * Portions (c) 2009-2013 Jeff Mott, (c) 2013-2016 Evan Vosberg, MIT License (crypto-js).
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { C_enc, WordArray, toBytes, type Any } from './core';

function swapEndian(word: number): number {
  return ((word << 8) & 0xff00ff00) | ((word >>> 8) & 0x00ff00ff);
}

export const Utf16BE: Any = (C_enc.Utf16 = C_enc.Utf16BE = {
  stringify(wordArray: Any): string {
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    const utf16Chars: string[] = [];
    for (let i = 0; i < sigBytes; i += 2) {
      const codePoint = (words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff;
      utf16Chars.push(String.fromCharCode(codePoint));
    }
    return utf16Chars.join('');
  },

  parse(utf16Str: string): Any {
    const utf16StrLength = utf16Str.length;
    const words: number[] = [];
    for (let i = 0; i < utf16StrLength; i++) {
      words[i >>> 1] |= utf16Str.charCodeAt(i) << (16 - (i % 2) * 16);
    }
    return WordArray.create(words, utf16StrLength * 2);
  },
});

export const Utf16LE: Any = (C_enc.Utf16LE = {
  stringify(wordArray: Any): string {
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    const utf16Chars: string[] = [];
    for (let i = 0; i < sigBytes; i += 2) {
      const codePoint = swapEndian((words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff);
      utf16Chars.push(String.fromCharCode(codePoint));
    }
    return utf16Chars.join('');
  },

  parse(utf16Str: string): Any {
    const utf16StrLength = utf16Str.length;
    const words: number[] = [];
    for (let i = 0; i < utf16StrLength; i++) {
      words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << (16 - (i % 2) * 16));
    }
    return WordArray.create(words, utf16StrLength * 2);
  },
});

function stringifyWithMap(wordArray: Any, map: string): string {
  // crypto-js clamps the caller's WordArray in place (and throws on a negative sigBytes there);
  // keep that side effect, then encode bytes with a lookup table. Output is identical to
  // crypto-js's per-character loop, including for custom `_map` alphabets.
  wordArray.clamp();
  const bytes = toBytes(wordArray);
  const n = bytes.length;
  const chars: string[] = [];
  for (let k = 0; k < 64; k++) {
    chars.push(map.charAt(k));
  }

  let out = '';
  let i = 0;
  for (; i + 2 < n; i += 3) {
    const triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      chars[(triplet >>> 18) & 0x3f] +
      chars[(triplet >>> 12) & 0x3f] +
      chars[(triplet >>> 6) & 0x3f] +
      chars[triplet & 0x3f];
  }
  let nChars = (i / 3) * 4;
  if (n - i === 1) {
    const triplet = bytes[i] << 16;
    out += chars[(triplet >>> 18) & 0x3f] + chars[(triplet >>> 12) & 0x3f];
    nChars += 2;
  } else if (n - i === 2) {
    const triplet = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += chars[(triplet >>> 18) & 0x3f] + chars[(triplet >>> 12) & 0x3f] + chars[(triplet >>> 6) & 0x3f];
    nChars += 3;
  }

  const paddingChar = map.charAt(64);
  if (paddingChar) {
    while (nChars % 4) {
      out += paddingChar;
      nChars++;
    }
  }
  return out;
}

function parseLoop(base64Str: string, base64StrLength: number, reverseMap: number[]): Any {
  const words: number[] = [];
  let nBytes = 0;
  for (let i = 0; i < base64StrLength; i++) {
    if (i % 4) {
      const bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
      const bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
      const bitsCombined = bits1 | bits2;
      words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
      nBytes++;
    }
  }
  return WordArray.create(words, nBytes);
}

function buildReverseMap(map: string): number[] {
  const reverseMap: number[] = [];
  for (let j = 0; j < map.length; j++) {
    reverseMap[map.charCodeAt(j)] = j;
  }
  return reverseMap;
}

function parseWithMap(base64Str: string, map: string, reverseMap: number[]): Any {
  let base64StrLength = base64Str.length;
  const paddingChar = map.charAt(64);
  if (paddingChar) {
    const paddingIndex = base64Str.indexOf(paddingChar);
    if (paddingIndex !== -1) {
      base64StrLength = paddingIndex;
    }
  }
  return parseLoop(base64Str, base64StrLength, reverseMap);
}

export const Base64: Any = (C_enc.Base64 = {
  stringify(this: Any, wordArray: Any): string {
    return stringifyWithMap(wordArray, this._map);
  },

  parse(this: Any, base64Str: string): Any {
    // crypto-js caches the reverse map on first use, keyed to whatever `_map` was then.
    let reverseMap = this._reverseMap;
    if (!reverseMap) {
      reverseMap = this._reverseMap = buildReverseMap(this._map);
    }
    return parseWithMap(base64Str, this._map, reverseMap);
  },

  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
});

export const Base64url: Any = (C_enc.Base64url = {
  stringify(this: Any, wordArray: Any, urlSafe?: boolean): string {
    if (urlSafe === undefined) {
      urlSafe = true;
    }
    return stringifyWithMap(wordArray, urlSafe ? this._safe_map : this._map);
  },

  parse(this: Any, base64Str: string, urlSafe?: boolean): Any {
    if (urlSafe === undefined) {
      urlSafe = true;
    }
    const map = urlSafe ? this._safe_map : this._map;
    // Fidelity: crypto-js 4.2.0 caches ONE reverse map for Base64url, built from whichever
    // alphabet was used first. Reproduced as-is.
    let reverseMap = this._reverseMap;
    if (!reverseMap) {
      reverseMap = this._reverseMap = buildReverseMap(map);
    }
    return parseWithMap(base64Str, map, reverseMap);
  },

  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
  _safe_map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
});

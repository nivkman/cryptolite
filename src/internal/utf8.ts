/**
 * Strict UTF-8 (RFC 3629) encoding and decoding without `TextEncoder`/`TextDecoder`, which
 * React Native (Hermes) does not guarantee. Internal: not part of the public API.
 * @module
 */
import { charCodesToString } from './bytes';
import { CryptoliteError } from './errors';

/**
 * Encodes a string as UTF-8.
 *
 * Unlike `TextEncoder` and `Buffer.from(str)`, which silently replace lone surrogates with U+FFFD,
 * this throws, matching `encodeURIComponent` (and therefore crypto-js's `Utf8.parse`). Silent
 * replacement would make distinct strings encrypt or hash to the same value.
 *
 * @throws {CryptoliteError} `ERR_UTF8` if the string contains a lone (unpaired) surrogate.
 */
export function utf8Encode(str: string): Uint8Array {
  const n = str.length;
  // Pass 1: validate and size exactly, so large ASCII strings don't over-allocate 3x.
  let size = 0;
  for (let i = 0; i < n; i++) {
    const c = str.charCodeAt(i);
    if (c < 0x80) size += 1;
    else if (c < 0x800) size += 2;
    else if (c < 0xd800 || c > 0xdfff) size += 3;
    else if (c <= 0xdbff && i + 1 < n && (str.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      size += 4;
      i++;
    } else {
      // No index in the message: the string may be a password or plaintext.
      throw new CryptoliteError(
        'ERR_UTF8',
        'The string is not well-formed Unicode (it contains a lone UTF-16 surrogate), so it cannot be encoded as UTF-8.',
      );
    }
  }
  // Pass 2: write. Input is known to be well-formed here.
  const out = new Uint8Array(size);
  let p = 0;
  for (let i = 0; i < n; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) {
      out[p++] = c;
    } else if (c < 0x800) {
      out[p++] = 0xc0 | (c >> 6);
      out[p++] = 0x80 | (c & 0x3f);
    } else if (c < 0xd800 || c > 0xdfff) {
      out[p++] = 0xe0 | (c >> 12);
      out[p++] = 0x80 | ((c >> 6) & 0x3f);
      out[p++] = 0x80 | (c & 0x3f);
    } else {
      c = 0x10000 + ((c - 0xd800) << 10) + (str.charCodeAt(++i) - 0xdc00);
      out[p++] = 0xf0 | (c >> 18);
      out[p++] = 0x80 | ((c >> 12) & 0x3f);
      out[p++] = 0x80 | ((c >> 6) & 0x3f);
      out[p++] = 0x80 | (c & 0x3f);
    }
  }
  return out;
}

const FLUSH_AT = 0x2000;

// No offset in the message: the bytes may be decrypted plaintext.
function invalidUtf8(): CryptoliteError {
  return new CryptoliteError('ERR_UTF8', 'The data is not valid UTF-8.');
}

/**
 * Decodes UTF-8 bytes to a string, rejecting anything RFC 3629 does not allow: overlong forms,
 * encoded surrogates (U+D800–U+DFFF), code points above U+10FFFF, stray continuation bytes, the
 * bytes C0, C1 and F5–FF, and truncated sequences. Accepts and rejects exactly what
 * `new TextDecoder('utf-8', { fatal: true })` does.
 *
 * A leading byte-order mark (EF BB BF) is kept as U+FEFF, never stripped: decoding must
 * round-trip the exact plaintext.
 *
 * @throws {CryptoliteError} `ERR_UTF8` if the bytes are not valid UTF-8.
 */
export function utf8Decode(bytes: Uint8Array): string {
  const n = bytes.length;
  const units = new Uint16Array(Math.min(n, FLUSH_AT) + 2);
  const chunks: string[] = [];
  let u = 0;
  let i = 0;
  while (i < n) {
    const b0 = bytes[i]!; // i < n
    if (b0 < 0x80) {
      units[u++] = b0;
      i++;
    } else {
      // RFC 3629 §4: the second byte's range depends on the lead byte; later bytes are 80..BF.
      let need: number;
      let cp: number;
      let lo = 0x80;
      let hi = 0xbf;
      if (b0 >= 0xc2 && b0 <= 0xdf) {
        need = 1;
        cp = b0 & 0x1f;
      } else if (b0 >= 0xe0 && b0 <= 0xef) {
        need = 2;
        cp = b0 & 0x0f;
        if (b0 === 0xe0) lo = 0xa0; // no overlongs
        else if (b0 === 0xed) hi = 0x9f; // no surrogates
      } else if (b0 >= 0xf0 && b0 <= 0xf4) {
        need = 3;
        cp = b0 & 0x07;
        if (b0 === 0xf0) lo = 0x90; // no overlongs
        else if (b0 === 0xf4) hi = 0x8f; // nothing above U+10FFFF
      } else {
        throw invalidUtf8();
      }
      if (i + need >= n) throw invalidUtf8();
      const b1 = bytes[i + 1]!; // i + need < n
      if (b1 < lo || b1 > hi) throw invalidUtf8();
      cp = (cp << 6) | (b1 & 0x3f);
      for (let k = 2; k <= need; k++) {
        const b = bytes[i + k]!;
        if ((b & 0xc0) !== 0x80) throw invalidUtf8();
        cp = (cp << 6) | (b & 0x3f);
      }
      i += need + 1;
      if (cp >= 0x10000) {
        cp -= 0x10000;
        units[u++] = 0xd800 | (cp >> 10);
        units[u++] = 0xdc00 | (cp & 0x3ff);
      } else {
        units[u++] = cp;
      }
    }
    if (u >= FLUSH_AT) {
      chunks.push(charCodesToString(units, u));
      u = 0;
    }
  }
  if (chunks.length === 0) return charCodesToString(units, u);
  if (u > 0) chunks.push(charCodesToString(units, u));
  return chunks.join('');
}

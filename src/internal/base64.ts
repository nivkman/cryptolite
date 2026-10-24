/**
 * Canonical base64 (RFC 4648 §4, padded) and base64url (RFC 4648 §5, unpadded) with strict
 * decoding. No dependency on `atob`/`btoa` or `Buffer`. Internal: not part of the public API.
 *
 * "Strict" means exactly one string is accepted for any byte sequence: no whitespace, no
 * characters from the other alphabet, padding exactly where required (and nowhere else), and the
 * unused low bits of the final character must be zero. Without the last rule, `QQ==` and `QR==`
 * would both decode to `A`, letting a token be altered without changing its decoded bytes.
 * @module
 */
import { charCodesToString } from './bytes';
import { CryptoliteError } from './errors';

const STD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const PAD = 0x3d; // '='

function encodeTable(alphabet: string): Uint8Array {
  const table = new Uint8Array(64);
  for (let i = 0; i < 64; i++) table[i] = alphabet.charCodeAt(i);
  return table;
}

function decodeTable(alphabet: string): Int8Array {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < 64; i++) table[alphabet.charCodeAt(i)] = i;
  return table;
}

const STD_ENC = /* @__PURE__ */ encodeTable(STD_ALPHABET);
const URL_ENC = /* @__PURE__ */ encodeTable(URL_ALPHABET);
const STD_DEC = /* @__PURE__ */ decodeTable(STD_ALPHABET);
const URL_DEC = /* @__PURE__ */ decodeTable(URL_ALPHABET);

// Index expressions below are in bounds by construction; `!` only satisfies noUncheckedIndexedAccess.
function encode(bytes: Uint8Array, table: Uint8Array, pad: boolean): string {
  const n = bytes.length;
  const rem = n % 3;
  const full = n - rem;
  const outLen = pad ? Math.ceil(n / 3) * 4 : (full / 3) * 4 + (rem === 0 ? 0 : rem + 1);
  const out = new Uint8Array(outLen);
  let p = 0;
  for (let i = 0; i < full; i += 3) {
    const v = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out[p++] = table[v >>> 18]!;
    out[p++] = table[(v >>> 12) & 63]!;
    out[p++] = table[(v >>> 6) & 63]!;
    out[p++] = table[v & 63]!;
  }
  if (rem === 1) {
    const v = bytes[full]!;
    out[p++] = table[v >>> 2]!;
    out[p++] = table[(v & 3) << 4]!;
    if (pad) {
      out[p++] = PAD;
      out[p++] = PAD;
    }
  } else if (rem === 2) {
    const v = (bytes[full]! << 8) | bytes[full + 1]!;
    out[p++] = table[v >>> 10]!;
    out[p++] = table[(v >>> 4) & 63]!;
    out[p++] = table[(v & 15) << 2]!;
    if (pad) out[p++] = PAD;
  }
  return charCodesToString(out, p);
}

function decode(str: string, table: Int8Array, padded: boolean, label: string): Uint8Array {
  const fail = (): CryptoliteError => new CryptoliteError('ERR_FORMAT', `Invalid ${label} string.`);
  let len = str.length;
  if (padded) {
    if (len % 4 !== 0) throw fail();
    if (len > 0 && str.charCodeAt(len - 1) === PAD) len -= str.charCodeAt(len - 2) === PAD ? 2 : 1;
  } else if (len % 4 === 1) {
    throw fail();
  }
  const rem = len % 4; // 0, 2 or 3 (a lone trailing character can never be valid)
  if (rem === 1) throw fail();
  const full = len - rem;
  const out = new Uint8Array((full / 4) * 3 + (rem === 0 ? 0 : rem - 1));
  const sextet = (i: number): number => {
    const c = str.charCodeAt(i);
    const v = c < 128 ? table[c]! : -1; // NaN (past the end) is not < 128
    if (v < 0) throw fail();
    return v;
  };
  let p = 0;
  for (let i = 0; i < full; i += 4) {
    const v = (sextet(i) << 18) | (sextet(i + 1) << 12) | (sextet(i + 2) << 6) | sextet(i + 3);
    out[p++] = v >>> 16;
    out[p++] = (v >>> 8) & 0xff;
    out[p++] = v & 0xff;
  }
  if (rem === 2) {
    const a = sextet(full);
    const b = sextet(full + 1);
    if (b & 15) throw fail(); // non-canonical: unused bits set
    out[p] = (a << 2) | (b >>> 4);
  } else if (rem === 3) {
    const a = sextet(full);
    const b = sextet(full + 1);
    const c = sextet(full + 2);
    if (c & 3) throw fail(); // non-canonical: unused bits set
    out[p++] = (a << 2) | (b >>> 4);
    out[p] = ((b & 15) << 4) | (c >>> 2);
  }
  return out;
}

/** Standard base64 with `=` padding (RFC 4648 §4), identical to `Buffer#toString('base64')`. */
export function base64Encode(bytes: Uint8Array): string {
  return encode(bytes, STD_ENC, true);
}

/**
 * Decodes canonical, padded standard base64.
 * @throws {CryptoliteError} `ERR_FORMAT` on any deviation from the canonical encoding.
 */
export function base64Decode(str: string): Uint8Array {
  return decode(str, STD_DEC, true, 'base64');
}

/** base64url without padding (RFC 4648 §5), identical to `Buffer#toString('base64url')`. */
export function base64UrlEncode(bytes: Uint8Array): string {
  return encode(bytes, URL_ENC, false);
}

/**
 * Decodes canonical, unpadded base64url.
 * @throws {CryptoliteError} `ERR_FORMAT` on any deviation from the canonical encoding
 *   (including `=` padding, `+`, `/` and whitespace).
 */
export function base64UrlDecode(str: string): Uint8Array {
  return decode(str, URL_DEC, false, 'base64url');
}

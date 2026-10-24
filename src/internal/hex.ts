/**
 * Hexadecimal encoding. Internal: not part of the public API.
 * @module
 */
import { charCodesToString } from './bytes';
import { CryptoliteError } from './errors';

const DIGITS = '0123456789abcdef';

/** Lowercase hex, identical to `Buffer#toString('hex')`. */
export function hexEncode(bytes: Uint8Array): string {
  const n = bytes.length;
  const out = new Uint8Array(n * 2);
  for (let i = 0; i < n; i++) {
    const b = bytes[i]!;
    out[2 * i] = DIGITS.charCodeAt(b >>> 4);
    out[2 * i + 1] = DIGITS.charCodeAt(b & 15);
  }
  return charCodesToString(out);
}

function nibble(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30; // 0-9
  if (c >= 0x61 && c <= 0x66) return c - 0x57; // a-f
  if (c >= 0x41 && c <= 0x46) return c - 0x37; // A-F
  return -1;
}

/**
 * Decodes hex (either case). The string must have even length and contain only `0-9a-fA-F`:
 * no `0x` prefix, separators or whitespace.
 * @throws {CryptoliteError} `ERR_FORMAT` if the string is not valid hex.
 */
export function hexDecode(str: string): Uint8Array {
  const n = str.length;
  if (n % 2 !== 0) throw new CryptoliteError('ERR_FORMAT', 'Invalid hex string: odd length.');
  const out = new Uint8Array(n / 2);
  for (let i = 0; i < n; i += 2) {
    const hi = nibble(str.charCodeAt(i));
    const lo = nibble(str.charCodeAt(i + 1));
    if (hi < 0 || lo < 0) throw new CryptoliteError('ERR_FORMAT', 'Invalid hex string: unexpected character.');
    out[i / 2] = (hi << 4) | lo;
  }
  return out;
}

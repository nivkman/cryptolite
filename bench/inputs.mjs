// Fixed, deterministic benchmark inputs. Plain ES2020 with no Node or Web APIs, because
// bench/hermes.mjs bundles this file into a script for the Hermes VM as well.

export const MiB = 1024 * 1024;

/** 43 bytes of ASCII: the "short string" case. */
export const SHORT = 'The quick brown fox jumps over the lazy dog';
export const PASSWORD = 'correct horse battery staple';

export const KEY_HEX = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'; // 32 bytes (AES-256)
export const IV_HEX = '000102030405060708090a0b0c0d0e0f'; // 16 bytes
export const SALT_HEX = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'; // 16 bytes (PBKDF2)
export const OPENSSL_SALT_HEX = '0011223344556677'; // 8 bytes (crypto-js passphrase mode)

/** `n` pseudo-random bytes from xorshift32 with a fixed seed (same bytes on every run and engine). */
export function fixedBytes(n, seed = 0x2545f491) {
  const out = new Uint8Array(n);
  let x = seed >>> 0;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

/** Big-endian 32-bit words, the layout of a crypto-js WordArray. */
export function bytesToWords(bytes) {
  const words = [];
  for (let i = 0; i < bytes.length; i++) {
    words[i >>> 2] |= bytes[i] << (24 - (i % 4) * 8);
  }
  return words;
}

function utf8Length(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

const TEXT_UNIT = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. שלום עולם, café, naïve 😀 ';

/**
 * Text whose UTF-8 encoding is exactly `bytes` long: TEXT_UNIT repeated (mostly ASCII, with
 * 2-, 3- and 4-byte sequences), padded with ASCII.
 */
export function fixedText(bytes = MiB) {
  const unitLen = utf8Length(TEXT_UNIT);
  const parts = [];
  let len = 0;
  while (len + unitLen <= bytes) {
    parts.push(TEXT_UNIT);
    len += unitLen;
  }
  parts.push('x'.repeat(bytes - len));
  return parts.join('');
}

export { utf8Length };

/**
 * Reading crypto-js passphrase-mode ciphertexts (`CryptoJS.AES.encrypt(text, passphrase).toString()`).
 * Internal: the public surface is `isLegacy`, `decrypt(..., { legacy: true })` and `upgrade`.
 *
 * Format (OpenSSL `enc` compatible): base64 of `"Salted__"` ‖ 8-byte salt ‖ AES-256-CBC ciphertext.
 * Key and IV come from OpenSSL `EVP_BytesToKey` with MD5 and one iteration:
 * D_i = MD5(D_{i-1} ‖ password ‖ salt), key ‖ iv = first 48 bytes of D_1 ‖ D_2 ‖ D_3.
 *
 * This format is NOT authenticated. Wrong passwords are only caught by the PKCS#7 padding check,
 * which about 1 in 256 wrong passwords pass, and the ciphertext can be modified undetectably.
 * @module
 */
import { cbc } from '@noble/ciphers/aes.js';
import { md5 } from '@noble/hashes/legacy.js';
import { base64Decode } from '../internal/base64';
import { decryptFailed } from './cl1';

/** "Salted__" — the OpenSSL salted-format magic. */
const MAGIC = [0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f] as const;
/** base64 of the first 7.5 bytes of the magic: every salted ciphertext starts with this. */
const MAGIC_BASE64_PREFIX = 'U2FsdGVkX1';
const HEADER_BYTES = 16; // magic + salt
const BLOCK_BYTES = 16;

/** A decoded crypto-js passphrase-mode ciphertext. */
export interface LegacyCiphertext {
  readonly salt: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/**
 * Decodes a crypto-js passphrase-mode ciphertext, or returns `undefined` if the string is not one:
 * it must be canonical padded base64 (exactly what `CipherParams#toString()` produces) of
 * `Salted__` ‖ salt ‖ a positive whole number of 16-byte blocks.
 */
export function parseLegacy(token: string): LegacyCiphertext | undefined {
  if (!token.startsWith(MAGIC_BASE64_PREFIX)) return undefined;
  let raw: Uint8Array;
  try {
    raw = base64Decode(token);
  } catch {
    return undefined;
  }
  if (raw.length < HEADER_BYTES + BLOCK_BYTES || raw.length % BLOCK_BYTES !== 0) return undefined;
  for (let i = 0; i < MAGIC.length; i++) if (raw[i] !== MAGIC[i]) return undefined;
  return { salt: raw.subarray(8, HEADER_BYTES), ciphertext: raw.subarray(HEADER_BYTES) };
}

/** OpenSSL EVP_BytesToKey(MD5, count = 1) → 32-byte key ‖ 16-byte IV, as crypto-js computes it. */
function evpBytesToKey(password: Uint8Array, salt: Uint8Array): Uint8Array {
  const out = new Uint8Array(48);
  let block = new Uint8Array(0);
  for (let offset = 0; offset < out.length; offset += block.length) {
    const next = md5.create().update(block).update(password).update(salt).digest();
    block.fill(0);
    block = next;
    out.set(block.subarray(0, out.length - offset), offset);
  }
  block.fill(0);
  return out;
}

/**
 * Decrypts a parsed crypto-js ciphertext (AES-256-CBC, PKCS#7 padding validated by noble).
 * @throws {CryptoliteError} `ERR_DECRYPT` on a padding failure (wrong password or corruption).
 */
export function legacyDecrypt(parsed: LegacyCiphertext, password: Uint8Array): Uint8Array {
  const keyAndIv = evpBytesToKey(password, parsed.salt);
  try {
    return cbc(keyAndIv.subarray(0, 32), keyAndIv.subarray(32, 48)).decrypt(parsed.ciphertext);
  } catch {
    throw decryptFailed();
  } finally {
    keyAndIv.fill(0);
  }
}

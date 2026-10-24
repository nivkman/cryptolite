/**
 * Synchronous hashing and HMAC on @noble/hashes.
 * @module
 */
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { md5 as nobleMd5, sha1 as nobleSha1 } from '@noble/hashes/legacy.js';
import { sha256 as nobleSha256, sha384 as nobleSha384, sha512 as nobleSha512 } from '@noble/hashes/sha2.js';
import { sha3_256 as nobleSha3_256, sha3_512 as nobleSha3_512 } from '@noble/hashes/sha3.js';
import type { CHash } from '@noble/hashes/utils.js';
import { base64Encode, base64UrlEncode } from '../internal/base64';
import { CryptoliteError } from '../internal/errors';
import { hexEncode } from '../internal/hex';
import { inputBytes } from './args';

/**
 * Output encoding for hashes and HMACs.
 *
 * - `'hex'` (default) — lowercase hexadecimal, like `digest('hex')` in Node.
 * - `'base64'` — standard base64 with `=` padding.
 * - `'base64url'` — URL-safe base64 without padding, like Node's `'base64url'`.
 * - `'bytes'` — the raw digest as a `Uint8Array`.
 */
export type Encoding = 'hex' | 'base64' | 'base64url' | 'bytes';

/** Hash algorithms accepted by {@link hmac}. */
export type HmacAlgorithm = 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512';

/**
 * Signature shared by {@link md5}, {@link sha1}, {@link sha256}, {@link sha384},
 * {@link sha512}, {@link sha3_256} and {@link sha3_512}.
 *
 * `data` may be a string (hashed as its UTF-8 bytes) or a `Uint8Array` (including a Node
 * `Buffer`). The result is a string unless `encoding` is `'bytes'`.
 *
 * Throws {@link CryptoliteError} `ERR_PARAMS` for other data types or an unknown encoding, and
 * `ERR_UTF8` for a string containing a lone surrogate (Node would hash U+FFFD instead; silently
 * replacing characters would make different strings hash alike).
 */
export interface HashFunction {
  (data: string | Uint8Array, encoding?: 'hex' | 'base64' | 'base64url'): string;
  (data: string | Uint8Array, encoding: 'bytes'): Uint8Array;
  (data: string | Uint8Array, encoding?: Encoding): string | Uint8Array;
}

/** A noble hash: callable on bytes, and usable by noble's HMAC. */
type Digest = CHash;

function encodeDigest(digest: Uint8Array, encoding: Encoding): string | Uint8Array {
  switch (encoding) {
    case 'hex':
      return hexEncode(digest);
    case 'base64':
      return base64Encode(digest);
    case 'base64url':
      return base64UrlEncode(digest);
    case 'bytes':
      return digest;
  }
}

function checkEncoding(encoding: unknown, fn: string): Encoding {
  if (encoding === undefined) return 'hex';
  if (encoding === 'hex' || encoding === 'base64' || encoding === 'base64url' || encoding === 'bytes') return encoding;
  throw new CryptoliteError(
    'ERR_PARAMS',
    `${fn}(): encoding must be 'hex', 'base64', 'base64url' or 'bytes'.`,
  );
}

function createHash(name: string, digest: Digest): HashFunction {
  const fn = (data: unknown, encoding?: unknown): string | Uint8Array => {
    const bytes = inputBytes(data, name, 'data');
    const enc = checkEncoding(encoding, name);
    return encodeDigest(digest(bytes), enc);
  };
  Object.defineProperty(fn, 'name', { value: name });
  return fn as HashFunction;
}

/**
 * MD5 digest (16 bytes).
 *
 * **Not for security.** MD5 is broken: collisions can be produced in seconds. Use it only to
 * interoperate with existing systems (checksums, ETags, legacy formats); use {@link sha256} for
 * anything new.
 *
 * @param data - string (hashed as UTF-8) or bytes
 * @param encoding - output encoding, default `'hex'`; `'bytes'` returns a `Uint8Array`
 * @example
 * ```ts
 * md5('hello'); // '5d41402abc4b2a76b9719d911017c592'
 * ```
 */
export const md5: HashFunction = /* @__PURE__ */ createHash('md5', nobleMd5);

/**
 * SHA-1 digest (20 bytes).
 *
 * **Not for security.** SHA-1 collisions are practical (SHAttered, 2017). Use it only to
 * interoperate with existing systems; use {@link sha256} for anything new.
 *
 * @param data - string (hashed as UTF-8) or bytes
 * @param encoding - output encoding, default `'hex'`; `'bytes'` returns a `Uint8Array`
 * @example
 * ```ts
 * sha1('hello'); // 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
 * ```
 */
export const sha1: HashFunction = /* @__PURE__ */ createHash('sha1', nobleSha1);

/**
 * SHA-256 digest (32 bytes), FIPS 180-4.
 *
 * Hashing is not password storage: for passwords use a slow KDF, not a bare hash.
 *
 * @param data - string (hashed as UTF-8) or bytes
 * @param encoding - output encoding, default `'hex'`; `'bytes'` returns a `Uint8Array`
 * @example
 * ```ts
 * sha256('hello'); // '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
 * sha256(fileBytes, 'base64url'); // URL-safe digest
 * sha256('hello', 'bytes'); // Uint8Array(32)
 * ```
 */
export const sha256: HashFunction = /* @__PURE__ */ createHash('sha256', nobleSha256);

/**
 * SHA-384 digest (48 bytes), FIPS 180-4.
 *
 * @param data - string (hashed as UTF-8) or bytes
 * @param encoding - output encoding, default `'hex'`; `'bytes'` returns a `Uint8Array`
 * @example
 * ```ts
 * // Subresource Integrity value
 * const integrity = 'sha384-' + sha384(scriptBytes, 'base64');
 * ```
 */
export const sha384: HashFunction = /* @__PURE__ */ createHash('sha384', nobleSha384);

/**
 * SHA-512 digest (64 bytes), FIPS 180-4.
 *
 * @param data - string (hashed as UTF-8) or bytes
 * @param encoding - output encoding, default `'hex'`; `'bytes'` returns a `Uint8Array`
 * @example
 * ```ts
 * sha512('hello');
 * ```
 */
export const sha512: HashFunction = /* @__PURE__ */ createHash('sha512', nobleSha512);

/**
 * SHA3-256 digest (32 bytes): standard FIPS 202 SHA-3, identical to Node's `'sha3-256'` and
 * Python's `hashlib.sha3_256`.
 *
 * **Not the same as crypto-js `CryptoJS.SHA3`**, which implements the original Keccak
 * submission (different padding) and returns different digests for the same input. To
 * reproduce crypto-js output, use the compat API (`CryptoJS.SHA3`) instead.
 *
 * @param data - string (hashed as UTF-8) or bytes
 * @param encoding - output encoding, default `'hex'`; `'bytes'` returns a `Uint8Array`
 * @example
 * ```ts
 * sha3_256(''); // 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
 * ```
 */
export const sha3_256: HashFunction = /* @__PURE__ */ createHash('sha3_256', nobleSha3_256);

/**
 * SHA3-512 digest (64 bytes): standard FIPS 202 SHA-3, identical to Node's `'sha3-512'` and
 * Python's `hashlib.sha3_512`.
 *
 * **Not the same as crypto-js `CryptoJS.SHA3`**, which implements the original Keccak
 * submission (different padding) and returns different digests for the same input. To
 * reproduce crypto-js output, use the compat API (`CryptoJS.SHA3`) instead.
 *
 * @param data - string (hashed as UTF-8) or bytes
 * @param encoding - output encoding, default `'hex'`; `'bytes'` returns a `Uint8Array`
 * @example
 * ```ts
 * sha3_512('hello');
 * ```
 */
export const sha3_512: HashFunction = /* @__PURE__ */ createHash('sha3_512', nobleSha3_512);

function hmacDigest(algorithm: unknown): Digest {
  switch (algorithm) {
    case 'md5':
      return nobleMd5;
    case 'sha1':
      return nobleSha1;
    case 'sha256':
      return nobleSha256;
    case 'sha384':
      return nobleSha384;
    case 'sha512':
      return nobleSha512;
    default:
      throw new CryptoliteError(
        'ERR_PARAMS',
        "hmac(): algorithm must be 'md5', 'sha1', 'sha256', 'sha384' or 'sha512'.",
      );
  }
}

/**
 * HMAC (RFC 2104) of `data` under `key`, synchronously.
 *
 * Use it to sign and verify messages with a shared secret. `'sha256'` or stronger is
 * recommended; HMAC-MD5 and HMAC-SHA1 exist for compatibility (as MACs they are not known to be
 * practically broken, unlike MD5 and SHA-1 as plain hashes). When verifying a received MAC,
 * compare in constant time (in Node: `crypto.timingSafeEqual`), never with `===`.
 *
 * @param algorithm - `'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512'`
 * @param key - string (UTF-8) or bytes; any length, including empty
 * @param data - string (UTF-8) or bytes
 * @param encoding - output encoding, default `'hex'`; `'bytes'` returns a `Uint8Array`
 * @throws {CryptoliteError} `ERR_PARAMS` for an unknown algorithm or encoding, or a key/data
 *   that is neither a string nor a `Uint8Array`; `ERR_UTF8` for a string with a lone surrogate.
 *
 * @example
 * ```ts
 * import { hmac } from 'cryptolite';
 * const signature = hmac('sha256', secret, payload, 'base64url');
 * ```
 */
export function hmac(
  algorithm: HmacAlgorithm,
  key: string | Uint8Array,
  data: string | Uint8Array,
  encoding?: 'hex' | 'base64' | 'base64url',
): string;
export function hmac(algorithm: HmacAlgorithm, key: string | Uint8Array, data: string | Uint8Array, encoding: 'bytes'): Uint8Array;
export function hmac(
  algorithm: HmacAlgorithm,
  key: string | Uint8Array,
  data: string | Uint8Array,
  encoding?: Encoding,
): string | Uint8Array;
export function hmac(algorithm: unknown, key: unknown, data: unknown, encoding?: unknown): string | Uint8Array {
  const digest = hmacDigest(algorithm);
  const keyBytes = inputBytes(key, 'hmac', 'key');
  const dataBytes = inputBytes(data, 'hmac', 'data');
  const enc = checkEncoding(encoding, 'hmac');
  try {
    return encodeDigest(nobleHmac(digest, keyBytes, dataBytes), enc);
  } finally {
    if (typeof key === 'string') keyBytes.fill(0); // our copy of the secret
  }
}

/**
 * cryptolite modern API: password-based authenticated encryption (AES-256-GCM + PBKDF2), an
 * opt-in path to read and upgrade crypto-js ciphertexts, and synchronous hashing/HMAC.
 *
 * Exactly the public surface: everything exported here is re-exported from the package root and
 * attached to the CommonJS export object. See docs/SPEC-modern.md.
 * @module
 */
export { decrypt, decryptBytes, encrypt, isLegacy, upgrade } from './encryption';
export type { DecryptOptions, EncryptOptions } from './encryption';

export { hmac, md5, sha1, sha256, sha3_256, sha3_512, sha384, sha512 } from './hash';
export type { Encoding, HashFunction, HmacAlgorithm } from './hash';

export { randomBytes } from '../internal/random';

export { CryptoliteError } from '../internal/errors';
export type { CryptoliteErrorCode } from '../internal/errors';

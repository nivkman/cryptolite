/*
 * Hash algorithms with the crypto-js Hasher API (create/update/finalize/reset/clone and the
 * CryptoJS.SHA256(...) helpers), backed by audited @noble/hashes implementations.
 *
 * crypto-js "SHA3" is Keccak with the ORIGINAL padding (0x01) and a configurable
 * `outputLength` (default 512) — it is NOT FIPS-202 SHA-3. We reproduce that exactly with
 * noble's Keccak core.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { md5, ripemd160, sha1 } from '@noble/hashes/legacy.js';
import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { Keccak, keccak_512 } from '@noble/hashes/sha3.js';
import { C, C_algo, Hasher, fromBytes, isWordArrayLike, toBytes, type Any } from './core';

/** Base for hashers whose compression function is delegated to noble. */
export const NobleHasher: Any = Hasher.extend({
  _newHash(): Any {
    throw new Error('cryptolite: NobleHasher._newHash not implemented');
  },

  _doReset(this: Any): void {
    this._noble = this._newHash();
  },

  update(this: Any, messageUpdate: Any): Any {
    this._noble.update(toBytes(messageUpdate));
    return this;
  },

  finalize(this: Any, messageUpdate?: Any): Any {
    if (messageUpdate) {
      this._noble.update(toBytes(messageUpdate));
    }
    return fromBytes(this._noble.digest());
  },

  clone(this: Any): Any {
    const clone = Hasher.clone.call(this);
    clone._noble = this._noble.clone();
    return clone;
  },
});

export const MD5: Any = (C_algo.MD5 = NobleHasher.extend({ _newHash: () => md5.create() }));
export const SHA1: Any = (C_algo.SHA1 = NobleHasher.extend({ _newHash: () => sha1.create() }));
export const SHA256: Any = (C_algo.SHA256 = NobleHasher.extend({ _newHash: () => sha256.create() }));
export const SHA224: Any = (C_algo.SHA224 = SHA256.extend({ _newHash: () => sha224.create() }));
export const SHA512: Any = (C_algo.SHA512 = NobleHasher.extend({
  _newHash: () => sha512.create(),
  blockSize: 1024 / 32,
}));
export const SHA384: Any = (C_algo.SHA384 = SHA512.extend({ _newHash: () => sha384.create() }));
export const RIPEMD160: Any = (C_algo.RIPEMD160 = NobleHasher.extend({
  _newHash: () => ripemd160.create(),
}));

export const SHA3: Any = (C_algo.SHA3 = NobleHasher.extend({
  cfg: Hasher.cfg.extend({
    outputLength: 512,
  }),

  _doReset(this: Any): void {
    const outputLength = this.cfg.outputLength;
    // Same rate computation as crypto-js (blockSize is in 32-bit words).
    this.blockSize = (1600 - 2 * outputLength) / 32;
    this._noble = new Keccak(this.blockSize * 4, 0x01, outputLength / 8);
  },
}));

const isMessage = (m: Any): boolean => typeof m === 'string' || isWordArrayLike(m);

/**
 * `CryptoJS.SHA256(message, cfg)`-style helper. Same as crypto-js's
 * `new hasher.init(cfg).finalize(message)`, with a one-shot noble fast path for the common
 * case (default config, string or WordArray message).
 */
function hashHelper(hasher: Any, nobleHash: Any) {
  return function (message: Any, cfg?: Any): Any {
    if (cfg === undefined && isMessage(message)) {
      return fromBytes(nobleHash(toBytes(message)));
    }
    return new hasher.init(cfg).finalize(message);
  };
}

/** `CryptoJS.HmacSHA256(message, key)`-style helper (note: message first, like crypto-js). */
function hmacHelper(hasher: Any, nobleHash: Any) {
  return function (message: Any, key: Any): Any {
    if (isMessage(message) && isMessage(key)) {
      return fromBytes(nobleHmac(nobleHash, toBytes(key), toBytes(message)));
    }
    return new C_algo.HMAC.init(hasher, key).finalize(message);
  };
}

C.MD5 = hashHelper(MD5, md5);
C.HmacMD5 = hmacHelper(MD5, md5);
C.SHA1 = hashHelper(SHA1, sha1);
C.HmacSHA1 = hmacHelper(SHA1, sha1);
C.SHA256 = hashHelper(SHA256, sha256);
C.HmacSHA256 = hmacHelper(SHA256, sha256);
C.SHA224 = hashHelper(SHA224, sha224);
C.HmacSHA224 = hmacHelper(SHA224, sha224);
C.SHA512 = hashHelper(SHA512, sha512);
C.HmacSHA512 = hmacHelper(SHA512, sha512);
C.SHA384 = hashHelper(SHA384, sha384);
C.HmacSHA384 = hmacHelper(SHA384, sha384);
C.SHA3 = hashHelper(SHA3, keccak_512);
C.HmacSHA3 = hmacHelper(SHA3, keccak_512);
C.RIPEMD160 = hashHelper(RIPEMD160, ripemd160);
C.HmacRIPEMD160 = hmacHelper(RIPEMD160, ripemd160);

/**
 * noble hash functions equivalent to our hashers in their DEFAULT configuration. Used by the
 * PBKDF2 fast path. Only exact identity matches are used, so user subclasses and custom
 * hashers always take the generic (crypto-js-identical) path.
 */
export const NOBLE_EQUIVALENT = new Map<Any, Any>([
  [MD5, md5],
  [SHA1, sha1],
  [SHA224, sha224],
  [SHA256, sha256],
  [SHA384, sha384],
  [SHA512, sha512],
  [RIPEMD160, ripemd160],
  [SHA3, keccak_512],
]);

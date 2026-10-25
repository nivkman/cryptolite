/*
 * Hash algorithms with the crypto-js Hasher API (create/update/finalize/reset/clone and the
 * CryptoJS.SHA256(...) helpers).
 *
 * Hasher objects are crypto-js's own design — its buffering (BufferedBlockAlgorithm) and its
 * padding code (`_doFinalize`, ported verbatim) — with only the compression function delegated
 * to audited @noble/hashes code. That keeps output identical to crypto-js even for inputs where
 * crypto-js deviates from the standard: a WordArray whose last word has bytes beyond `sigBytes`
 * (e.g. straight out of `AES.decrypt`) leaks those bytes into the padding, and a fractional
 * `sigBytes` (e.g. `Hex.parse('abc')`) hashes a bit-length message.
 *
 * The one-shot helpers (`CryptoJS.SHA256(message)`) skip all of that and call noble directly
 * when the input is "clean" (a string, or a WordArray with a whole number of bytes and nothing
 * beyond them), which is where the speed comes from. Both paths are differential-tested
 * against crypto-js 4.2.0.
 *
 * crypto-js "SHA3" is Keccak with the ORIGINAL padding (0x01) and a configurable
 * `outputLength` (default 512) — it is NOT FIPS-202 SHA-3. We reproduce that exactly.
 *
 * Portions (c) 2009-2013 Jeff Mott, (c) 2013-2016 Evan Vosberg, MIT License (crypto-js).
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { _MD5, _RIPEMD160, _SHA1, md5, ripemd160, sha1 } from '@noble/hashes/legacy.js';
import { _SHA224, _SHA256, _SHA384, _SHA512, sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { keccakP, keccak_512 } from '@noble/hashes/sha3.js';
import { C, C_algo, Hasher, WordArray, fromBytes, isCleanMessage, isWordArrayLike, toBytes, type Any } from './core';

function swapEndian(word: number): number {
  return (((word << 8) | (word >>> 24)) & 0x00ff00ff) | (((word << 24) | (word >>> 8)) & 0xff00ff00);
}

// ---------------------------------------------------------------------------------------------
// Merkle–Damgård hashers (MD5, SHA-1, SHA-2, RIPEMD-160): noble `process()` per block
// ---------------------------------------------------------------------------------------------

/**
 * Base for MD-family hashers. `_newCore()` returns a fresh noble hash object (initial state);
 * crypto-js's BufferedBlockAlgorithm hands it one block of words at a time.
 */
const MDHasher: Any = Hasher.extend({
  _newCore(): Any {
    throw new Error('cryptolite: MDHasher._newCore not implemented');
  },

  _doReset(this: Any): void {
    this._core = this._newCore();
    this._hashSigBytes = undefined;
    this._blockView = new DataView(new ArrayBuffer(this.blockSize * 4));
  },

  _doProcessBlock(this: Any, M: number[], offset: number): void {
    // crypto-js reads words with `| 0` (undefined/NaN → 0); write them big-endian and let noble
    // read them in its own byte order (big-endian for SHA, little-endian for MD5/RIPEMD-160,
    // which is exactly crypto-js's byte swap).
    const view = this._blockView;
    const n = this.blockSize;
    for (let i = 0; i < n; i++) {
      view.setUint32(i * 4, M[offset + i] | 0, false);
    }
    this._core.process(view, 0);
  },

  clone(this: Any): Any {
    const clone = Hasher.clone.call(this);
    clone._core = this._core.clone();
    clone._blockView = new DataView(new ArrayBuffer(this.blockSize * 4));
    return clone;
  },
});

/** crypto-js's big-endian 64-bit-length padding (SHA-1 and SHA-256 use the same code). */
function padBigEndian64(self: Any): void {
  const data = self._data;
  const dataWords = data.words;
  const nBitsTotal = self._nDataBytes * 8;
  const nBitsLeft = data.sigBytes * 8;
  dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));
  dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
  dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
  data.sigBytes = dataWords.length * 4;
  self._process();
}

function stateWords(self: Any): number[] {
  return Array.prototype.slice.call(self._core.get()).map((w: number) => w | 0);
}

/**
 * MD5 and RIPEMD-160 in crypto-js byte-swap their live hash state in place to produce the
 * digest, so finalizing again without reset() continues from the swapped state. Mirror that.
 */
function swapStateInPlace(self: Any, sigBytes: number): Any {
  const swapped = stateWords(self).map(swapEndian);
  self._core.set(...swapped);
  return new WordArray.init(swapped, sigBytes);
}

export const MD5: Any = (C_algo.MD5 = MDHasher.extend({
  _newCore: () => new _MD5(),

  _doFinalize(this: Any): Any {
    const data = this._data;
    const dataWords = data.words;
    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));
    const nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
    const nBitsTotalL = nBitsTotal;
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] =
      (((nBitsTotalH << 8) | (nBitsTotalH >>> 24)) & 0x00ff00ff) |
      (((nBitsTotalH << 24) | (nBitsTotalH >>> 8)) & 0xff00ff00);
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] =
      (((nBitsTotalL << 8) | (nBitsTotalL >>> 24)) & 0x00ff00ff) |
      (((nBitsTotalL << 24) | (nBitsTotalL >>> 8)) & 0xff00ff00);
    data.sigBytes = (dataWords.length + 1) * 4;
    this._process();
    return swapStateInPlace(this, 16);
  },
}));

export const SHA1: Any = (C_algo.SHA1 = MDHasher.extend({
  _newCore: () => new _SHA1(),

  _doFinalize(this: Any): Any {
    padBigEndian64(this);
    return new WordArray.init(stateWords(this), 20);
  },
}));

export const SHA256: Any = (C_algo.SHA256 = MDHasher.extend({
  _newCore: () => new _SHA256(),

  _doFinalize(this: Any): Any {
    padBigEndian64(this);
    return new WordArray.init(stateWords(this), this._hashSigBytes ?? 32);
  },
}));

export const SHA224: Any = (C_algo.SHA224 = SHA256.extend({
  _newCore: () => new _SHA224(),

  _doFinalize(this: Any): Any {
    // Like crypto-js: all eight state words, sigBytes 28. crypto-js returns (and shrinks) its
    // live hash object, so each further finalize() without reset() is 4 bytes shorter.
    const hash = SHA256._doFinalize.call(this);
    hash.sigBytes -= 4;
    this._hashSigBytes = hash.sigBytes;
    return hash;
  },
}));

export const SHA512: Any = (C_algo.SHA512 = MDHasher.extend({
  _newCore: () => new _SHA512(),

  _doFinalize(this: Any): Any {
    const data = this._data;
    const dataWords = data.words;
    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));
    dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
    dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
    data.sigBytes = dataWords.length * 4;
    this._process();
    // noble's state is [Ah, Al, Bh, Bl, ...], the same order as crypto-js's toX32().
    return new WordArray.init(stateWords(this), 64);
  },

  blockSize: 1024 / 32,
}));

export const SHA384: Any = (C_algo.SHA384 = SHA512.extend({
  _newCore: () => new _SHA384(),

  _doFinalize(this: Any): Any {
    const hash = SHA512._doFinalize.call(this);
    hash.sigBytes -= 16;
    return hash;
  },
}));

export const RIPEMD160: Any = (C_algo.RIPEMD160 = MDHasher.extend({
  _newCore: () => new _RIPEMD160(),

  _doFinalize(this: Any): Any {
    const data = this._data;
    const dataWords = data.words;
    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] =
      (((nBitsTotal << 8) | (nBitsTotal >>> 24)) & 0x00ff00ff) |
      (((nBitsTotal << 24) | (nBitsTotal >>> 8)) & 0xff00ff00);
    data.sigBytes = (dataWords.length + 1) * 4;
    this._process();
    return swapStateInPlace(this, 20);
  },
}));

// ---------------------------------------------------------------------------------------------
// Keccak ("SHA3" in crypto-js): noble's keccak-f[1600] permutation per block
// ---------------------------------------------------------------------------------------------

export const SHA3: Any = (C_algo.SHA3 = Hasher.extend({
  cfg: Hasher.cfg.extend({
    outputLength: 512,
  }),

  _doReset(this: Any): void {
    const outputLength = this.cfg.outputLength;
    const blockSize = (1600 - 2 * outputLength) / 32;
    // crypto-js computes garbage, or loops forever, for other values; refuse them clearly.
    if (!(Number.isInteger(blockSize) && blockSize > 0 && blockSize <= 50 && blockSize % 2 === 0)) {
      throw new Error(
        `cryptolite: SHA3 outputLength must be a multiple of 32 from 0 to 768 (got ${outputLength}).`,
      );
    }
    this.blockSize = blockSize;
    // 25 lanes as 50 little-endian 32-bit halves — the layout noble's keccakP permutes.
    this._state = new Uint32Array(50);
  },

  _doProcessBlock(this: Any, M: number[], offset: number): void {
    const state = this._state;
    const nBlockSizeLanes = this.blockSize / 2;
    for (let i = 0; i < nBlockSizeLanes; i++) {
      state[2 * i] ^= swapEndian(M[offset + 2 * i] | 0);
      state[2 * i + 1] ^= swapEndian(M[offset + 2 * i + 1] | 0);
    }
    keccakP(state, 24);
  },

  _doFinalize(this: Any): Any {
    const data = this._data;
    const dataWords = data.words;
    const nBitsLeft = data.sigBytes * 8;
    const blockSizeBits = this.blockSize * 32;
    dataWords[nBitsLeft >>> 5] |= 0x1 << (24 - (nBitsLeft % 32));
    dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80;
    data.sigBytes = dataWords.length * 4;
    this._process();

    const state = this._state;
    const outputLengthBytes = this.cfg.outputLength / 8;
    const outputLengthLanes = outputLengthBytes / 8;
    const hashWords: number[] = [];
    for (let i = 0; i < outputLengthLanes; i++) {
      hashWords.push(swapEndian(state[2 * i]));
      hashWords.push(swapEndian(state[2 * i + 1]));
    }
    return new WordArray.init(hashWords, outputLengthBytes);
  },

  clone(this: Any): Any {
    const clone = Hasher.clone.call(this);
    clone._state = this._state.slice();
    return clone;
  },
}));

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/**
 * SHA-224/384 digests are WordArrays with extra words beyond `sigBytes` in crypto-js (all of the
 * hash state); only the full hasher reproduces that, so they have no one-shot fast path.
 */
const hasFastPath = (hasher: Any): boolean => hasher !== SHA224 && hasher !== SHA384;

/**
 * `CryptoJS.SHA256(message, cfg)`-style helper: crypto-js's `new hasher.init(cfg).finalize(message)`,
 * with a one-shot noble fast path for clean input and the default config.
 */
function hashHelper(hasher: Any, nobleHash: Any) {
  const { _doFinalize, _doProcessBlock } = hasher;
  const fast = hasFastPath(hasher);
  // SHA-224/384: standard one-shot digest, then the full state crypto-js returns as words.
  const FullState = hasher === SHA224 ? _SHA224 : hasher === SHA384 ? _SHA384 : undefined;
  return function (message: Any, cfg?: Any): Any {
    if (
      cfg === undefined &&
      hasher._doFinalize === _doFinalize &&
      hasher._doProcessBlock === _doProcessBlock &&
      isCleanMessage(message)
    ) {
      if (fast) return fromBytes(nobleHash(toBytes(message)));
      if (FullState) {
        const core: Any = new FullState(); // get() is protected in the types; stable in the pinned build
        core.update(toBytes(message));
        core.digestInto(new Uint8Array(core.outputLen));
        return new WordArray.init(
          Array.prototype.slice.call(core.get()).map((w: number) => w | 0),
          core.outputLen,
        );
      }
    }
    return new hasher.init(cfg).finalize(message);
  };
}

/**
 * The HMAC key bytes crypto-js would use, or undefined when only the full HMAC object is exact.
 * Keys longer than the block are hashed (so must be clean); shorter ones are clamped first,
 * which crypto-js does to the caller's WordArray in place — and so do we.
 */
function hmacKeyBytes(key: Any, blockLen: number): Uint8Array | undefined {
  if (typeof key === 'string') return toBytes(key);
  if (!isWordArrayLike(key)) return undefined;
  if (key.sigBytes > blockLen) return isCleanMessage(key) ? toBytes(key) : undefined;
  key.clamp();
  return toBytes(key);
}

/** `CryptoJS.HmacSHA256(message, key)`-style helper (note: message first, like crypto-js). */
function hmacHelper(hasher: Any, nobleHash: Any) {
  const { _doFinalize, _doProcessBlock } = hasher;
  const fast = hasFastPath(hasher);
  return function (message: Any, key: Any): Any {
    if (
      fast &&
      hasher._doFinalize === _doFinalize &&
      hasher._doProcessBlock === _doProcessBlock &&
      isCleanMessage(message)
    ) {
      const keyBytes = hmacKeyBytes(key, nobleHash.blockLen);
      if (keyBytes) {
        return fromBytes(nobleHmac(nobleHash, keyBytes, toBytes(message)));
      }
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
 * noble hash functions equivalent to our hashers in their DEFAULT configuration, for the
 * PBKDF2/EvpKDF fast paths. Only exact identity matches are used, so user subclasses and custom
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

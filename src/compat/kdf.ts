/*
 * crypto-js PBKDF2 and EvpKDF.
 *
 * PBKDF2 keeps crypto-js 4.2.0 defaults (SHA256, 250000 iterations, 128-bit key). For the
 * built-in hashers with sane parameters it runs noble's PBKDF2 (same standard algorithm, much
 * faster); anything unusual falls back to the verbatim crypto-js loop so results always match.
 *
 * Portions (c) 2009-2013 Jeff Mott, (c) 2013-2016 Evan Vosberg, MIT License (crypto-js).
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2.js';
import { Base, C, C_algo, WordArray, fromBytes, isWordArrayLike, toBytes, type Any } from './core';
import { MD5, NOBLE_EQUIVALENT, SHA256 } from './hashers';
import { HMAC } from './hmac';

export const PBKDF2: Any = (C_algo.PBKDF2 = Base.extend({
  cfg: Base.extend({
    keySize: 128 / 32,
    hasher: SHA256,
    iterations: 250000,
  }),

  init: function (this: Any, cfg?: Any): void {
    this.cfg = this.cfg.extend(cfg);
  },

  compute(this: Any, password: Any, salt: Any): Any {
    const cfg = this.cfg;
    const keySize = cfg.keySize;
    const iterations = cfg.iterations;

    const nobleHash = NOBLE_EQUIVALENT.get(cfg.hasher);
    const dkLen = keySize * 4;
    if (
      nobleHash &&
      Number.isInteger(iterations) &&
      iterations >= 1 &&
      Number.isInteger(dkLen) &&
      dkLen > 0
    ) {
      return fromBytes(
        noblePbkdf2(nobleHash, toBytes(password), toBytes(salt), { c: iterations, dkLen }),
      );
    }

    // Generic path: verbatim crypto-js.
    const hmac = HMAC.create(cfg.hasher, password);
    const derivedKey = WordArray.create();
    const blockIndex = WordArray.create([0x00000001]);
    const derivedKeyWords = derivedKey.words;
    const blockIndexWords = blockIndex.words;

    while (derivedKeyWords.length < keySize) {
      const block = hmac.update(salt).finalize(blockIndex);
      hmac.reset();

      const blockWords = block.words;
      const blockWordsLength = blockWords.length;

      let intermediate = block;
      for (let i = 1; i < iterations; i++) {
        intermediate = hmac.finalize(intermediate);
        hmac.reset();
        const intermediateWords = intermediate.words;
        for (let j = 0; j < blockWordsLength; j++) {
          blockWords[j] ^= intermediateWords[j];
        }
      }

      derivedKey.concat(block);
      blockIndexWords[0]++;
    }
    derivedKey.sigBytes = keySize * 4;

    return derivedKey;
  },
}));

C.PBKDF2 = function (password: Any, salt: Any, cfg?: Any): Any {
  return PBKDF2.create(cfg).compute(password, salt);
};

/**
 * EvpKDF (OpenSSL EVP_BytesToKey) with one-shot noble hashes. Produces the same words as the
 * crypto-js loop — every full digest round is kept, because OpenSSLKdf slices the IV out of
 * the words beyond `keySize` — or returns undefined to use the verbatim path.
 */
function evpFast(cfg: Any, password: Any, salt: Any): Any {
  const nobleHash = NOBLE_EQUIVALENT.get(cfg.hasher);
  const keySize = cfg.keySize;
  const iterations = cfg.iterations;
  if (!nobleHash || !Number.isInteger(iterations) || iterations < 1) return undefined;
  if (!Number.isInteger(keySize * 4) || keySize <= 0) return undefined;
  if (!isMessage(password)) return undefined;
  if (!(salt === undefined || salt === '' || isMessage(salt))) return undefined;

  const pw = toBytes(password);
  const sl = salt ? toBytes(salt) : new Uint8Array(0);
  const digestLen: number = nobleHash.outputLen;
  const rounds = Math.ceil(keySize / (digestLen / 4));
  const out = new Uint8Array(rounds * digestLen);

  let block: Uint8Array | undefined;
  for (let r = 0; r < rounds; r++) {
    const prefix = block ? block.length : 0;
    const input = new Uint8Array(prefix + pw.length + sl.length);
    if (block) input.set(block, 0);
    input.set(pw, prefix);
    input.set(sl, prefix + pw.length);
    block = nobleHash(input) as Uint8Array;
    for (let i = 1; i < iterations; i++) {
      block = nobleHash(block) as Uint8Array;
    }
    out.set(block, r * digestLen);
  }

  const derivedKey = fromBytes(out);
  derivedKey.sigBytes = keySize * 4;
  return derivedKey;
}

const isMessage = (m: Any): boolean => typeof m === 'string' || isWordArrayLike(m);

export const EvpKDF: Any = (C_algo.EvpKDF = Base.extend({
  cfg: Base.extend({
    keySize: 128 / 32,
    hasher: MD5,
    iterations: 1,
  }),

  init: function (this: Any, cfg?: Any): void {
    this.cfg = this.cfg.extend(cfg);
  },

  compute(this: Any, password: Any, salt: Any): Any {
    const fast = evpFast(this.cfg, password, salt);
    if (fast) return fast;

    let block;
    const cfg = this.cfg;
    const hasher = cfg.hasher.create();
    const derivedKey = WordArray.create();
    const derivedKeyWords = derivedKey.words;
    const keySize = cfg.keySize;
    const iterations = cfg.iterations;

    while (derivedKeyWords.length < keySize) {
      if (block) {
        hasher.update(block);
      }
      block = hasher.update(password).finalize(salt);
      hasher.reset();

      for (let i = 1; i < iterations; i++) {
        block = hasher.finalize(block);
        hasher.reset();
      }

      derivedKey.concat(block);
    }
    derivedKey.sigBytes = keySize * 4;

    return derivedKey;
  },
}));

C.EvpKDF = function (password: Any, salt: Any, cfg?: Any): Any {
  return EvpKDF.create(cfg).compute(password, salt);
};

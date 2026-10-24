/*
 * crypto-js HMAC (generic over any Hasher), ported verbatim.
 * Portions (c) 2009-2013 Jeff Mott, (c) 2013-2016 Evan Vosberg, MIT License (crypto-js).
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Base, C_algo, Utf8, type Any } from './core';

export const HMAC: Any = (C_algo.HMAC = Base.extend({
  init: function (this: Any, hasher: Any, key: Any): void {
    hasher = this._hasher = new hasher.init();

    if (typeof key == 'string') {
      key = Utf8.parse(key);
    }

    const hasherBlockSize = hasher.blockSize;
    const hasherBlockSizeBytes = hasherBlockSize * 4;

    if (key.sigBytes > hasherBlockSizeBytes) {
      key = hasher.finalize(key);
    }
    key.clamp();

    const oKey = (this._oKey = key.clone());
    const iKey = (this._iKey = key.clone());
    const oKeyWords = oKey.words;
    const iKeyWords = iKey.words;
    for (let i = 0; i < hasherBlockSize; i++) {
      oKeyWords[i] ^= 0x5c5c5c5c;
      iKeyWords[i] ^= 0x36363636;
    }
    oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

    this.reset();
  },

  reset(this: Any): void {
    const hasher = this._hasher;
    hasher.reset();
    hasher.update(this._iKey);
  },

  update(this: Any, messageUpdate: Any): Any {
    this._hasher.update(messageUpdate);
    return this;
  },

  finalize(this: Any, messageUpdate?: Any): Any {
    const hasher = this._hasher;
    const innerHash = hasher.finalize(messageUpdate);
    hasher.reset();
    return hasher.finalize(this._oKey.clone().concat(innerHash));
  },
}));

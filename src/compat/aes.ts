/*
 * AES with the crypto-js BlockCipher API. The key schedule and block function are noble's
 * audited AES (@noble/ciphers); everything around it (modes, padding, OpenSSL format,
 * passphrase KDF) is the ported crypto-js framework in ./cipher-core.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { cbc, ecb, unsafe } from '@noble/ciphers/aes.js';
import { C, fromBytes, isWordArrayLike, toBytes, type Any } from './core';
import { BlockCipher, CBC, Pkcs7 } from './cipher-core';
import { ECB } from './modes';
import { NoPadding } from './pads';

function wordsToBlock(words: number[], offset: number, block: Uint8Array): void {
  for (let i = 0; i < 4; i++) {
    const w = words[offset + i];
    block[i * 4] = w >>> 24;
    block[i * 4 + 1] = w >>> 16;
    block[i * 4 + 2] = w >>> 8;
    block[i * 4 + 3] = w;
  }
}

function blockToWords(block: Uint8Array, words: number[], offset: number): void {
  for (let i = 0; i < 4; i++) {
    words[offset + i] =
      (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
  }
}

/**
 * One-shot fast path for the overwhelmingly common case: a whole message passed to
 * `finalize` (which is what `CryptoJS.AES.encrypt/decrypt` do) in CBC or ECB mode with
 * Pkcs7 or NoPadding. Runs noble's whole-message CBC/ECB. Returns undefined whenever the
 * situation is in any way unusual, so the verbatim crypto-js block-by-block path handles it.
 *
 * Fidelity notes:
 * - crypto-js reads the IV as raw `iv.words[0..3]` ignoring `sigBytes`; we do the same.
 * - On decrypt we never let noble validate padding: we decrypt without padding and apply
 *   crypto-js's own (non-validating) unpad, so wrong keys behave exactly as in crypto-js.
 */
function fastFinalize(self: Any, dataUpdate: Any): Any {
  if (self._data.sigBytes !== 0 || self._nDataBytes !== 0) return undefined; // process() was used
  if (!(dataUpdate === undefined || dataUpdate === '' || typeof dataUpdate === 'string' || isWordArrayLike(dataUpdate))) {
    return undefined;
  }
  const cfg = self.cfg;
  const mode = cfg.mode;
  const padding = cfg.padding;
  if (mode !== CBC && mode !== ECB) return undefined;
  if (padding !== Pkcs7 && padding !== NoPadding) return undefined;

  let iv: Uint8Array | undefined;
  if (mode === CBC) {
    const ivWords = cfg.iv && cfg.iv.words;
    if (!Array.isArray(ivWords)) return undefined; // crypto-js throws here; let it.
    iv = new Uint8Array(16);
    for (let i = 0; i < 4; i++) {
      const w = ivWords[i];
      if (w !== undefined && !Number.isInteger(w)) return undefined;
      iv[i * 4] = w >>> 24;
      iv[i * 4 + 1] = w >>> 16;
      iv[i * 4 + 2] = w >>> 8;
      iv[i * 4 + 3] = w;
    }
  }

  const data = dataUpdate ? toBytes(dataUpdate) : new Uint8Array(0);
  const key = self._keyBytes;

  if (self._xformMode == self._ENC_XFORM_MODE) {
    if (padding === NoPadding && data.length % 16 !== 0) return undefined;
    const disablePadding = padding === NoPadding;
    const c = mode === CBC ? cbc(key, iv!, { disablePadding }) : ecb(key, { disablePadding });
    return fromBytes(c.encrypt(data));
  }

  if (data.length === 0 || data.length % 16 !== 0) return undefined;
  const c = mode === CBC ? cbc(key, iv!, { disablePadding: true }) : ecb(key, { disablePadding: true });
  const plaintext = fromBytes(c.decrypt(data));
  padding.unpad(plaintext);
  return plaintext;
}

export const AESAlgo: Any = (C.algo.AES = BlockCipher.extend({
  finalize(this: Any, dataUpdate?: Any): Any {
    const fast = fastFinalize(this, dataUpdate);
    return fast !== undefined ? fast : BlockCipher.finalize.call(this, dataUpdate);
  },

  _doReset(this: Any): void {
    // Skip reset of nRounds has been set before and key did not change (crypto-js behaviour).
    if (this._nRounds && this._keyPriorReset === this._key) {
      return;
    }

    const key = (this._keyPriorReset = this._key);
    const keyBytes = toBytes(key);
    const n = keyBytes.length;
    if (n !== 16 && n !== 24 && n !== 32) {
      throw new Error(
        `cryptolite: AES key must be 16, 24 or 32 bytes (got ${key.sigBytes}). ` +
          'crypto-js silently accepted other sizes and produced non-standard ciphertext that no ' +
          'other AES implementation can read. Pass a string to use a passphrase instead, or ' +
          'derive a proper key with PBKDF2. See MIGRATION.md#aes-key-sizes.',
      );
    }

    this._keyBytes = keyBytes;
    this._encKey = unsafe.expandKeyLE(keyBytes);
    this._decKey = undefined; // derived lazily: CFB/CTR/OFB never need it
    this._block = new Uint8Array(16);
    this._nRounds = n / 4 + 6;
  },

  encryptBlock(this: Any, M: number[], offset: number): void {
    const block = this._block;
    wordsToBlock(M, offset, block);
    unsafe.encryptBlock(this._encKey, block);
    blockToWords(block, M, offset);
  },

  decryptBlock(this: Any, M: number[], offset: number): void {
    if (!this._decKey) {
      this._decKey = unsafe.expandKeyDecLE(this._keyBytes);
    }
    const block = this._block;
    wordsToBlock(M, offset, block);
    unsafe.decryptBlock(this._decKey, block);
    blockToWords(block, M, offset);
  },

  keySize: 256 / 32,
}));

C.AES = BlockCipher._createHelper(AESAlgo);

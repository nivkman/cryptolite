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
 * One-shot fast path for the overwhelmingly common case: a whole message passed to `finalize`
 * on a fresh cipher (which is what `CryptoJS.AES.encrypt/decrypt` do) in CBC or ECB mode with
 * Pkcs7 or NoPadding. Runs noble's whole-message CBC/ECB. Returns undefined — before touching
 * any state — whenever the situation is in any way unusual, so the verbatim crypto-js
 * block-by-block path handles it.
 *
 * Fidelity notes:
 * - The IV is the one crypto-js's mode captured at reset (`_mode._iv`, raw `iv.words[0..3]`,
 *   `sigBytes` ignored), not `cfg.iv`, which callers may have replaced since.
 * - Afterwards the mode's chaining state is updated exactly as block-by-block processing would
 *   leave it, so a later `process()`/`finalize()` on the same object continues the chain.
 * - On decrypt we never let noble validate padding: we decrypt without padding and apply
 *   crypto-js's own (non-validating) unpad, so wrong keys behave exactly as in crypto-js.
 * - Any data beyond `sigBytes` in the plaintext's last word is irrelevant here: crypto-js's
 *   Pkcs7 pad clamps the buffer before encrypting it.
 */
function fastFinalize(self: Any, dataUpdate: Any): Any {
  if (!self._pristine) return undefined; // process() or finalize() already ran since reset
  if (
    self.encryptBlock !== AES_ENCRYPT_BLOCK ||
    self.decryptBlock !== AES_DECRYPT_BLOCK ||
    self._doFinalize !== BlockCipher._doFinalize ||
    self._doProcessBlock !== BlockCipher._doProcessBlock
  ) {
    return undefined; // a subclass customised the cipher
  }
  if (!(dataUpdate === undefined || dataUpdate === '' || typeof dataUpdate === 'string' || isWordArrayLike(dataUpdate))) {
    return undefined;
  }
  const cfg = self.cfg;
  const mode = cfg.mode;
  const padding = cfg.padding;
  const modeState = self._mode;
  if (mode !== CBC && mode !== ECB) return undefined;
  if (padding !== Pkcs7 && padding !== NoPadding) return undefined;

  let iv: Uint8Array | undefined;
  if (mode === CBC) {
    const ivWords = modeState._iv;
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
  const encrypting = self._xformMode == self._ENC_XFORM_MODE;
  let output: Uint8Array;
  let lastCiphertextBlock: Uint8Array | undefined;

  if (encrypting) {
    if (padding === NoPadding && data.length % 16 !== 0) return undefined;
    const disablePadding = padding === NoPadding;
    const c = mode === CBC ? cbc(key, iv!, { disablePadding }) : ecb(key, { disablePadding });
    output = c.encrypt(data);
    if (output.length) lastCiphertextBlock = output.subarray(output.length - 16);
  } else {
    if (data.length === 0 || data.length % 16 !== 0) return undefined;
    const c = mode === CBC ? cbc(key, iv!, { disablePadding: true }) : ecb(key, { disablePadding: true });
    output = c.decrypt(data);
    lastCiphertextBlock = data.subarray(data.length - 16);
  }

  // Leave the object as crypto-js would: data consumed, CBC chain advanced.
  self._pristine = false;
  self._nDataBytes += data.length;
  if (mode === CBC && lastCiphertextBlock) {
    modeState._iv = undefined;
    modeState._prevBlock = fromBytes(lastCiphertextBlock).words;
  }

  const result = fromBytes(output);
  if (!encrypting) padding.unpad(result);
  return result;
}

const AES_ENCRYPT_BLOCK = function (this: Any, M: number[], offset: number): void {
  const block = this._block;
  wordsToBlock(M, offset, block);
  unsafe.encryptBlock(this._encKey, block);
  blockToWords(block, M, offset);
};

const AES_DECRYPT_BLOCK = function (this: Any, M: number[], offset: number): void {
  if (!this._decKey) {
    this._decKey = unsafe.expandKeyDecLE(this._keyBytes);
  }
  const block = this._block;
  wordsToBlock(M, offset, block);
  unsafe.decryptBlock(this._decKey, block);
  blockToWords(block, M, offset);
};

export const AESAlgo: Any = (C.algo.AES = BlockCipher.extend({
  reset(this: Any): void {
    BlockCipher.reset.call(this);
    this._pristine = true;
  },

  process(this: Any, dataUpdate: Any): Any {
    this._pristine = false;
    return BlockCipher.process.call(this, dataUpdate);
  },

  finalize(this: Any, dataUpdate?: Any): Any {
    const fast = fastFinalize(this, dataUpdate);
    if (fast !== undefined) return fast;
    this._pristine = false;
    return BlockCipher.finalize.call(this, dataUpdate);
  },

  _doReset(this: Any): void {
    // Skip reset of nRounds has been set before and key did not change (crypto-js behaviour).
    if (this._nRounds && this._keyPriorReset === this._key) {
      return;
    }

    const key = (this._keyPriorReset = this._key);
    if (!isWordArrayLike(key)) {
      throw new TypeError(
        'cryptolite: an AES key must be a WordArray with a whole number of bytes (16, 24 or 32). ' +
          '(crypto-js accepted other values here and produced unusable ciphertext.) To encrypt with ' +
          'a passphrase, pass a string to CryptoJS.AES.encrypt() instead.',
      );
    }
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

  encryptBlock: AES_ENCRYPT_BLOCK,
  decryptBlock: AES_DECRYPT_BLOCK,

  keySize: 256 / 32,
}));

C.AES = BlockCipher._createHelper(AESAlgo);

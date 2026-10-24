/*
 * crypto-js block cipher modes CFB, CTR, CTRGladman, OFB, ECB (CBC lives in ./cipher-core),
 * ported verbatim — including CTR's crypto-js-specific counter increment (last 32-bit word
 * only, no carry).
 * Portions (c) 2009-2013 Jeff Mott, (c) 2013-2016 Evan Vosberg, MIT License (crypto-js).
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { C, type Any } from './core';
import { BlockCipherMode } from './cipher-core';

const C_mode: Any = C.mode;

export const CFB: Any = (C_mode.CFB = (function () {
  const CFB: Any = BlockCipherMode.extend();

  function generateKeystreamAndEncrypt(
    this: Any,
    words: number[],
    offset: number,
    blockSize: number,
    cipher: Any,
  ): void {
    let keystream;
    const iv = this._iv;
    if (iv) {
      keystream = iv.slice(0);
      this._iv = undefined;
    } else {
      keystream = this._prevBlock;
    }
    cipher.encryptBlock(keystream, 0);
    for (let i = 0; i < blockSize; i++) {
      words[offset + i] ^= keystream[i];
    }
  }

  CFB.Encryptor = CFB.extend({
    processBlock(this: Any, words: number[], offset: number): void {
      const cipher = this._cipher;
      const blockSize = cipher.blockSize;
      generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);
      this._prevBlock = words.slice(offset, offset + blockSize);
    },
  });

  CFB.Decryptor = CFB.extend({
    processBlock(this: Any, words: number[], offset: number): void {
      const cipher = this._cipher;
      const blockSize = cipher.blockSize;
      const thisBlock = words.slice(offset, offset + blockSize);
      generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);
      this._prevBlock = thisBlock;
    },
  });

  return CFB;
})());

export const CTR: Any = (C_mode.CTR = (function () {
  const CTR: Any = BlockCipherMode.extend();

  const Encryptor = (CTR.Encryptor = CTR.extend({
    processBlock(this: Any, words: number[], offset: number): void {
      const cipher = this._cipher;
      const blockSize = cipher.blockSize;
      const iv = this._iv;
      let counter = this._counter;

      if (iv) {
        counter = this._counter = iv.slice(0);
        this._iv = undefined;
      }
      const keystream = counter.slice(0);
      cipher.encryptBlock(keystream, 0);

      counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0;

      for (let i = 0; i < blockSize; i++) {
        words[offset + i] ^= keystream[i];
      }
    },
  }));

  CTR.Decryptor = Encryptor;
  return CTR;
})());

export const CTRGladman: Any = (C_mode.CTRGladman = (function () {
  const CTRGladman: Any = BlockCipherMode.extend();

  function incWord(word: number): number {
    if (((word >> 24) & 0xff) === 0xff) {
      // overflow
      let b1 = (word >> 16) & 0xff;
      let b2 = (word >> 8) & 0xff;
      let b3 = word & 0xff;

      if (b1 === 0xff) {
        b1 = 0;
        if (b2 === 0xff) {
          b2 = 0;
          if (b3 === 0xff) {
            b3 = 0;
          } else {
            ++b3;
          }
        } else {
          ++b2;
        }
      } else {
        ++b1;
      }

      word = 0;
      word += b1 << 16;
      word += b2 << 8;
      word += b3;
    } else {
      word += 0x01 << 24;
    }
    return word;
  }

  function incCounter(counter: number[]): number[] {
    if ((counter[0] = incWord(counter[0])) === 0) {
      // encr_data in fileenc.c from Dr Brian Gladman's counts only with DWORD j < 8
      counter[1] = incWord(counter[1]);
    }
    return counter;
  }

  const Encryptor = (CTRGladman.Encryptor = CTRGladman.extend({
    processBlock(this: Any, words: number[], offset: number): void {
      const cipher = this._cipher;
      const blockSize = cipher.blockSize;
      const iv = this._iv;
      let counter = this._counter;

      if (iv) {
        counter = this._counter = iv.slice(0);
        this._iv = undefined;
      }

      incCounter(counter);

      const keystream = counter.slice(0);
      cipher.encryptBlock(keystream, 0);

      for (let i = 0; i < blockSize; i++) {
        words[offset + i] ^= keystream[i];
      }
    },
  }));

  CTRGladman.Decryptor = Encryptor;
  return CTRGladman;
})());

export const OFB: Any = (C_mode.OFB = (function () {
  const OFB: Any = BlockCipherMode.extend();

  const Encryptor = (OFB.Encryptor = OFB.extend({
    processBlock(this: Any, words: number[], offset: number): void {
      const cipher = this._cipher;
      const blockSize = cipher.blockSize;
      const iv = this._iv;
      let keystream = this._keystream;

      if (iv) {
        keystream = this._keystream = iv.slice(0);
        this._iv = undefined;
      }
      cipher.encryptBlock(keystream, 0);

      for (let i = 0; i < blockSize; i++) {
        words[offset + i] ^= keystream[i];
      }
    },
  }));

  OFB.Decryptor = Encryptor;
  return OFB;
})());

export const ECB: Any = (C_mode.ECB = (function () {
  const ECB: Any = BlockCipherMode.extend();

  ECB.Encryptor = ECB.extend({
    processBlock(this: Any, words: number[], offset: number): void {
      this._cipher.encryptBlock(words, offset);
    },
  });

  ECB.Decryptor = ECB.extend({
    processBlock(this: Any, words: number[], offset: number): void {
      this._cipher.decryptBlock(words, offset);
    },
  });

  return ECB;
})());

/*
 * crypto-js cipher framework: Cipher, StreamCipher, BlockCipherMode (+CBC), Pkcs7,
 * BlockCipher, CipherParams, OpenSSL formatter, SerializableCipher, OpenSSL KDF and
 * PasswordBasedCipher — ported verbatim so every mode/padding/format behaves identically.
 * Only the block functions (see ./aes.ts) are delegated to @noble/ciphers.
 *
 * Portions (c) 2009-2013 Jeff Mott, (c) 2013-2016 Evan Vosberg, MIT License (crypto-js).
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Base, BufferedBlockAlgorithm, C, WordArray, type Any } from './core';
import { Base64 } from './enc';
import { EvpKDF } from './kdf';

const C_lib: Any = C.lib;

export const Cipher: Any = (C_lib.Cipher = BufferedBlockAlgorithm.extend({
  cfg: Base.extend(),

  createEncryptor(this: Any, key: Any, cfg?: Any): Any {
    return this.create(this._ENC_XFORM_MODE, key, cfg);
  },

  createDecryptor(this: Any, key: Any, cfg?: Any): Any {
    return this.create(this._DEC_XFORM_MODE, key, cfg);
  },

  init: function (this: Any, xformMode: number, key: Any, cfg?: Any): void {
    this.cfg = this.cfg.extend(cfg);
    this._xformMode = xformMode;
    this._key = key;
    this.reset();
  },

  reset(this: Any): void {
    BufferedBlockAlgorithm.reset.call(this);
    this._doReset();
  },

  process(this: Any, dataUpdate: Any): Any {
    this._append(dataUpdate);
    return this._process();
  },

  finalize(this: Any, dataUpdate?: Any): Any {
    if (dataUpdate) {
      this._append(dataUpdate);
    }
    return this._doFinalize();
  },

  keySize: 128 / 32,
  ivSize: 128 / 32,
  _ENC_XFORM_MODE: 1,
  _DEC_XFORM_MODE: 2,

  _createHelper(cipher: Any) {
    return {
      encrypt(message: Any, key: Any, cfg?: Any): Any {
        return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
      },
      decrypt(ciphertext: Any, key: Any, cfg?: Any): Any {
        return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
      },
    };
  },
}));

function selectCipherStrategy(key: Any): Any {
  if (typeof key == 'string') {
    return PasswordBasedCipher;
  } else {
    return SerializableCipher;
  }
}

export const StreamCipher: Any = (C_lib.StreamCipher = Cipher.extend({
  _doFinalize(this: Any): Any {
    return this._process(true /* flush */);
  },
  blockSize: 1,
}));

const C_mode: Any = (C.mode = {});

export const BlockCipherMode: Any = (C_lib.BlockCipherMode = Base.extend({
  createEncryptor(this: Any, cipher: Any, iv: Any): Any {
    return this.Encryptor.create(cipher, iv);
  },

  createDecryptor(this: Any, cipher: Any, iv: Any): Any {
    return this.Decryptor.create(cipher, iv);
  },

  init: function (this: Any, cipher: Any, iv: Any): void {
    this._cipher = cipher;
    this._iv = iv;
  },
}));

export const CBC: Any = (C_mode.CBC = (function () {
  const CBC: Any = BlockCipherMode.extend();

  function xorBlock(this: Any, words: number[], offset: number, blockSize: number): void {
    let block;
    const iv = this._iv;
    if (iv) {
      block = iv;
      this._iv = undefined;
    } else {
      block = this._prevBlock;
    }
    for (let i = 0; i < blockSize; i++) {
      words[offset + i] ^= block[i];
    }
  }

  CBC.Encryptor = CBC.extend({
    processBlock(this: Any, words: number[], offset: number): void {
      const cipher = this._cipher;
      const blockSize = cipher.blockSize;
      xorBlock.call(this, words, offset, blockSize);
      cipher.encryptBlock(words, offset);
      this._prevBlock = words.slice(offset, offset + blockSize);
    },
  });

  CBC.Decryptor = CBC.extend({
    processBlock(this: Any, words: number[], offset: number): void {
      const cipher = this._cipher;
      const blockSize = cipher.blockSize;
      const thisBlock = words.slice(offset, offset + blockSize);
      cipher.decryptBlock(words, offset);
      xorBlock.call(this, words, offset, blockSize);
      this._prevBlock = thisBlock;
    },
  });

  return CBC;
})());

const C_pad: Any = (C.pad = {});

export const Pkcs7: Any = (C_pad.Pkcs7 = {
  pad(data: Any, blockSize: number): void {
    const blockSizeBytes = blockSize * 4;
    const nPaddingBytes = blockSizeBytes - (data.sigBytes % blockSizeBytes);
    const paddingWord =
      (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;
    const paddingWords: number[] = [];
    for (let i = 0; i < nPaddingBytes; i += 4) {
      paddingWords.push(paddingWord);
    }
    const padding = WordArray.create(paddingWords, nPaddingBytes);
    data.concat(padding);
  },

  unpad(data: Any): void {
    // crypto-js does not validate padding; neither do we (the modern API does).
    const nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;
    data.sigBytes -= nPaddingBytes;
  },
});

export const BlockCipher: Any = (C_lib.BlockCipher = Cipher.extend({
  cfg: Cipher.cfg.extend({
    mode: CBC,
    padding: Pkcs7,
  }),

  reset(this: Any): void {
    let modeCreator;
    Cipher.reset.call(this);

    const cfg = this.cfg;
    const iv = cfg.iv;
    const mode = cfg.mode;

    if (this._xformMode == this._ENC_XFORM_MODE) {
      modeCreator = mode.createEncryptor;
    } else {
      modeCreator = mode.createDecryptor;
      // Keep at least one block in the buffer for unpadding
      this._minBufferSize = 1;
    }

    if (this._mode && this._mode.__creator == modeCreator) {
      this._mode.init(this, iv && iv.words);
    } else {
      this._mode = modeCreator.call(mode, this, iv && iv.words);
      this._mode.__creator = modeCreator;
    }
  },

  _doProcessBlock(this: Any, words: number[], offset: number): void {
    this._mode.processBlock(words, offset);
  },

  _doFinalize(this: Any): Any {
    let finalProcessedBlocks;
    const padding = this.cfg.padding;

    if (this._xformMode == this._ENC_XFORM_MODE) {
      padding.pad(this._data, this.blockSize);
      finalProcessedBlocks = this._process(true /* flush */);
    } else {
      finalProcessedBlocks = this._process(true /* flush */);
      padding.unpad(finalProcessedBlocks);
    }

    return finalProcessedBlocks;
  },

  blockSize: 128 / 32,
}));

export const CipherParams: Any = (C_lib.CipherParams = Base.extend({
  init: function (this: Any, cipherParams: Any): void {
    this.mixIn(cipherParams);
  },

  toString(this: Any, formatter?: Any): string {
    return (formatter || this.formatter).stringify(this);
  },
}));

const C_format: Any = (C.format = {});

export const OpenSSLFormatter: Any = (C_format.OpenSSL = {
  stringify(cipherParams: Any): string {
    let wordArray;
    const ciphertext = cipherParams.ciphertext;
    const salt = cipherParams.salt;

    if (salt) {
      // "Salted__" + salt + ciphertext
      wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
    } else {
      wordArray = ciphertext;
    }

    return wordArray.toString(Base64);
  },

  parse(openSSLStr: string): Any {
    let salt;
    const ciphertext = Base64.parse(openSSLStr);
    const ciphertextWords = ciphertext.words;

    if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
      salt = WordArray.create(ciphertextWords.slice(2, 4));
      ciphertextWords.splice(0, 4);
      ciphertext.sigBytes -= 16;
    }

    return CipherParams.create({ ciphertext: ciphertext, salt: salt });
  },
});

export const SerializableCipher: Any = (C_lib.SerializableCipher = Base.extend({
  cfg: Base.extend({
    format: OpenSSLFormatter,
  }),

  encrypt(this: Any, cipher: Any, message: Any, key: Any, cfg?: Any): Any {
    cfg = this.cfg.extend(cfg);

    const encryptor = cipher.createEncryptor(key, cfg);
    const ciphertext = encryptor.finalize(message);
    const cipherCfg = encryptor.cfg;

    return CipherParams.create({
      ciphertext: ciphertext,
      key: key,
      iv: cipherCfg.iv,
      algorithm: cipher,
      mode: cipherCfg.mode,
      padding: cipherCfg.padding,
      blockSize: cipher.blockSize,
      formatter: cfg.format,
    });
  },

  decrypt(this: Any, cipher: Any, ciphertext: Any, key: Any, cfg?: Any): Any {
    cfg = this.cfg.extend(cfg);
    ciphertext = this._parse(ciphertext, cfg.format);
    return cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);
  },

  _parse(this: Any, ciphertext: Any, format: Any): Any {
    if (typeof ciphertext == 'string') {
      return format.parse(ciphertext, this);
    } else {
      return ciphertext;
    }
  },
}));

const C_kdf: Any = (C.kdf = {});

export const OpenSSLKdf: Any = (C_kdf.OpenSSL = {
  execute(password: Any, keySize: number, ivSize: number, salt?: Any, hasher?: Any): Any {
    if (!salt) {
      salt = WordArray.random(64 / 8);
    }

    let key;
    if (!hasher) {
      key = EvpKDF.create({ keySize: keySize + ivSize }).compute(password, salt);
    } else {
      key = EvpKDF.create({ keySize: keySize + ivSize, hasher: hasher }).compute(password, salt);
    }

    const iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
    key.sigBytes = keySize * 4;

    return CipherParams.create({ key: key, iv: iv, salt: salt });
  },
});

export const PasswordBasedCipher: Any = (C_lib.PasswordBasedCipher = SerializableCipher.extend({
  cfg: SerializableCipher.cfg.extend({
    kdf: OpenSSLKdf,
  }),

  encrypt(this: Any, cipher: Any, message: Any, password: Any, cfg?: Any): Any {
    cfg = this.cfg.extend(cfg);

    const derivedParams = cfg.kdf.execute(
      password,
      cipher.keySize,
      cipher.ivSize,
      cfg.salt,
      cfg.hasher,
    );
    cfg.iv = derivedParams.iv;

    const ciphertext = SerializableCipher.encrypt.call(
      this,
      cipher,
      message,
      derivedParams.key,
      cfg,
    );
    ciphertext.mixIn(derivedParams);

    return ciphertext;
  },

  decrypt(this: Any, cipher: Any, ciphertext: Any, password: Any, cfg?: Any): Any {
    cfg = this.cfg.extend(cfg);
    ciphertext = this._parse(ciphertext, cfg.format);

    const derivedParams = cfg.kdf.execute(
      password,
      cipher.keySize,
      cipher.ivSize,
      ciphertext.salt,
      cfg.hasher,
    );
    cfg.iv = derivedParams.iv;

    return SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);
  },
}));


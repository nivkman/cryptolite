/*
 * crypto-js paddings AnsiX923, Iso10126, Iso97971, ZeroPadding, NoPadding (Pkcs7 lives in
 * ./cipher-core) and the Hex ciphertext format — ported verbatim.
 * Portions (c) 2009-2013 Jeff Mott, (c) 2013-2016 Evan Vosberg, MIT License (crypto-js).
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { C, Hex, WordArray, type Any } from './core';
import { CipherParams } from './cipher-core';

const C_pad: Any = C.pad;

export const AnsiX923: Any = (C_pad.AnsiX923 = {
  pad(data: Any, blockSize: number): void {
    const dataSigBytes = data.sigBytes;
    const blockSizeBytes = blockSize * 4;
    const nPaddingBytes = blockSizeBytes - (dataSigBytes % blockSizeBytes);
    const lastBytePos = dataSigBytes + nPaddingBytes - 1;

    data.clamp();
    data.words[lastBytePos >>> 2] |= nPaddingBytes << (24 - (lastBytePos % 4) * 8);
    data.sigBytes += nPaddingBytes;
  },

  unpad(data: Any): void {
    const nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;
    data.sigBytes -= nPaddingBytes;
  },
});

export const ZeroPadding: Any = (C_pad.ZeroPadding = {
  pad(data: Any, blockSize: number): void {
    const blockSizeBytes = blockSize * 4;
    data.clamp();
    data.sigBytes += blockSizeBytes - (data.sigBytes % blockSizeBytes || blockSizeBytes);
  },

  unpad(data: Any): void {
    const dataWords = data.words;
    for (let i = data.sigBytes - 1; i >= 0; i--) {
      if ((dataWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff) {
        data.sigBytes = i + 1;
        break;
      }
    }
  },
});

export const Iso10126: Any = (C_pad.Iso10126 = {
  pad(data: Any, blockSize: number): void {
    const blockSizeBytes = blockSize * 4;
    const nPaddingBytes = blockSizeBytes - (data.sigBytes % blockSizeBytes);
    data
      .concat(WordArray.random(nPaddingBytes - 1))
      .concat(WordArray.create([nPaddingBytes << 24], 1));
  },

  unpad(data: Any): void {
    const nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;
    data.sigBytes -= nPaddingBytes;
  },
});

export const Iso97971: Any = (C_pad.Iso97971 = {
  pad(data: Any, blockSize: number): void {
    data.concat(WordArray.create([0x80000000], 1));
    ZeroPadding.pad(data, blockSize);
  },

  unpad(data: Any): void {
    ZeroPadding.unpad(data);
    data.sigBytes--;
  },
});

export const NoPadding: Any = (C_pad.NoPadding = {
  pad(): void {},
  unpad(): void {},
});

export const HexFormatter: Any = (C.format.Hex = {
  stringify(cipherParams: Any): string {
    return cipherParams.ciphertext.toString(Hex);
  },

  parse(input: string): Any {
    const ciphertext = Hex.parse(input);
    return CipherParams.create({ ciphertext: ciphertext });
  },
});

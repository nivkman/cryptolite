/*
 * crypto-js x64-core (CryptoJS.x64.Word / CryptoJS.x64.WordArray), ported for API completeness.
 * Portions (c) 2009-2013 Jeff Mott, (c) 2013-2016 Evan Vosberg, MIT License (crypto-js).
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Base, C, WordArray, type Any } from './core';

const C_x64: Any = (C.x64 = {});

export const X64Word: Any = (C_x64.Word = Base.extend({
  init: function (this: Any, high: number, low: number) {
    this.high = high;
    this.low = low;
  },
}));

export const X64WordArray: Any = (C_x64.WordArray = Base.extend({
  init: function (this: Any, words?: Any[], sigBytes?: number) {
    words = this.words = words || [];
    if (sigBytes != undefined) {
      this.sigBytes = sigBytes;
    } else {
      this.sigBytes = words.length * 8;
    }
  },

  toX32(this: Any): Any {
    const x64Words = this.words;
    const x32Words: number[] = [];
    for (let i = 0; i < x64Words.length; i++) {
      const x64Word = x64Words[i];
      x32Words.push(x64Word.high);
      x32Words.push(x64Word.low);
    }
    return WordArray.create(x32Words, this.sigBytes);
  },

  clone(this: Any): Any {
    const clone = Base.clone.call(this);
    const words = (clone.words = this.words.slice(0));
    for (let i = 0; i < words.length; i++) {
      words[i] = words[i].clone();
    }
    return clone;
  },
}));

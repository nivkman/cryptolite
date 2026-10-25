/*
 * Compat core: the crypto-js object model (Base, WordArray, encoders, BufferedBlockAlgorithm,
 * Hasher), ported from crypto-js 4.2.0 so behaviour — including its quirks — is identical.
 *
 * Portions (c) 2009-2013 Jeff Mott, (c) 2013-2016 Evan Vosberg, MIT License (crypto-js).
 *
 * The object model is prototype-based (`X.extend({...})`, `X.create(...)`, `new X.init(...)`),
 * exactly like crypto-js, because user code and subclasses depend on it. Internally it is
 * loosely typed; the public surface is typed by ./types.ts.
 *
 * IMPORTANT: every `init` must be written `init: function (...) {}`, never as a method
 * shorthand `init(...) {}`. crypto-js and its users call `new X.init(...)`, and shorthand
 * methods are not constructible.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

export type Any = any;

const hasOwn = (obj: object, key: PropertyKey): boolean =>
  Object.prototype.hasOwnProperty.call(obj, key);

/** The CryptoJS namespace object every compat module attaches to. */
export const C: Any = {};
const C_lib: Any = (C.lib = {});
export const C_enc: Any = (C.enc = {});
export const C_algo: Any = (C.algo = {});

// ---------------------------------------------------------------------------------------------
// Secure randomness. crypto-js 4.x throws when no secure source exists; so do we.
// ---------------------------------------------------------------------------------------------

function getCrypto(): Any {
  const g: Any = typeof globalThis !== 'undefined' ? globalThis : undefined;
  return g && g.crypto;
}

/**
 * `count` secure random 32-bit words. Like crypto-js's `getRandomValues` path the words are
 * unsigned, and a missing or failing source raises crypto-js's own error. Filled in chunks
 * because Web Crypto limits one call to 65536 bytes.
 */
export function secureRandomWords(count: number): number[] {
  const crypto = getCrypto();
  if (crypto && typeof crypto.getRandomValues === 'function') {
    try {
      const out = new Uint32Array(count);
      for (let i = 0; i < count; i += 16384) {
        crypto.getRandomValues(out.subarray(i, Math.min(count, i + 16384)));
      }
      return Array.from(out);
    } catch {
      // fall through to the error below, as crypto-js does
    }
  }
  throw new Error(
    'Native crypto module could not be used to get secure random number. ' +
      '(cryptolite: globalThis.crypto.getRandomValues is missing or failed; on React Native ' +
      "install and import 'react-native-get-random-values' first.)",
  );
}

// ---------------------------------------------------------------------------------------------
// Base object model
// ---------------------------------------------------------------------------------------------

export const Base: Any = (C_lib.Base = {
  extend(this: Any, overrides?: Any): Any {
    const subtype = Object.create(this);
    if (overrides) {
      subtype.mixIn(overrides);
    }
    if (!hasOwn(subtype, 'init') || this.init === subtype.init) {
      subtype.init = function (this: Any) {
        // eslint-disable-next-line prefer-rest-params
        subtype.$super.init.apply(this, arguments);
      };
    }
    subtype.init.prototype = subtype;
    subtype.$super = this;
    return subtype;
  },

  create(this: Any): Any {
    const instance = this.extend();
    // eslint-disable-next-line prefer-rest-params
    instance.init.apply(instance, arguments);
    return instance;
  },

  init: function (): void {},

  mixIn(this: Any, properties: Any): void {
    for (const propertyName in properties) {
      if (hasOwn(properties, propertyName)) {
        this[propertyName] = properties[propertyName];
      }
    }
    // IE won't copy toString using the loop above (kept for fidelity).
    if (hasOwn(properties, 'toString')) {
      this.toString = properties.toString;
    }
  },

  clone(this: Any): Any {
    return this.init.prototype.extend(this);
  },
});

// ---------------------------------------------------------------------------------------------
// WordArray (big-endian 32-bit words + significant byte count)
// ---------------------------------------------------------------------------------------------

export const WordArray: Any = (C_lib.WordArray = Base.extend({
  init: function (this: Any, words?: number[], sigBytes?: number) {
    words = this.words = words || [];
    if (sigBytes != undefined) {
      this.sigBytes = sigBytes;
    } else {
      this.sigBytes = words.length * 4;
    }
  },

  toString(this: Any, encoder?: Any): string {
    return (encoder || Hex).stringify(this);
  },

  concat(this: Any, wordArray: Any): Any {
    const thisWords = this.words;
    const thatWords = wordArray.words;
    const thisSigBytes = this.sigBytes;
    const thatSigBytes = wordArray.sigBytes;

    this.clamp();

    if (thisSigBytes % 4) {
      for (let i = 0; i < thatSigBytes; i++) {
        const thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
      }
    } else {
      for (let j = 0; j < thatSigBytes; j += 4) {
        thisWords[(thisSigBytes + j) >>> 2] = thatWords[j >>> 2];
      }
    }
    this.sigBytes += thatSigBytes;

    return this;
  },

  clamp(this: Any): void {
    const words = this.words;
    const sigBytes = this.sigBytes;
    words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
    words.length = Math.ceil(sigBytes / 4);
  },

  clone(this: Any): Any {
    const clone = Base.clone.call(this);
    clone.words = this.words.slice(0);
    return clone;
  },

  random(nBytes: number): Any {
    // Same word count as crypto-js's `for (i = 0; i < nBytes; i += 4)`.
    const words = secureRandomWords(nBytes > 0 ? Math.ceil(nBytes / 4) : 0);
    return new WordArray.init(words, nBytes);
  },
}));

// lib-typedarrays: WordArray.create(ArrayBuffer | TypedArray)
{
  const superInit = WordArray.init;
  const subInit = (WordArray.init = function (this: Any, typedArray?: Any) {
    if (typedArray instanceof ArrayBuffer) {
      typedArray = new Uint8Array(typedArray);
    }
    if (
      typedArray instanceof Int8Array ||
      (typeof Uint8ClampedArray !== 'undefined' && typedArray instanceof Uint8ClampedArray) ||
      typedArray instanceof Int16Array ||
      typedArray instanceof Uint16Array ||
      typedArray instanceof Int32Array ||
      typedArray instanceof Uint32Array ||
      typedArray instanceof Float32Array ||
      typedArray instanceof Float64Array
    ) {
      typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
    }
    if (typedArray instanceof Uint8Array) {
      const typedArrayByteLength = typedArray.byteLength;
      const words: number[] = [];
      for (let i = 0; i < typedArrayByteLength; i++) {
        words[i >>> 2] |= typedArray[i] << (24 - (i % 4) * 8);
      }
      superInit.call(this, words, typedArrayByteLength);
    } else {
      // eslint-disable-next-line prefer-rest-params
      superInit.apply(this, arguments);
    }
  });
  subInit.prototype = WordArray;
}

// ---------------------------------------------------------------------------------------------
// Encoders: Hex, Latin1, Utf8
// ---------------------------------------------------------------------------------------------

const HEX_TABLE: string[] = [];
for (let i = 0; i < 256; i++) {
  HEX_TABLE.push((i >>> 4).toString(16) + (i & 0x0f).toString(16));
}

export const Hex: Any = (C_enc.Hex = {
  stringify(wordArray: Any): string {
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    let out = '';
    for (let i = 0; i < sigBytes; i++) {
      out += HEX_TABLE[(words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff];
    }
    return out;
  },

  parse(hexStr: string): Any {
    const hexStrLength = hexStr.length;
    const words: number[] = [];
    for (let i = 0; i < hexStrLength; i += 2) {
      words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
    }
    return new WordArray.init(words, hexStrLength / 2);
  },
});

export const Latin1: Any = (C_enc.Latin1 = {
  stringify(wordArray: Any): string {
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    const latin1Chars: string[] = [];
    for (let i = 0; i < sigBytes; i++) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      latin1Chars.push(String.fromCharCode(bite));
    }
    return latin1Chars.join('');
  },

  parse(latin1Str: string): Any {
    const latin1StrLength = latin1Str.length;
    const words: number[] = [];
    for (let i = 0; i < latin1StrLength; i++) {
      words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
    }
    return new WordArray.init(words, latin1StrLength);
  },
});

// UTF-8. crypto-js uses `unescape(encodeURIComponent(s))` / `decodeURIComponent(escape(b))`.
// We use TextEncoder/TextDecoder when present (much faster) with the exact same acceptance
// rules — encoding throws URIError on lone surrogates, decoding rejects any byte sequence that
// isn't well-formed UTF-8 and keeps a leading BOM — and fall back to crypto-js's own
// expressions where those APIs are missing (e.g. older React Native).
// Platform APIs are looked up on globalThis (not typed globals) because the library is typed
// against plain ES2020: React Native/Hermes may not have them, or may have partial versions.
const g: Any = typeof globalThis !== 'undefined' ? globalThis : {};

const textEncoder: Any = (() => {
  try {
    const te = typeof g.TextEncoder === 'function' ? new g.TextEncoder() : undefined;
    // Sanity check: must produce standard UTF-8.
    const probe = te && te.encode('\u00e9\ud83d\ude00');
    return probe && probe.length === 6 && probe[0] === 0xc3 && probe[2] === 0xf0 ? te : undefined;
  } catch {
    return undefined;
  }
})();

const textDecoder: Any = (() => {
  try {
    if (typeof g.TextDecoder !== 'function') return undefined;
    const td = new g.TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    // Only trust it if it really keeps a BOM and really rejects invalid input; otherwise use
    // crypto-js's own expression, whose behaviour we must match exactly.
    if (td.decode(new Uint8Array([0xef, 0xbb, 0xbf, 0x41])) !== '\ufeffA') return undefined;
    try {
      td.decode(new Uint8Array([0xed, 0xa0, 0x80])); // encoded surrogate: must throw
      return undefined;
    } catch {
      return td;
    }
  } catch {
    return undefined;
  }
})();

const LONE_OR_ANY_SURROGATE = /[\uD800-\uDFFF]/;
function isWellFormed(s: string): boolean {
  const native = (s as Any).isWellFormed;
  // Without String#isWellFormed, conservatively send anything containing a surrogate down the
  // slow path, which validates exactly like crypto-js.
  return typeof native === 'function' ? native.call(s) : !LONE_OR_ANY_SURROGATE.test(s);
}

/** UTF-8 bytes of `s`, with crypto-js's error behaviour (URIError on lone surrogates). */
export function utf8Encode(s: string): Uint8Array {
  if (textEncoder && typeof s === 'string' && isWellFormed(s)) {
    return textEncoder.encode(s);
  }
  const bin = unescape(encodeURIComponent(s));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export const Utf8: Any = (C_enc.Utf8 = {
  stringify(wordArray: Any): string {
    if (textDecoder) {
      try {
        return textDecoder.decode(wordArrayBytes(wordArray));
      } catch {
        throw new Error('Malformed UTF-8 data');
      }
    }
    try {
      return decodeURIComponent(escape(Latin1.stringify(wordArray)));
    } catch {
      throw new Error('Malformed UTF-8 data');
    }
  },

  parse(utf8Str: string): Any {
    return fromBytes(utf8Encode(utf8Str));
  },
});

// ---------------------------------------------------------------------------------------------
// Bridges between WordArray and Uint8Array (used to hand data to @noble primitives)
// ---------------------------------------------------------------------------------------------

/** True for objects shaped like a usable WordArray (what the fast paths accept). */
export function isWordArrayLike(x: Any): boolean {
  return (
    x != null &&
    typeof x === 'object' &&
    Array.isArray(x.words) &&
    typeof x.sigBytes === 'number' &&
    x.sigBytes >= 0 &&
    Number.isInteger(x.sigBytes)
  );
}

/**
 * True for input whose bytes are unambiguous, i.e. where hashing exactly `toBytes(x)` matches
 * crypto-js: a string, or a WordArray with a whole number of bytes and no bits set beyond them
 * in its last word (crypto-js's padding would pick those up). Everything else goes through the
 * verbatim crypto-js code paths.
 */
export function isCleanMessage(x: Any): boolean {
  if (typeof x === 'string') return true;
  if (!isWordArrayLike(x)) return false;
  const tail = x.sigBytes % 4;
  return tail === 0 || (x.words[x.sigBytes >>> 2] << (tail * 8)) === 0;
}

/**
 * WordArray | string (UTF-8) → bytes. Reads `sigBytes` bytes, rounding a fractional count up
 * the way crypto-js's byte loops (`for (i = 0; i < sigBytes; i++)`) do.
 */
export function toBytes(data: Any): Uint8Array {
  if (typeof data === 'string') {
    return utf8Encode(data);
  }
  return wordArrayBytes(data);
}

/**
 * The bytes crypto-js's byte loops read from a WordArray-shaped value — never treating a string
 * as text (a string has no `words`/`sigBytes`, so crypto-js reads nothing from it).
 */
export function wordArrayBytes(data: Any): Uint8Array {
  const words = data.words;
  const sigBytes = data.sigBytes > 0 ? Math.ceil(data.sigBytes) : 0;
  const out = new Uint8Array(sigBytes);
  const fullWords = sigBytes >>> 2;
  let j = 0;
  for (let i = 0; i < fullWords; i++) {
    const w = words[i];
    out[j++] = w >>> 24;
    out[j++] = w >>> 16;
    out[j++] = w >>> 8;
    out[j++] = w;
  }
  for (let i = fullWords * 4; i < sigBytes; i++) {
    out[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return out;
}

/** bytes → WordArray. */
export function fromBytes(bytes: Uint8Array): Any {
  const n = bytes.length;
  const nWords = (n + 3) >>> 2;
  const words: number[] = new Array(nWords);
  const fullWords = n >>> 2;
  let j = 0;
  for (let i = 0; i < fullWords; i++, j += 4) {
    words[i] = (bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3];
  }
  if (fullWords < nWords) {
    let w = 0;
    for (let k = 0; j + k < n; k++) {
      w |= bytes[j + k] << (24 - k * 8);
    }
    words[fullWords] = w;
  }
  return new WordArray.init(words, n);
}

// ---------------------------------------------------------------------------------------------
// BufferedBlockAlgorithm and Hasher
// ---------------------------------------------------------------------------------------------

export const BufferedBlockAlgorithm: Any = (C_lib.BufferedBlockAlgorithm = Base.extend({
  reset(this: Any): void {
    this._data = new WordArray.init();
    this._nDataBytes = 0;
  },

  _append(this: Any, data: Any): void {
    if (typeof data == 'string') {
      data = Utf8.parse(data);
    }
    this._data.concat(data);
    this._nDataBytes += data.sigBytes;
  },

  _process(this: Any, doFlush?: boolean): Any {
    let processedWords;
    const data = this._data;
    const dataWords = data.words;
    const dataSigBytes = data.sigBytes;
    const blockSize = this.blockSize;
    const blockSizeBytes = blockSize * 4;

    let nBlocksReady = dataSigBytes / blockSizeBytes;
    if (doFlush) {
      nBlocksReady = Math.ceil(nBlocksReady);
    } else {
      nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
    }

    const nWordsReady = nBlocksReady * blockSize;
    const nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

    if (nWordsReady) {
      for (let offset = 0; offset < nWordsReady; offset += blockSize) {
        this._doProcessBlock(dataWords, offset);
      }
      processedWords = dataWords.splice(0, nWordsReady);
      data.sigBytes -= nBytesReady;
    }

    return new WordArray.init(processedWords, nBytesReady);
  },

  clone(this: Any): Any {
    const clone = Base.clone.call(this);
    clone._data = this._data.clone();
    return clone;
  },

  _minBufferSize: 0,
}));

export const Hasher: Any = (C_lib.Hasher = BufferedBlockAlgorithm.extend({
  cfg: Base.extend(),

  init: function (this: Any, cfg?: Any): void {
    this.cfg = this.cfg.extend(cfg);
    this.reset();
  },

  reset(this: Any): void {
    BufferedBlockAlgorithm.reset.call(this);
    this._doReset();
  },

  update(this: Any, messageUpdate: Any): Any {
    this._append(messageUpdate);
    this._process();
    return this;
  },

  finalize(this: Any, messageUpdate?: Any): Any {
    if (messageUpdate) {
      this._append(messageUpdate);
    }
    return this._doFinalize();
  },

  blockSize: 512 / 32,

  _createHelper(hasher: Any) {
    return function (message: Any, cfg?: Any): Any {
      return new hasher.init(cfg).finalize(message);
    };
  },

  _createHmacHelper(hasher: Any) {
    return function (message: Any, key: Any): Any {
      return new C_algo.HMAC.init(hasher, key).finalize(message);
    };
  },
}));

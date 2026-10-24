import { describe, expect, it } from 'vitest';
import CryptoJS from '../../src/compat/index';
import {
  RefCryptoJS,
  bytesToHex,
  prngBytes,
  randInt,
  wordArrayToBytes,
} from './_util';

const libs = { cryptolite: CryptoJS, 'crypto-js': RefCryptoJS } as const;

describe('WordArray.create — words/sigBytes', () => {
  it('defaults sigBytes to words.length * 4', () => {
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create([0x01020304, 0x05060708]);
      expect(wa.sigBytes).toBe(8);
      expect(wa.toString()).toBe('0102030405060708');
    }
  });

  it('honors an explicit sigBytes shorter than words.length * 4', () => {
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create([0xaabbccdd], 2);
      expect(wa.toString()).toBe('aabb');
    }
  });

  it('no-arg create() is an empty WordArray', () => {
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create();
      expect(wa.sigBytes).toBe(0);
      expect(wa.toString()).toBe('');
    }
  });
});

describe('WordArray.create — typed arrays / ArrayBuffer / Buffer / subarray offsets', () => {
  const byteSamples: Array<[string, (bytes: Uint8Array) => unknown]> = [
    ['Uint8Array', (b) => b],
    ['Int8Array', (b) => new Int8Array(b.buffer, b.byteOffset, b.byteLength)],
    ['Uint8ClampedArray', (b) => new Uint8ClampedArray(b)],
    ['Buffer', (b) => Buffer.from(b)],
    ['ArrayBuffer', (b) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)],
  ];

  it.each(byteSamples)('%s produces the same WordArray as a plain byte read', (_name, make) => {
    const raw = prngBytes(13);
    const view = make(raw);
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create(view);
      expect(bytesToHex(wordArrayToBytes(wa))).toBe(bytesToHex(raw));
      expect(wa.sigBytes).toBe(raw.length);
    }
  });

  it('Uint16Array/Uint32Array/Int16Array/Int32Array/Float32Array/Float64Array read the underlying bytes', () => {
    const raw = prngBytes(32); // big enough for 4 and 8-byte elements
    const views: Array<() => unknown> = [
      () => new Uint16Array(raw.buffer, raw.byteOffset, raw.byteLength / 2),
      () => new Int16Array(raw.buffer, raw.byteOffset, raw.byteLength / 2),
      () => new Uint32Array(raw.buffer, raw.byteOffset, raw.byteLength / 4),
      () => new Int32Array(raw.buffer, raw.byteOffset, raw.byteLength / 4),
      () => new Float32Array(raw.buffer, raw.byteOffset, raw.byteLength / 4),
      () => new Float64Array(raw.buffer, raw.byteOffset, raw.byteLength / 8),
    ];
    for (const makeView of views) {
      for (const [, CJS] of Object.entries(libs)) {
        const wa = CJS.lib.WordArray.create(makeView());
        expect(bytesToHex(wordArrayToBytes(wa))).toBe(bytesToHex(raw));
      }
    }
  });

  it('subarray offsets are respected (not the whole backing buffer)', () => {
    const raw = prngBytes(40);
    const sub = raw.subarray(7, 23); // offset view, not 0-based, not full length
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create(sub);
      expect(bytesToHex(wordArrayToBytes(wa))).toBe(bytesToHex(raw.slice(7, 23)));
      expect(wa.sigBytes).toBe(16);
    }
  });

  it('Buffer subarray (offset, non-zero-copy view) is respected', () => {
    const raw = prngBytes(24);
    const buf = Buffer.from(raw).subarray(5, 19);
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create(buf);
      expect(bytesToHex(wordArrayToBytes(wa))).toBe(bytesToHex(raw.slice(5, 19)));
    }
  });
});

describe('WordArray.random', () => {
  it('produces the requested byte length (content necessarily differs between libraries)', () => {
    for (let i = 0; i < 10; i++) {
      const n = randInt(0, 64);
      for (const [, CJS] of Object.entries(libs)) {
        const wa = CJS.lib.WordArray.random(n);
        expect(wa.sigBytes).toBe(n);
        expect(wordArrayToBytes(wa).length).toBe(n);
      }
    }
  });
});

describe('WordArray#concat', () => {
  it('aligned concat (both sigBytes multiples of 4)', () => {
    const a = prngBytes(8);
    const b = prngBytes(12);
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create(a).concat(CJS.lib.WordArray.create(b));
      expect(bytesToHex(wordArrayToBytes(wa))).toBe(bytesToHex(a) + bytesToHex(b));
    }
  });

  it('unaligned concat (sigBytes not a multiple of 4, every misalignment 1..3)', () => {
    for (const misalignment of [1, 2, 3]) {
      const a = prngBytes(4 + misalignment);
      const b = prngBytes(9);
      for (const [, CJS] of Object.entries(libs)) {
        const wa = CJS.lib.WordArray.create(a).concat(CJS.lib.WordArray.create(b));
        expect(bytesToHex(wordArrayToBytes(wa))).toBe(bytesToHex(a) + bytesToHex(b));
      }
    }
  });

  it('concatenating an empty WordArray is a no-op', () => {
    const a = prngBytes(10);
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create(a).concat(CJS.lib.WordArray.create());
      expect(bytesToHex(wordArrayToBytes(wa))).toBe(bytesToHex(a));
    }
  });
});

describe('WordArray#clamp', () => {
  it('truncates trailing words past sigBytes and masks the partial final word', () => {
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create([0xaabbccdd, 0x11223344], 6);
      wa.clamp();
      expect(wa.words.length).toBe(2);
      expect(wa.words[1] >>> 0).toBe(0x11220000);
      expect(wa.toString()).toBe('aabbccdd1122');
    }
  });
});

describe('WordArray#clone — independence', () => {
  it('mutating the clone does not affect the original, and vice versa', () => {
    for (const [, CJS] of Object.entries(libs)) {
      const original = CJS.lib.WordArray.create([0x01020304, 0x05060708]);
      const clone = original.clone();
      clone.words[0] = 0;
      clone.sigBytes = 4;
      expect(original.toString()).toBe('0102030405060708');
      expect(clone.toString()).toBe('00000000');

      original.words[1] = 0xffffffff;
      expect(clone.words[1]).toBe(0x05060708);
    }
  });
});

describe('WordArray#toString', () => {
  it('defaults to Hex when no encoder is given', () => {
    for (const [, CJS] of Object.entries(libs)) {
      const wa = CJS.lib.WordArray.create([0x0a0b0c0d]);
      expect(wa.toString()).toBe(wa.toString(CJS.enc.Hex));
    }
  });

  it('accepts each encoder explicitly and matches crypto-js byte for byte', () => {
    const bytes = prngBytes(10);
    const encoders = ['Hex', 'Latin1', 'Base64', 'Base64url'] as const;
    for (const encName of encoders) {
      const outputs = Object.entries(libs).map(([, CJS]) =>
        CJS.lib.WordArray.create(bytes).toString(CJS.enc[encName]),
      );
      expect(outputs[0]).toBe(outputs[1]);
    }
  });
});

describe('new WordArray.init(...)', () => {
  it('is constructible directly (not just via .create)', () => {
    for (const [, CJS] of Object.entries(libs)) {
      const wa = new CJS.lib.WordArray.init([0x11223344], 3);
      expect(wa.toString()).toBe('112233');
    }
  });
});

describe('WordArray.create subclassing via extend', () => {
  it('a subclass created with extend() inherits WordArray behaviour and identifies itself', () => {
    for (const [, CJS] of Object.entries(libs)) {
      const Sub = CJS.lib.WordArray.extend({
        sayHi(this: { sigBytes: number }): string {
          return `hi:${this.sigBytes}`;
        },
      });
      const inst = Sub.create([0x01020304], 4);
      expect(inst.toString()).toBe('01020304');
      expect(inst.sayHi()).toBe('hi:4');
      expect(inst.clone().toString()).toBe('01020304');
    }
  });
});

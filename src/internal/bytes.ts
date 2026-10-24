/**
 * Byte-array helpers shared by the modern and compat layers. Internal: not part of the public API.
 * @module
 */

// `%TypedArray%.prototype[Symbol.toStringTag]` reads the internal [[TypedArrayName]] slot, so it
// recognises Uint8Arrays (and Node Buffers) from other realms — e.g. Jest's per-test VM context,
// where `Buffer.from(x) instanceof Uint8Array` is false — and cannot be spoofed by a plain object.
const typedArrayName: ((this: unknown) => string | undefined) | undefined = (() => {
  const proto: unknown = Object.getPrototypeOf(Uint8Array.prototype);
  const desc = proto ? Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag) : undefined;
  return typeof desc?.get === 'function' ? (desc.get as (this: unknown) => string | undefined) : undefined;
})();

/**
 * True for any `Uint8Array`, including Node `Buffer`s and Uint8Arrays from another realm
 * (iframe, `vm` context, Jest environment). False for other typed arrays, DataViews and ArrayBuffers.
 */
export function isBytes(value: unknown): value is Uint8Array {
  if (value instanceof Uint8Array) return true;
  return (
    typedArrayName !== undefined &&
    ArrayBuffer.isView(value) &&
    typedArrayName.call(value) === 'Uint8Array'
  );
}

/**
 * Returns a plain `Uint8Array` from this realm over the same memory (no copy). Normalising
 * subclasses such as `Buffer` (whose `slice()` does not copy) and cross-realm arrays before they
 * reach noble keeps every downstream assumption about plain Uint8Arrays true.
 */
export function plainBytes(value: Uint8Array): Uint8Array {
  return value.constructor === Uint8Array
    ? value
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
}

/** Concatenates byte arrays into a new array. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// Small enough for every engine's argument-count limit (Hermes and JavaScriptCore included).
const CHUNK = 0x2000;

/**
 * Builds a string from UTF-16 code units (or Latin-1/ASCII codes) in `codes[0..length)`.
 * Works in fixed-size chunks so large inputs never overflow the engine's argument limit.
 */
export function charCodesToString(codes: Uint8Array | Uint16Array, length: number = codes.length): string {
  if (length <= CHUNK) {
    return String.fromCharCode.apply(null, codes.subarray(0, length) as unknown as number[]);
  }
  const chunks: string[] = [];
  for (let i = 0; i < length; i += CHUNK) {
    const end = Math.min(length, i + CHUNK);
    chunks.push(String.fromCharCode.apply(null, codes.subarray(i, end) as unknown as number[]));
  }
  return chunks.join('');
}

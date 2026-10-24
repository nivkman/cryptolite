/**
 * PBKDF2-HMAC-SHA256 + AES-256-GCM back ends for the cl1 format. Internal: not part of the public
 * API (tests import it directly to compare the two implementations byte for byte).
 *
 * Both engines implement the same primitives with the same parameters, so they are
 * interchangeable: a token sealed by one opens with the other.
 * @module
 */
import { gcm } from '@noble/ciphers/aes.js';
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';

/** @internal */
export interface Cl1Engine {
  readonly name: 'webcrypto' | 'noble';
  /** PBKDF2-HMAC-SHA256 → 32-byte key. */
  deriveKey(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array>;
  /** AES-256-GCM encrypt; returns ciphertext with the 16-byte tag appended. */
  seal(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  /** AES-256-GCM decrypt of ciphertext‖tag; rejects (with any error) if authentication fails. */
  open(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, sealed: Uint8Array): Promise<Uint8Array>;
}

/** Pure-JS engine on @noble/hashes + @noble/ciphers. Works everywhere, including Hermes. */
export const nobleEngine: Cl1Engine = {
  name: 'noble',
  // pbkdf2Async yields to the event loop periodically, so long derivations don't freeze a UI thread.
  deriveKey: (password, salt, iterations) => pbkdf2Async(sha256, password, salt, { c: iterations, dkLen: 32 }),
  seal: async (key, iv, aad, plaintext) => gcm(key, iv, aad).encrypt(plaintext),
  open: async (key, iv, aad, sealed) => gcm(key, iv, aad).decrypt(sealed),
};

/**
 * The subset of `SubtleCrypto` used here, typed locally so neither the DOM lib nor @types/node
 * is needed to compile (or consume) this package.
 * @internal
 */
export interface SubtleLike {
  importKey(
    format: 'raw',
    keyData: Uint8Array,
    algorithm: { name: string },
    extractable: boolean,
    keyUsages: string[],
  ): Promise<unknown>;
  deriveBits(
    algorithm: { name: 'PBKDF2'; hash: 'SHA-256'; salt: Uint8Array; iterations: number },
    baseKey: unknown,
    length: number,
  ): Promise<ArrayBuffer>;
  encrypt(
    algorithm: { name: 'AES-GCM'; iv: Uint8Array; additionalData: Uint8Array; tagLength: 128 },
    key: unknown,
    data: Uint8Array,
  ): Promise<ArrayBuffer>;
  decrypt(
    algorithm: { name: 'AES-GCM'; iv: Uint8Array; additionalData: Uint8Array; tagLength: 128 },
    key: unknown,
    data: Uint8Array,
  ): Promise<ArrayBuffer>;
}

/** `globalThis.crypto.subtle` if it offers everything cl1 needs, read at call time. @internal */
export function getSubtle(): SubtleLike | undefined {
  const subtle = (globalThis as { crypto?: { subtle?: Partial<SubtleLike> } }).crypto?.subtle;
  return subtle &&
    typeof subtle.importKey === 'function' &&
    typeof subtle.deriveBits === 'function' &&
    typeof subtle.encrypt === 'function' &&
    typeof subtle.decrypt === 'function'
    ? (subtle as SubtleLike)
    : undefined;
}

/** Engine on a Web Crypto `SubtleCrypto` (native code: much faster PBKDF2). @internal */
export function webCryptoEngine(subtle: SubtleLike): Cl1Engine {
  const importAesKey = (key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<unknown> =>
    subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [usage]);
  return {
    name: 'webcrypto',
    async deriveKey(password, salt, iterations) {
      const baseKey = await subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']);
      const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, baseKey, 256);
      return new Uint8Array(bits);
    },
    async seal(key, iv, aad, plaintext) {
      const cryptoKey = await importAesKey(key, 'encrypt');
      const algorithm = { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 } as const;
      return new Uint8Array(await subtle.encrypt(algorithm, cryptoKey, plaintext));
    },
    async open(key, iv, aad, sealed) {
      const cryptoKey = await importAesKey(key, 'decrypt');
      const algorithm = { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 } as const;
      return new Uint8Array(await subtle.decrypt(algorithm, cryptoKey, sealed));
    },
  };
}

/**
 * The engine the public API uses, chosen per call (so polyfills installed after import count):
 * Web Crypto when `crypto.subtle` exists, otherwise noble.
 *
 * Web Crypto is treated as an accelerator, not a dependency: if a Web Crypto step throws for any
 * reason (some runtimes cap PBKDF2 iteration counts or ship partial `subtle` polyfills), that
 * step is retried with noble and noble's outcome is final. Both compute the same function, so
 * the retry can only turn a spurious platform failure into the correct result; a wrong password
 * or a tampered token still fails in noble.
 * @internal
 */
export function platformEngine(): Cl1Engine {
  const subtle = getSubtle();
  if (!subtle) return nobleEngine;
  const web = webCryptoEngine(subtle);
  return {
    name: 'webcrypto',
    deriveKey: (password, salt, iterations) =>
      web.deriveKey(password, salt, iterations).catch(() => nobleEngine.deriveKey(password, salt, iterations)),
    seal: (key, iv, aad, plaintext) =>
      web.seal(key, iv, aad, plaintext).catch(() => nobleEngine.seal(key, iv, aad, plaintext)),
    open: (key, iv, aad, sealed) =>
      web.open(key, iv, aad, sealed).catch(() => nobleEngine.open(key, iv, aad, sealed)),
  };
}

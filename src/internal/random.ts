/**
 * Cryptographically secure random bytes from the platform. Internal module; `randomBytes` is
 * re-exported publicly by the modern API.
 * @module
 */
import { CryptoliteError } from './errors';

/** Largest accepted `length`; the same ceiling as Node's `crypto.randomBytes`. */
export const MAX_RANDOM_BYTES = 2 ** 31 - 1;

// Web Crypto limits a single getRandomValues() call to 65536 bytes (QuotaExceededError).
const GET_RANDOM_VALUES_QUOTA = 65536;

interface RandomSource {
  getRandomValues(array: Uint8Array): unknown;
}

/**
 * Returns `length` cryptographically secure random bytes from
 * `globalThis.crypto.getRandomValues` (Web Crypto). Never falls back to `Math.random`.
 *
 * Available natively on Node >= 19, Deno, Bun, Cloudflare Workers and all modern browsers.
 * **React Native** has no built-in implementation: install
 * [`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values)
 * and `import 'react-native-get-random-values'` once, before anything uses cryptolite.
 *
 * @param length - number of bytes, an integer from 0 to 2147483647
 * @returns a new `Uint8Array` of `length` random bytes
 * @throws {CryptoliteError} `ERR_PARAMS` if `length` is not an integer in range.
 * @throws {CryptoliteError} `ERR_RANDOM` if `globalThis.crypto.getRandomValues` is unavailable.
 *
 * @example
 * ```ts
 * import { randomBytes } from 'cryptolite';
 * const key = randomBytes(32);
 * ```
 */
export function randomBytes(length: number): Uint8Array {
  if (typeof length !== 'number' || !Number.isInteger(length) || length < 0 || length > MAX_RANDOM_BYTES) {
    throw new CryptoliteError(
      'ERR_PARAMS',
      `randomBytes(): length must be an integer from 0 to ${MAX_RANDOM_BYTES}.`,
    );
  }
  const source = (globalThis as { crypto?: Partial<RandomSource> }).crypto;
  if (!source || typeof source.getRandomValues !== 'function') {
    throw new CryptoliteError(
      'ERR_RANDOM',
      'No secure random number generator: globalThis.crypto.getRandomValues is not available. ' +
        "On React Native, install react-native-get-random-values and add `import 'react-native-get-random-values'` " +
        'at the top of your entry file, before cryptolite is used.',
    );
  }
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += GET_RANDOM_VALUES_QUOTA) {
    // Called as a method: Web Crypto throws "Illegal invocation" on a detached getRandomValues.
    (source as RandomSource).getRandomValues(out.subarray(i, Math.min(length, i + GET_RANDOM_VALUES_QUOTA)));
  }
  return out;
}

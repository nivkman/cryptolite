/**
 * Machine-readable error codes carried by {@link CryptoliteError.code}.
 *
 * - `ERR_DECRYPT` — wrong password, or the data was corrupted or tampered with. Every decryption
 *   failure uses the same message on purpose: it never reveals which check failed.
 * - `ERR_FORMAT` — the input is not in the expected format (not a `cl1` token, not a crypto-js
 *   ciphertext when legacy input is allowed, or malformed base64/base64url/hex).
 * - `ERR_LEGACY_NOT_ALLOWED` — the input is a crypto-js ciphertext but legacy decryption was not
 *   enabled. Pass `{ legacy: true }` or call `upgrade()`.
 * - `ERR_PARAMS` — an argument has the wrong type or is out of range (for example an empty
 *   password or an iteration count outside the allowed bounds).
 * - `ERR_RANDOM` — no secure random number generator (`globalThis.crypto.getRandomValues`).
 * - `ERR_UTF8` — text could not be converted: a string contains a lone UTF-16 surrogate and cannot
 *   be encoded as UTF-8, or bytes that should be UTF-8 text are not valid UTF-8.
 */
export type CryptoliteErrorCode =
  | 'ERR_DECRYPT'
  | 'ERR_FORMAT'
  | 'ERR_LEGACY_NOT_ALLOWED'
  | 'ERR_PARAMS'
  | 'ERR_RANDOM'
  | 'ERR_UTF8';

/**
 * The only error type cryptolite's modern API throws (or rejects with) for invalid input and
 * failed operations. Branch on {@link CryptoliteError.code}, not on the message: messages are
 * written for humans and may be reworded in any release.
 *
 * @example
 * ```ts
 * import { decrypt, CryptoliteError } from 'cryptolite';
 *
 * try {
 *   const text = await decrypt(token, password);
 * } catch (err) {
 *   if (err instanceof CryptoliteError && err.code === 'ERR_DECRYPT') {
 *     // wrong password or tampered token
 *   } else {
 *     throw err;
 *   }
 * }
 * ```
 */
export class CryptoliteError extends Error {
  /** Always `'CryptoliteError'`. */
  declare readonly name: 'CryptoliteError';

  /** Stable, machine-readable reason. See {@link CryptoliteErrorCode}. */
  readonly code: CryptoliteErrorCode;

  /**
   * @param code - machine-readable reason
   * @param message - human-readable explanation; must not contain secrets or plaintext
   */
  constructor(code: CryptoliteErrorCode, message: string) {
    super(message);
    // Keeps `instanceof` working when a downstream toolchain transpiles classes to ES5.
    Object.setPrototypeOf(this, new.target.prototype);
    this.code = code;
  }
}

// On the prototype (not an instance field) so the name is already set when the engine
// captures the stack header inside the Error constructor.
Object.defineProperty(CryptoliteError.prototype, 'name', {
  value: 'CryptoliteError',
  writable: true,
  enumerable: false,
  configurable: true,
});

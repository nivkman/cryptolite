/**
 * Password-based authenticated encryption: `encrypt`, `decrypt`, `decryptBytes`, `isLegacy`,
 * `upgrade`.
 * @module
 */
import { CryptoliteError } from '../internal/errors';
import { randomBytes } from '../internal/random';
import { utf8Decode } from '../internal/utf8';
import { booleanOption, inputBytes, integerOption, passwordBytes, readOptions, requireString } from './args';
import {
  decryptFailed,
  DEFAULT_ITERATIONS,
  IV_BYTES,
  looksLikeCl1,
  MAX_ITERATIONS,
  MAX_PLAINTEXT_BYTES,
  MIN_ENCRYPT_ITERATIONS,
  MIN_TOKEN_ITERATIONS,
  openCl1,
  parseCl1,
  SALT_BYTES,
  sealCl1,
} from './cl1';
import { platformEngine } from './engine';
import { legacyDecrypt, parseLegacy } from './legacy';

/** Options for {@link encrypt} and {@link upgrade}. */
export interface EncryptOptions {
  /**
   * PBKDF2-HMAC-SHA256 iteration count: an integer from 100000 to 2000000.
   * Default **600000** (OWASP 2023 guidance). The count is stored in the token, so tokens made
   * with different counts can all be decrypted; raising it later only affects new tokens
   * (re-encrypt old ones with {@link upgrade}).
   *
   * Higher is slower for attackers and for you: every `encrypt` and `decrypt` pays the full cost.
   * Where Web Crypto is unavailable (React Native), derivation runs in JavaScript and takes
   * noticeably longer; measure on your slowest target device.
   */
  iterations?: number;
}

/** Options for {@link decrypt} and {@link decryptBytes}. */
export interface DecryptOptions {
  /**
   * Also accept crypto-js ciphertexts (`CryptoJS.AES.encrypt(text, passphrase).toString()`).
   * Default `false`: such input is rejected with `ERR_LEGACY_NOT_ALLOWED`.
   *
   * **Legacy ciphertexts are not authenticated.** Anyone who can modify them can alter the
   * plaintext without detection, and a wrong password is only caught by a padding check that
   * roughly 1 in 256 wrong passwords pass. Enable this only to migrate data, and prefer
   * {@link upgrade} to re-encrypt it as soon as it is read.
   */
  legacy?: boolean;
  /**
   * Refuse cl1 tokens whose iteration count is above this (`ERR_FORMAT`), before doing any work.
   * An integer from 10000 to 2000000; default 2000000 (the format's hard limit).
   *
   * Anyone can write a token with a high count, and decrypting it costs that many PBKDF2
   * iterations even with no password. If you decrypt tokens from untrusted sources (a server
   * receiving them from clients, say), set this to the count you actually issue, e.g. 600000.
   */
  maxIterations?: number;
}

/** Options for {@link upgrade}: `iterations` for the new token, `maxIterations` for the input. */
export interface UpgradeOptions extends EncryptOptions {
  /** See {@link DecryptOptions.maxIterations}; applies to a cl1 token passed in. */
  maxIterations?: number;
}

const ENCRYPT_OPTION_KEYS = ['iterations'] as const;
const DECRYPT_OPTION_KEYS = ['legacy', 'maxIterations'] as const;
const UPGRADE_OPTION_KEYS = ['iterations', 'maxIterations'] as const;

function iterationsOption(value: unknown, fn: string): number {
  return integerOption(value, fn, 'iterations', MIN_ENCRYPT_ITERATIONS, MAX_ITERATIONS, DEFAULT_ITERATIONS);
}

function maxIterationsOption(value: unknown, fn: string): number {
  return integerOption(value, fn, 'maxIterations', MIN_TOKEN_ITERATIONS, MAX_ITERATIONS, MAX_ITERATIONS);
}

function encryptIterations(options: unknown, fn: string): number {
  const { iterations } = readOptions(options, fn, ENCRYPT_OPTION_KEYS);
  return iterationsOption(iterations, fn);
}

interface DecryptPolicy {
  readonly legacy: boolean;
  readonly maxIterations: number;
}

function decryptPolicy(options: unknown, fn: string): DecryptPolicy {
  const { legacy, maxIterations } = readOptions(options, fn, DECRYPT_OPTION_KEYS);
  return { legacy: booleanOption(legacy, fn, 'legacy'), maxIterations: maxIterationsOption(maxIterations, fn) };
}

function checkPlaintextSize(plaintext: Uint8Array, fn: string): void {
  if (plaintext.length > MAX_PLAINTEXT_BYTES) {
    throw new CryptoliteError(
      'ERR_PARAMS',
      `${fn}(): plaintext is too large (${plaintext.length} bytes; the maximum is ${MAX_PLAINTEXT_BYTES}).`,
    );
  }
}

function seal(plaintext: Uint8Array, password: Uint8Array, iterations: number): Promise<string> {
  return sealCl1(platformEngine(), plaintext, password, iterations, randomBytes(SALT_BYTES), randomBytes(IV_BYTES));
}

interface Opened {
  readonly plaintext: Uint8Array;
  readonly legacy: boolean;
}

async function open(token: string, password: Uint8Array, policy: DecryptPolicy, fn: string): Promise<Opened> {
  const legacyAllowed = policy.legacy;
  if (looksLikeCl1(token)) {
    const parsed = parseCl1(token);
    if (parsed.iterations > policy.maxIterations) {
      throw new CryptoliteError(
        'ERR_FORMAT',
        `${fn}(): this cl1 token asks for ${parsed.iterations} PBKDF2 iterations, more than options.maxIterations (${policy.maxIterations}).`,
      );
    }
    return { plaintext: await openCl1(platformEngine(), parsed, password), legacy: false };
  }
  const legacy = parseLegacy(token);
  if (legacy) {
    if (!legacyAllowed) {
      throw new CryptoliteError(
        'ERR_LEGACY_NOT_ALLOWED',
        `${fn}(): this is a crypto-js ciphertext, which is not authenticated. ` +
          'Pass { legacy: true } to decrypt it anyway, or call upgrade(token, password) to re-encrypt it as a cl1 token.',
      );
    }
    return { plaintext: legacyDecrypt(legacy, password), legacy: true };
  }
  throw new CryptoliteError(
    'ERR_FORMAT',
    legacyAllowed
      ? `${fn}(): unrecognized input: expected a cryptolite token (cl1.…) or a crypto-js AES ciphertext (U2FsdGVkX1…).`
      : `${fn}(): unrecognized input: expected a cryptolite token (cl1.…).`,
  );
}

/**
 * Decodes decrypted bytes as UTF-8. For unauthenticated legacy input, invalid UTF-8 almost always
 * means a wrong password that slipped past the padding check, so it is reported as `ERR_DECRYPT`.
 */
function decodeText(opened: Opened, fn: string): string {
  try {
    return utf8Decode(opened.plaintext);
  } catch {
    if (opened.legacy) throw decryptFailed();
    throw new CryptoliteError(
      'ERR_UTF8',
      `${fn}(): the decrypted data is not UTF-8 text. Use decryptBytes() to get the raw bytes.`,
    );
  }
}

/**
 * Encrypts a string or bytes with a password. Returns a `cl1` token: a compact, URL-safe string
 * (`cl1.<iterations>.<salt>.<iv>.<ciphertext>`) that carries everything needed to decrypt it
 * except the password.
 *
 * - Key: PBKDF2-HMAC-SHA256 over the UTF-8 password with a fresh random 16-byte salt.
 * - Cipher: AES-256-GCM with a fresh random 12-byte IV; the header is authenticated too, so any
 *   change to the token makes {@link decrypt} fail with `ERR_DECRYPT` or `ERR_FORMAT`.
 * - Every call produces a different token, even for identical input.
 *
 * Uses the platform's Web Crypto (`crypto.subtle`) when available and pure-JS
 * [@noble](https://github.com/paulmillr/noble-hashes) implementations otherwise (React Native);
 * both produce interchangeable tokens. Requires `crypto.getRandomValues` (see {@link randomBytes}).
 *
 * The password is the only secret. Use a long, high-entropy passphrase or a generated secret:
 * PBKDF2 slows down guessing, but cannot make a weak password strong.
 *
 * @param plaintext - text (encoded as UTF-8) or bytes to encrypt; may be empty; at most
 *   256 MiB once encoded. Bytes are copied when the call starts, so later changes to the array
 *   do not affect the token.
 * @param password - non-empty string, encoded as UTF-8
 * @param options - see {@link EncryptOptions}
 * @returns a `cl1` token
 * @throws {CryptoliteError} (as a rejected promise) `ERR_PARAMS` for a non-string/non-bytes or
 *   oversized plaintext, an empty or non-string password, unknown options, or iterations out of range;
 *   `ERR_UTF8` if a string contains a lone surrogate; `ERR_RANDOM` if no secure RNG exists.
 *
 * @example
 * ```ts
 * import { encrypt, decrypt } from 'cryptolite';
 *
 * const token = await encrypt('meet at noon', password);
 * // 'cl1.600000.Xb3k…'
 * const text = await decrypt(token, password); // 'meet at noon'
 * ```
 */
export async function encrypt(
  plaintext: string | Uint8Array,
  password: string,
  options?: EncryptOptions,
): Promise<string> {
  const input = inputBytes(plaintext, 'encrypt', 'plaintext');
  checkPlaintextSize(input, 'encrypt');
  const pw = passwordBytes(password, 'encrypt');
  // Key derivation is asynchronous: snapshot caller-owned bytes so the token reflects the
  // plaintext as it was at call time, and so wiping below never touches the caller's array.
  const data = typeof plaintext === 'string' ? input : input.slice();
  try {
    return await seal(data, pw, encryptIterations(options, 'encrypt'));
  } finally {
    pw.fill(0);
    data.fill(0);
  }
}

/**
 * Decrypts a token from {@link encrypt} and returns the plaintext as a string.
 *
 * Tokens are parsed strictly: anything that is not exactly what `encrypt` produces (extra
 * whitespace, padding, a different base64 alphabet, a leading zero in the iteration count) is
 * rejected with `ERR_FORMAT` before any key derivation. Tokens whose iteration count is outside
 * 10000–2000000 are rejected too, which bounds the work a hostile token can cause; lower the
 * bound with `maxIterations` when decrypting tokens from untrusted sources.
 *
 * With `{ legacy: true }`, crypto-js ciphertexts (`CryptoJS.AES.encrypt(text, passphrase)
 * .toString()`, default settings) are accepted as well. They are not authenticated; see
 * {@link DecryptOptions.legacy}. For them, plaintext that is not valid UTF-8 is reported as
 * `ERR_DECRYPT`, since that almost always indicates a wrong password.
 *
 * @param token - a `cl1` token (or, with `legacy`, a crypto-js ciphertext)
 * @param password - the password used to encrypt
 * @param options - see {@link DecryptOptions}
 * @returns the plaintext, decoded as UTF-8 (a leading byte-order mark is preserved)
 * @throws {CryptoliteError} (as a rejected promise)
 *   `ERR_DECRYPT` wrong password, or the token was corrupted or tampered with;
 *   `ERR_FORMAT` not a token;
 *   `ERR_LEGACY_NOT_ALLOWED` a crypto-js ciphertext without `{ legacy: true }`;
 *   `ERR_UTF8` the plaintext is binary (use {@link decryptBytes});
 *   `ERR_PARAMS` invalid arguments.
 *
 * @example
 * ```ts
 * import { decrypt, CryptoliteError } from 'cryptolite';
 *
 * try {
 *   const text = await decrypt(token, password);
 * } catch (err) {
 *   if (err instanceof CryptoliteError && err.code === 'ERR_DECRYPT') showWrongPassword();
 *   else throw err;
 * }
 * ```
 */
export async function decrypt(token: string, password: string, options?: DecryptOptions): Promise<string> {
  const input = requireString(token, 'decrypt', 'token');
  const pw = passwordBytes(password, 'decrypt');
  try {
    const opened = await open(input, pw, decryptPolicy(options, 'decrypt'), 'decrypt');
    try {
      return decodeText(opened, 'decrypt');
    } finally {
      opened.plaintext.fill(0);
    }
  } finally {
    pw.fill(0);
  }
}

/**
 * Decrypts a token from {@link encrypt} and returns the plaintext bytes, whether the token was
 * made from a string (you get its UTF-8 bytes) or from bytes.
 *
 * Same parsing, bounds and errors as {@link decrypt}, without the UTF-8 step. Note that for
 * unauthenticated legacy input, roughly 1 in 256 wrong passwords pass the padding check and
 * yield garbage bytes instead of an error; {@link decrypt} and {@link upgrade} catch most of
 * those cases with their UTF-8 check, `decryptBytes` cannot.
 *
 * @param token - a `cl1` token (or, with `legacy`, a crypto-js ciphertext)
 * @param password - the password used to encrypt
 * @param options - see {@link DecryptOptions}
 * @returns the plaintext bytes (a new array)
 * @throws {CryptoliteError} (as a rejected promise) `ERR_DECRYPT`, `ERR_FORMAT`,
 *   `ERR_LEGACY_NOT_ALLOWED` or `ERR_PARAMS`, as for {@link decrypt}.
 *
 * @example
 * ```ts
 * const token = await encrypt(new Uint8Array([1, 2, 3]), password);
 * const bytes = await decryptBytes(token, password); // Uint8Array [1, 2, 3]
 * ```
 */
export async function decryptBytes(token: string, password: string, options?: DecryptOptions): Promise<Uint8Array> {
  const input = requireString(token, 'decryptBytes', 'token');
  const pw = passwordBytes(password, 'decryptBytes');
  try {
    return (await open(input, pw, decryptPolicy(options, 'decryptBytes'), 'decryptBytes')).plaintext;
  } finally {
    pw.fill(0);
  }
}

/**
 * True if `token` is a crypto-js passphrase-mode AES ciphertext, i.e. the output of
 * `CryptoJS.AES.encrypt(text, passphrase).toString()`: canonical padded base64 of `Salted__`,
 * an 8-byte salt and a positive whole number of 16-byte blocks. Such strings always start with
 * `U2FsdGVkX1`.
 *
 * Purely syntactic and cheap (no password, no decryption). Use it to find stored values that
 * still need {@link upgrade}. Never throws; returns `false` for non-strings.
 *
 * @example
 * ```ts
 * if (isLegacy(stored)) stored = await upgrade(stored, password);
 * ```
 */
export function isLegacy(token: string): boolean {
  return typeof token === 'string' && parseLegacy(token) !== undefined;
}

/**
 * Re-encrypts a token as a fresh `cl1` token: the migration path off crypto-js, and the way to
 * move existing cl1 tokens to a new iteration count.
 *
 * Accepts a crypto-js ciphertext (no `legacy` flag needed: reading legacy input is the point) or
 * a `cl1` token. Always decrypts and re-encrypts with a new salt and IV, so the result never
 * equals the input. The password stays the same.
 *
 * Legacy plaintext must be UTF-8 text, which is what `CryptoJS.AES.encrypt(string, passphrase)`
 * produces. Because legacy ciphertexts are unauthenticated, this check is also what stops most
 * wrong passwords from being "upgraded" into a token of garbage; if it fails you get
 * `ERR_DECRYPT`. For a legacy ciphertext of binary data, use
 * `decryptBytes(token, password, { legacy: true })` and {@link encrypt} instead, and verify the
 * result yourself.
 *
 * @param token - a crypto-js ciphertext or a `cl1` token
 * @param password - the password the token was encrypted with (also used for the new token)
 * Integrity caveat: a legacy ciphertext carries no authentication, so `upgrade()` cannot prove it
 * was not modified. Whatever it decrypts to becomes an authenticated cl1 token, so tampering done
 * BEFORE the upgrade is "laundered" into a valid-looking token. Random corruption is very likely
 * caught by the UTF-8 check (`ERR_DECRYPT`), but that check is probabilistic, and the
 * `decryptBytes` + `encrypt` route for binary data has no check at all. Upgrade data you trust.
 *
 * @param options - see {@link UpgradeOptions}; `iterations` applies to the new token,
 *   `maxIterations` to a cl1 token passed in
 * @returns a new `cl1` token with the same plaintext
 * @throws {CryptoliteError} (as a rejected promise) `ERR_DECRYPT`, `ERR_FORMAT`, `ERR_PARAMS`,
 *   `ERR_RANDOM`.
 *
 * @example
 * ```ts
 * import { isLegacy, upgrade } from 'cryptolite';
 *
 * if (isLegacy(row.secret)) {
 *   row.secret = await upgrade(row.secret, password);
 *   await save(row);
 * }
 * ```
 */
export async function upgrade(token: string, password: string, options?: UpgradeOptions): Promise<string> {
  const input = requireString(token, 'upgrade', 'token');
  const pw = passwordBytes(password, 'upgrade');
  try {
    const opts = readOptions(options, 'upgrade', UPGRADE_OPTION_KEYS);
    const iterations = iterationsOption(opts.iterations, 'upgrade');
    const maxIterations = maxIterationsOption(opts.maxIterations, 'upgrade');
    const opened = await open(input, pw, { legacy: true, maxIterations }, 'upgrade');
    try {
      if (opened.legacy) decodeText(opened, 'upgrade');
      checkPlaintextSize(opened.plaintext, 'upgrade');
      return await seal(opened.plaintext, pw, iterations);
    } finally {
      opened.plaintext.fill(0);
    }
  } finally {
    pw.fill(0);
  }
}

/**
 * The `cl1` token format: `cl1.<iterations>.<salt>.<iv>.<ciphertext>`. Internal: the public
 * surface is `encrypt`/`decrypt`/`upgrade`. `sealCl1`/`openCl1` take an explicit engine, salt and
 * IV so tests can compare engines on fixed inputs; they are not exported from the package.
 *
 * - iterations: PBKDF2-HMAC-SHA256 count, base-10, no leading zeros
 * - salt: 16 bytes, iv: 12 bytes, ciphertext: AES-256-GCM output with the 16-byte tag appended;
 *   all canonical unpadded base64url
 * - key = PBKDF2-HMAC-SHA256(UTF-8 password, salt, iterations, 32 bytes)
 * - AAD = ASCII bytes of the header `cl1.<iterations>.<salt>.<iv>`
 * @module
 */
import { base64UrlDecode, base64UrlEncode } from '../internal/base64';
import { CryptoliteError } from '../internal/errors';
import { utf8Encode } from '../internal/utf8';
import type { Cl1Engine } from './engine';

export const CL1_VERSION = 'cl1';
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
export const TAG_BYTES = 16;

/** Default PBKDF2 iteration count for new tokens (OWASP 2023 guidance for PBKDF2-HMAC-SHA256). */
export const DEFAULT_ITERATIONS = 600_000;
/** Smallest iteration count `encrypt`/`upgrade` will use. */
export const MIN_ENCRYPT_ITERATIONS = 100_000;
/** Smallest iteration count a token may carry: refuses trivially weak tokens. */
export const MIN_TOKEN_ITERATIONS = 10_000;
/** Largest iteration count anywhere: bounds the work a hostile token can demand. */
export const MAX_ITERATIONS = 10_000_000;

const SALT_CHARS = 22; // ceil(16 * 4 / 3), unpadded
const IV_CHARS = 16; // 12 * 4 / 3
const MIN_SEALED_CHARS = 22; // the 16-byte tag alone (empty plaintext)
// 1-8 digits without a leading zero; the numeric bounds are checked afterwards.
const ITERATIONS_PATTERN = /^[1-9][0-9]{0,7}$/;

/** A syntactically valid cl1 token, decoded. */
export interface Cl1Token {
  readonly iterations: number;
  readonly salt: Uint8Array;
  readonly iv: Uint8Array;
  /** Ciphertext with the GCM tag appended. */
  readonly sealed: Uint8Array;
  /** `cl1.<iterations>.<salt>.<iv>`, exactly as it appears in the token (the AAD). */
  readonly header: string;
}

function malformed(detail: string): CryptoliteError {
  return new CryptoliteError(
    'ERR_FORMAT',
    `Malformed cl1 token: ${detail}. Expected cl1.<iterations>.<salt>.<iv>.<ciphertext>.`,
  );
}

function decodePart(value: string, name: string, chars: number | undefined): Uint8Array {
  if (chars !== undefined && value.length !== chars) throw malformed(`${name} has the wrong length`);
  try {
    return base64UrlDecode(value);
  } catch {
    throw malformed(`${name} is not canonical unpadded base64url`);
  }
}

/** True if the string claims to be a cl1 token (it may still be malformed). */
export function looksLikeCl1(token: string): boolean {
  return token.startsWith(`${CL1_VERSION}.`);
}

/**
 * Strictly parses a cl1 token. Only the canonical serialisation is accepted, so a token cannot be
 * altered in any way that leaves its decoded contents (and hence authentication) unchanged.
 * @throws {CryptoliteError} `ERR_FORMAT` if the token is malformed or its iteration count is
 *   outside [{@link MIN_TOKEN_ITERATIONS}, {@link MAX_ITERATIONS}].
 */
export function parseCl1(token: string): Cl1Token {
  // A limit of 6 keeps a hostile string with millions of dots from allocating millions of parts.
  const parts = token.split('.', 6);
  if (parts.length !== 5 || parts[0] !== CL1_VERSION) throw malformed('wrong number of parts');
  const [, iterationsText, saltText, ivText, sealedText] = parts as [string, string, string, string, string];
  if (!ITERATIONS_PATTERN.test(iterationsText)) throw malformed('iterations is not a canonical decimal integer');
  const iterations = Number(iterationsText);
  if (iterations < MIN_TOKEN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new CryptoliteError(
      'ERR_FORMAT',
      `This cl1 token uses ${iterations} PBKDF2 iterations; accepted tokens use ${MIN_TOKEN_ITERATIONS} to ${MAX_ITERATIONS}.`,
    );
  }
  const salt = decodePart(saltText, 'salt', SALT_CHARS);
  const iv = decodePart(ivText, 'iv', IV_CHARS);
  if (sealedText.length < MIN_SEALED_CHARS) throw malformed('ciphertext is too short');
  const sealed = decodePart(sealedText, 'ciphertext', undefined);
  return {
    iterations,
    salt,
    iv,
    sealed,
    header: `${CL1_VERSION}.${iterationsText}.${saltText}.${ivText}`,
  };
}

/** The single, detail-free decryption failure shared by the cl1 and legacy paths. */
export function decryptFailed(): CryptoliteError {
  return new CryptoliteError(
    'ERR_DECRYPT',
    'Decryption failed: wrong password, or the data is corrupted or was tampered with.',
  );
}

/**
 * Seals `plaintext` into a cl1 token with the given engine, parameters, salt and IV.
 * The caller supplies fresh random salt and IV; reusing an IV with the same key breaks GCM.
 * @throws {CryptoliteError} `ERR_PARAMS` if the parameters could not produce a token that
 *   `parseCl1` accepts.
 */
export async function sealCl1(
  engine: Cl1Engine,
  plaintext: Uint8Array,
  password: Uint8Array,
  iterations: number,
  salt: Uint8Array,
  iv: Uint8Array,
): Promise<string> {
  if (
    !Number.isInteger(iterations) ||
    iterations < MIN_TOKEN_ITERATIONS ||
    iterations > MAX_ITERATIONS ||
    salt.length !== SALT_BYTES ||
    iv.length !== IV_BYTES
  ) {
    throw new CryptoliteError('ERR_PARAMS', 'Invalid cl1 parameters.');
  }
  const header = `${CL1_VERSION}.${iterations}.${base64UrlEncode(salt)}.${base64UrlEncode(iv)}`;
  const key = await engine.deriveKey(password, salt, iterations);
  try {
    const sealed = await engine.seal(key, iv, utf8Encode(header), plaintext);
    return `${header}.${base64UrlEncode(sealed)}`;
  } finally {
    key.fill(0);
  }
}

/**
 * Opens a parsed cl1 token.
 * @throws {CryptoliteError} `ERR_DECRYPT` if authentication fails (wrong password or tampering).
 */
export async function openCl1(engine: Cl1Engine, token: Cl1Token, password: Uint8Array): Promise<Uint8Array> {
  const key = await engine.deriveKey(password, token.salt, token.iterations);
  try {
    return await engine.open(key, token.iv, utf8Encode(token.header), token.sealed);
  } catch {
    throw decryptFailed();
  } finally {
    key.fill(0);
  }
}

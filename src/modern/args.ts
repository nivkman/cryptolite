/**
 * Runtime validation of public-API arguments. TypeScript types vanish at runtime and many callers
 * are plain JavaScript, so every public entry point checks its inputs here before doing any work.
 * Internal: not part of the public API.
 * @module
 */
import { isBytes, plainBytes } from '../internal/bytes';
import { CryptoliteError } from '../internal/errors';
import { utf8Encode } from '../internal/utf8';

function paramsError(message: string): CryptoliteError {
  return new CryptoliteError('ERR_PARAMS', message);
}

/** UTF-8 encodes an argument, naming it (never quoting it) if it is not well-formed Unicode. */
function encodeArgument(value: string, fn: string, name: string): Uint8Array {
  try {
    return utf8Encode(value);
  } catch {
    throw new CryptoliteError(
      'ERR_UTF8',
      `${fn}(): ${name} is not well-formed Unicode (it contains a lone UTF-16 surrogate), so it cannot be encoded as UTF-8.`,
    );
  }
}

/** Converts `string | Uint8Array` input to plain bytes; strings are UTF-8 encoded. */
export function inputBytes(value: unknown, fn: string, name: string): Uint8Array {
  if (typeof value === 'string') return encodeArgument(value, fn, name);
  if (isBytes(value)) return plainBytes(value);
  throw paramsError(`${fn}(): ${name} must be a string or a Uint8Array.`);
}

/** UTF-8 bytes of a password; the caller should wipe them after use. */
export function passwordBytes(value: unknown, fn: string): Uint8Array {
  if (typeof value !== 'string' || value.length === 0) {
    throw paramsError(`${fn}(): password must be a non-empty string.`);
  }
  return encodeArgument(value, fn, 'password');
}

export function requireString(value: unknown, fn: string, name: string): string {
  if (typeof value !== 'string') throw paramsError(`${fn}(): ${name} must be a string.`);
  return value;
}

/**
 * Validates an options object: `undefined`, or a plain object whose own keys are all in `allowed`.
 * Unknown keys are rejected so a typo (`{ iteration: 200000 }`) is an error, not a silent default.
 */
export function readOptions<K extends string>(
  options: unknown,
  fn: string,
  allowed: readonly K[],
): Partial<Record<K, unknown>> {
  if (options === undefined) return {};
  if (typeof options !== 'object' || options === null || Array.isArray(options)) {
    throw paramsError(`${fn}(): options must be an object.`);
  }
  for (const key of Object.keys(options)) {
    if (!(allowed as readonly string[]).includes(key)) {
      throw paramsError(`${fn}(): unknown option "${key}" (supported: ${allowed.join(', ')}).`);
    }
  }
  return options as Partial<Record<K, unknown>>;
}

/** Validates an integer option in [min, max], returning `fallback` when it is absent. */
export function integerOption(
  value: unknown,
  fn: string,
  name: string,
  min: number,
  max: number,
  fallback: number,
): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw paramsError(`${fn}(): options.${name} must be an integer from ${min} to ${max} (default ${fallback}).`);
  }
  return value;
}

/** Validates a boolean option, returning `false` when it is absent. */
export function booleanOption(value: unknown, fn: string, name: string): boolean {
  if (value === undefined) return false;
  if (typeof value !== 'boolean') throw paramsError(`${fn}(): options.${name} must be a boolean.`);
  return value;
}

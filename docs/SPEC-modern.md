# Modern API spec (v1)

Named exports from the package root (`import { encrypt } from 'cryptolite'`), also attached to
the CommonJS export object. Pure functions, no global state. All primitives from `@noble/*`
or the platform's Web Crypto (never home-made). Must run on Node >= 20, browsers, Deno, Bun,
Cloudflare Workers and React Native (Hermes: no `crypto.subtle`, and do NOT rely on
`TextEncoder`/`TextDecoder` existing).

## Password-based authenticated encryption

```ts
encrypt(plaintext: string | Uint8Array, password: string, options?: { iterations?: number }): Promise<string>
decrypt(token: string, password: string, options?: { legacy?: boolean }): Promise<string>
decryptBytes(token: string, password: string, options?: { legacy?: boolean }): Promise<Uint8Array>
isLegacy(token: string): boolean
upgrade(token: string, password: string, options?: { iterations?: number }): Promise<string>
```
All five validate their arguments at runtime; the async ones report every error as a rejected
promise, never a synchronous throw. Unknown option keys are `ERR_PARAMS` (R5). `upgrade` also
accepts cl1 tokens (R4).

### Token format `cl1`
`cl1.<iterations>.<salt>.<iv>.<ciphertext>`
- `iterations`: base-10 integer, PBKDF2 iteration count. Default **600000** (OWASP 2023 for
  PBKDF2-HMAC-SHA256). `encrypt` accepts `options.iterations` in [100000, 2000000].
  `decrypt` rejects tokens outside [10000, 2000000] (bounds DoS from hostile tokens and
  refuses trivially weak ones).
- `salt`: 16 random bytes, base64url (no padding).
- `iv`: 12 random bytes, base64url.
- `ciphertext`: AES-256-GCM ciphertext with the 16-byte tag appended, base64url.
- Key = PBKDF2-HMAC-SHA256(password UTF-8, salt, iterations, 32 bytes).
- AAD = the ASCII bytes of the header `cl1.<iterations>.<salt>.<iv>` so the header can't be
  altered without failing authentication.
- Strict parsing: exactly 5 dot-separated parts, canonical base64url (reject padding, `+`, `/`,
  whitespace), exact lengths, iterations without leading zeros.

### Implementation paths
- Prefer `globalThis.crypto.subtle` (PBKDF2 + AES-GCM) when present: native and fast.
  Chosen per call. If any Web Crypto step throws, that step is retried with noble and noble's
  result is final (R6).
- Fallback when `subtle` is missing (React Native): `@noble/hashes` `pbkdf2Async` + `sha256`
  and `@noble/ciphers` `gcm`. Outputs must be identical; test both paths against each other
  (expose an internal switch for tests only, not in the public types). Implemented as internal
  `sealCl1`/`openCl1` (src/modern/cl1.ts) taking an explicit engine, salt and IV; not exported
  from src/modern/index.ts.

### Errors
Throw `CryptoliteError` (exported class, `name = 'CryptoliteError'`, `code` string):
- `ERR_DECRYPT` — wrong password or tampered/corrupted data (single generic message, no oracle detail).
- `ERR_FORMAT` — not a cl1 token (and not legacy when legacy allowed), including a cl1 token
  whose iteration count is outside [10000, 2000000] (R1).
- `ERR_LEGACY_NOT_ALLOWED` — the input is a crypto-js ciphertext but `legacy` was not enabled;
  message tells the user to pass `{ legacy: true }` or call `upgrade()`.
- `ERR_PARAMS` — `options.iterations` out of range, empty password, wrong argument types,
  unknown option keys, invalid encoding/algorithm/length.
- `ERR_RANDOM` — `crypto.getRandomValues` unavailable; message mentions
  `react-native-get-random-values` for React Native.
- `ERR_UTF8` — decrypted cl1 bytes are not valid UTF-8 (use `decryptBytes`), or a string
  argument contains a lone surrogate and cannot be UTF-8 encoded (R2). For legacy input,
  invalid UTF-8 is `ERR_DECRYPT` instead (R3).

Messages never contain passwords, plaintext, or positions within them.

### Legacy (crypto-js) ciphertext
`isLegacy(token)` is true when the token is standard base64 that decodes to bytes starting
with `Salted__` (i.e. the string starts with `U2FsdGVkX1`) and length >= 32 bytes with a
ciphertext length that's a positive multiple of 16. "Standard base64" means canonical and
padded, exactly what `CipherParams#toString()` emits (R7). Never throws; `false` for non-strings.
Legacy decrypt (only with `{ legacy: true }` or via `upgrade`): crypto-js default passphrase
mode = OpenSSL `EVP_BytesToKey` (MD5, 1 iteration) → 32-byte key + 16-byte IV from
password+salt, AES-256-CBC, PKCS#7. Use noble `md5` + `cbc` (which validates padding).
Any failure → `ERR_DECRYPT`. Document clearly that legacy ciphertexts are unauthenticated.
Must decrypt output of real `CryptoJS.AES.encrypt(text, passphrase).toString()` — test it
against the `crypto-js` devDependency.

## Hashing (synchronous)

```ts
type Encoding = 'hex' | 'base64' | 'base64url' | 'bytes'
md5(data: string | Uint8Array, encoding?: Encoding): string | Uint8Array   // default 'hex'
sha1(...), sha256(...), sha384(...), sha512(...), sha3_256(...), sha3_512(...)
hmac(algorithm: 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512', key: string | Uint8Array, data: string | Uint8Array, encoding?: Encoding)
randomBytes(length: number): Uint8Array
```
Overloads so `encoding: 'bytes'` returns `Uint8Array` and others return `string`.
Strings are UTF-8 encoded. `sha3_*` are FIPS-202 SHA-3 (NOT crypto-js's Keccak "SHA3");
say so in the JSDoc. `md5`/`sha1` JSDoc: not for security, compatibility only.

## Non-goals for v1
Key-based (non-password) encryption, streaming, AAD parameters, asymmetric crypto.

## Refinements made during implementation (modern-api agent, 2026-10-24)

Each entry: what changed relative to the original text above, then why.

- **R1. A token's out-of-range iteration count is `ERR_FORMAT`, not `ERR_PARAMS`.**
  `ERR_PARAMS` is for the caller's arguments. The iteration count in a token is data. Rejecting
  it before key derivation is a format check, so every single-character tamper of a token yields
  `ERR_FORMAT` or `ERR_DECRYPT`.
- **R2. `ERR_UTF8` also covers string *inputs* with lone surrogates** (plaintext, password, hash
  data, HMAC key). `TextEncoder`/`Buffer` silently replace them with U+FFFD, which would make
  different strings encrypt or hash identically. crypto-js's `Utf8.parse` throws here too
  (`encodeURIComponent`).
- **R3. Legacy plaintext that is not valid UTF-8 is `ERR_DECRYPT` in `decrypt()` and `upgrade()`.**
  Legacy CBC is unauthenticated: about 1 in 256 wrong passwords pass the PKCS#7 check and yield
  garbage. Reporting `ERR_UTF8` ("use decryptBytes") would tell a user with the wrong password
  that their password was right. Consequence: `upgrade()` only migrates legacy *text*. Binary
  legacy payloads go through `decryptBytes(t, pw, { legacy: true })` + `encrypt()`, as
  documented in the JSDoc. `decryptBytes` cannot detect those wrong passwords, and its JSDoc says so.
- **R4. `upgrade()` accepts cl1 tokens too and always re-encrypts** with a fresh salt and IV (at
  `options.iterations`, default 600000). It is the same call for moving off crypto-js and for raising
  the iteration count of existing tokens; "always re-encrypt" is simpler to reason about than
  "sometimes return the input".
- **R5. Options are strict:** `undefined` or a non-array object whose keys are all known; anything else
  is `ERR_PARAMS`. This makes a typo like `{ iteration: 200000 }` fail loudly instead of silently using
  the default. It is easier to relax in a minor release than to tighten.
- **R6. Web Crypto is an accelerator, not a dependency.** If any Web Crypto step rejects, that step is
  retried with noble and noble's outcome is final. Both compute the same function, so this
  can only turn a platform failure into the correct answer; wrong passwords and tampering still fail.
  Motivation: runtimes whose `subtle` is partial (polyfills) or caps PBKDF2 iterations. *Unverified:*
  Cloudflare Workers is reported to cap PBKDF2 at 100000 iterations. The fallback is tested
  here with a simulated cap, not on Workers. If such a cap applies, iteration counts above it run in
  pure JS there, which is CPU-expensive.
- **R7. Legacy input must be canonical padded base64** (no surrounding whitespace, no stripped
  padding), matching what crypto-js emits. Other strings are not legacy, so they get `ERR_FORMAT`.
  Callers can `.trim()` first.
- **R8. Empty passwords are rejected everywhere, including legacy decryption** (crypto-js allowed `''`).
  Such data was never protected. The compat API (`CryptoJS.AES.decrypt(ct, '')`) can still read it.
- **R9. Legacy scope:** only crypto-js *default* passphrase mode (AES, CBC, Pkcs7, OpenSSL format,
  MD5 EvpKDF). Ciphertexts made with a custom `hasher`, mode, padding, or key/IV mode give `ERR_DECRYPT` or
  `ERR_FORMAT`.
- **R10. Public types** exported alongside the functions: `EncryptOptions`, `DecryptOptions`,
  `Encoding`, `HashFunction` (the overloaded signature shared by `md5` … `sha3_512`), `HmacAlgorithm`,
  `CryptoliteErrorCode`. Hash functions are `const`s typed `HashFunction` (one overload set instead of
  seven copies). Accepted byte inputs: any `Uint8Array`, including Node `Buffer` and cross-realm arrays
  (Jest/vm/iframes); other typed arrays, `ArrayBuffer` and `DataView` are `ERR_PARAMS`.
- **R11. `randomBytes(length)`**: integer 0..2147483647 (Node's ceiling), else `ERR_PARAMS`. Fills in
  65536-byte chunks (Web Crypto's per-call quota). Never falls back to `Math.random`.
- **R12. Plaintext bound: 256 MiB** (after UTF-8 encoding) for `encrypt` and `upgrade`, else `ERR_PARAMS`.
  A token is one string, and its base64url form must fit under engines' maximum string length (about
  512 MiB in V8). Without the bound, oversized input dies deep inside with `RangeError: Invalid string
  length`. Hostile *tokens* need no extra bound: their size is already capped by the string limit,
  and their PBKDF2 cost by R1.
- **R13. `encrypt` snapshots byte input when called** (one copy, wiped afterwards). Key derivation is
  asynchronous, so without the copy a caller mutating the array mid-call would change what gets encrypted.
  Caller-owned arrays are never wiped or modified.

### Internal helpers (`src/internal/`, reusable by the compat layer)
`utf8.ts` (`utf8Encode`/`utf8Decode`: no TextEncoder/TextDecoder, same accept/reject set as
`TextDecoder({ fatal: true })`, BOM kept, throws `CryptoliteError` `ERR_UTF8`), `base64.ts` (strict
canonical `base64*`/`base64Url*`), `hex.ts`, `random.ts`, `bytes.ts` (`isBytes`, `plainBytes`,
`concatBytes`, `charCodesToString`), `errors.ts` (`CryptoliteError`). No constant-time compare: nothing
in the modern API needs one (GCM tag checks happen inside noble/Web Crypto).

## Security-review changes (2026-10-24, see docs/reviews/security.md)
- **S1 (M1)** Options are read from a null-prototype copy of the caller's own keys, so a polluted
  `Object.prototype` cannot change `iterations` or `legacy`.
- **S2 (M2)** Hard iteration cap lowered from 10,000,000 to **2,000,000** (≈0.4 s Web Crypto /
  ≈7 s pure JS for a hostile token on a 2026 server CPU), and `decrypt`/`decryptBytes`/`upgrade`
  take `maxIterations` (10000..2000000, default 2000000) to refuse higher counts before any work.
  Unreleased format, so no compatibility impact.
- **S3 (L1)** A Web Crypto `OperationError` on decrypt (GCM authentication failure) is final; only
  other platform errors fall back to noble.
- **S4 (L2)** A throwing `getRandomValues` surfaces as `ERR_RANDOM`.
- **S5 (L3)** `upgrade()` JSDoc states the integrity caveat for legacy input.

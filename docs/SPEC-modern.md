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

### Token format `cl1`
`cl1.<iterations>.<salt>.<iv>.<ciphertext>`
- `iterations`: base-10 integer, PBKDF2 iteration count. Default **600000** (OWASP 2023 for
  PBKDF2-HMAC-SHA256). `encrypt` accepts `options.iterations` in [100000, 10000000].
  `decrypt` rejects tokens outside [10000, 10000000] (bounds DoS from hostile tokens and
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
- Fallback when `subtle` is missing (React Native): `@noble/hashes` `pbkdf2Async` + `sha256`
  and `@noble/ciphers` `gcm`. Outputs must be identical; test both paths against each other
  (expose an internal switch for tests only, not in the public types).

### Errors
Throw `CryptoliteError` (exported class, `name = 'CryptoliteError'`, `code` string):
- `ERR_DECRYPT` — wrong password or tampered/corrupted data (single generic message, no oracle detail).
- `ERR_FORMAT` — not a cl1 token (and not legacy when legacy allowed).
- `ERR_LEGACY_NOT_ALLOWED` — the input is a crypto-js ciphertext but `legacy` was not enabled;
  message tells the user to pass `{ legacy: true }` or call `upgrade()`.
- `ERR_PARAMS` — iterations out of range, empty password, wrong argument types.
- `ERR_RANDOM` — `crypto.getRandomValues` unavailable; message mentions
  `react-native-get-random-values` for React Native.
- `ERR_UTF8` — decrypted bytes are not valid UTF-8 (use `decryptBytes`).

### Legacy (crypto-js) ciphertext
`isLegacy(token)` is true when the token is standard base64 that decodes to bytes starting
with `Salted__` (i.e. the string starts with `U2FsdGVkX1`) and length >= 32 bytes with a
ciphertext length that's a positive multiple of 16.
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

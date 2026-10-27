# Migrating to cryptolite

For the one-paragraph version, see the README's [10-second migration](README.md#the-10-second-migration). This document covers the rest: library authors, migrating stored ciphertexts, verifying the switch, and the two documented incompatibilities with crypto-js (unsupported ciphers, AES key sizes).

## For applications

1. **Install.**

   ```sh
   npm install @nivkman/cryptolite
   ```

2. **Swap the import.** Every crypto-js import path has the same cryptolite path:

   ```diff
   - import CryptoJS from 'crypto-js';
   + import CryptoJS from '@nivkman/cryptolite';
   ```

   ```diff
   - const sha256 = require('crypto-js/sha256');
   + const sha256 = require('@nivkman/cryptolite/sha256');
   ```

   Everything else in your code — `CryptoJS.AES.encrypt(...)`, `CryptoJS.enc.Utf8`, `CryptoJS.algo.SHA256.create()`, and so on — is unchanged. That's the point of the compat API: it mirrors crypto-js 4.2.0's module paths and object shapes exactly.

3. **Remove the old dependency** once nothing imports it:

   ```sh
   npm uninstall crypto-js
   ```

   If you also had `@types/crypto-js` installed for type checking, you can remove that too — cryptolite ships its own, compatible types. (Keep it if some other dependency still needs the real crypto-js types; it does no harm.)

4. **Run your tests.** See [Verifying the switch](#verifying-the-switch) below.

If you'd rather not touch imports at all — because there are many of them, or because a dependency you don't control imports crypto-js directly — use one of the aliasing routes instead; see the README's [Option 2 and Option 3](README.md#the-10-second-migration). Both are zero-code-change: you only edit `package.json` (or `pnpm-workspace.yaml`), not your source.

## For library authors

If you publish a package that currently depends on `crypto-js`:

- **Switch your own `package.json` dependency to `cryptolite` and update your own imports** (step 2 above), the same as an application would. Relying on *your users* to set up an `overrides`/`resolutions` entry only helps consumers who think to do it; it does nothing for your own CI, your own tests, or users who don't.
- **This is very unlikely to be a breaking change for your own consumers.** Byte-identical output means anything your package returns or stores (hashes, ciphertexts, encodings) is unaffected. The two documented exceptions are the [unsupported ciphers](#unsupported-ciphers) and [non-standard AES key sizes](#aes-key-sizes) below — if your package's public API exposes either of those, note it in your own changelog.
- **Keep `@types/crypto-js` or switch to cryptolite's bundled types** in your own `.d.ts` output — both describe the same shapes, so either is fine; just be consistent so your consumers don't end up with two conflicting `CryptoJS` namespaces at the type level.
- **If you must keep working with raw crypto-js types in your source** (e.g. you re-export `CryptoJS.lib.WordArray` as part of your own public API), nothing changes: cryptolite's `WordArray` is the same shape.
- You do not need to publish a codemod or a compatibility shim for your own users — the root/subpath mirror means a plain dependency swap is enough.

## Migrating stored data to the modern format

Compat-API output (crypto-js-shaped ciphertexts, e.g. from `CryptoJS.AES.encrypt(text, passphrase).toString()`) keeps working forever in cryptolite's compat layer — switching to cryptolite does not, by itself, require migrating anything you've already stored. Migrate when you choose to move to the modern, authenticated format:

```ts
import { isLegacy, decrypt, upgrade } from '@nivkman/cryptolite';

if (isLegacy(stored)) {
  stored = await upgrade(stored, password);
  await save(stored);
}
```

- `isLegacy(token)` is a cheap, synchronous, no-password check: `true` if `token` looks like crypto-js passphrase-mode AES output (`CryptoJS.AES.encrypt(text, passphrase).toString()`, the default settings — not a custom hasher, mode, padding, or key/IV mode).
- `upgrade(token, password)` decrypts it (crypto-js's legacy format, unauthenticated) and re-encrypts it as a fresh `cl1` token with a new salt and IV. The password stays the same.
- `upgrade()` requires the legacy plaintext to be valid UTF-8 text — which is what `CryptoJS.AES.encrypt(string, passphrase)` produces. This also happens to be the main thing standing between a wrong password and silently "upgrading" garbage: legacy CBC is unauthenticated, so roughly 1 in 256 wrong passwords pass the PKCS#7 padding check, and most of what comes out on the wrong side of that is not valid UTF-8.
- If the legacy ciphertext holds **binary** data (not text), `upgrade()` can't be used directly — decode and re-encrypt by hand instead, and verify the result yourself since this path has no built-in check against a wrong password:

  ```ts
  import { decryptBytes, encrypt } from '@nivkman/cryptolite';

  const bytes = await decryptBytes(stored, password, { legacy: true });
  stored = await encrypt(bytes, password);
  ```
- You can also call `decrypt(token, password, { legacy: true })` to read a legacy ciphertext without upgrading it yet — useful if you want to migrate on read, over time, rather than in one pass over your whole dataset.
- Prefer migrating sooner rather than later: legacy ciphertexts are **not authenticated** (see the README's [cl1 token format](README.md#the-cl1-token-format) section for why), so anyone who can modify stored legacy ciphertext can tamper with the plaintext undetected until it's upgraded.
- **`upgrade()` cannot prove a legacy ciphertext wasn't tampered with before you read it** — only that the result looked like valid UTF-8, which is a probabilistic check (see the point above), not authentication. Whatever it decrypts to is re-encrypted as a fully authenticated `cl1` token, so a tamper that happened before the upgrade is effectively laundered into something later code will trust. Only run `upgrade()` on legacy data you otherwise trust the integrity of (e.g. it came from your own database, not directly from a user-supplied field you've never validated).

## Verifying the switch

Don't take byte-identical output on faith — check it against your own data and your own test suite.

1. **Run your existing test suite** against cryptolite exactly as it ran against crypto-js. If your tests covered crypto-js's output (fixed hashes, ciphertexts, HMACs), they're already a differential check; they should pass unchanged.
2. **Compare outputs directly**, if you want an extra point of evidence beyond your own tests — install both packages side by side under different names and diff a few real values from your own data:

   ```ts
   import RealCryptoJS from 'crypto-js';
   import CryptoJS from '@nivkman/cryptolite';

   console.log(RealCryptoJS.SHA256('abc').toString() === CryptoJS.SHA256('abc').toString()); // true
   console.log(RealCryptoJS.AES.decrypt(CryptoJS.AES.encrypt('hi', 'pw').toString(), 'pw').toString(RealCryptoJS.enc.Utf8)); // 'hi', decrypted by the *other* library
   ```

   This is exactly what cryptolite's own differential suite does at a larger scale — see `test/compat/**`, which runs fixed vectors, randomized sweeps, and (with `FUZZ=1`) much wider fuzzing against the real `crypto-js@4.2.0` devDependency, in both directions (cryptolite reads crypto-js output and vice versa).
3. **Typecheck**, if you use TypeScript: your existing `@types/crypto-js`-typed code should compile against cryptolite's bundled types without changes. If it doesn't, that's worth a bug report (cryptolite's types are a mechanical port of `@types/crypto-js@4.2.2`, plus one additive fix documented in `docs/DECISIONS.md` D12).

## Unsupported ciphers

cryptolite does not implement `DES`, `TripleDES`, `RC4`, `RC4Drop`, `Rabbit`, `RabbitLegacy` or `Blowfish`. `import`ing them still works (so a side-effect-only import doesn't break), but calling them throws:

```
cryptolite does not implement RC4: it is a broken legacy cipher and cryptolite only ships
audited primitives. Keep crypto-js for RC4 data, or migrate it — see
https://github.com/nivkman/cryptolite/blob/main/MIGRATION.md#unsupported-ciphers
```

Why: cryptolite implements no cryptography of its own (see `docs/DECISIONS.md` D4) — every cipher and hash comes from `@noble/ciphers` / `@noble/hashes`, which don't implement these constructions, most of which are broken or long obsolete. Shipping a hand-rolled copy just for compatibility would contradict the one design rule that makes a one-person-maintained crypto package worth trusting.

**What to do:**

- **If you still need to read or write data in one of these ciphers**, keep `crypto-js` installed alongside cryptolite for that specific use (they can coexist under different import names), or use a dedicated library for that cipher.
- **If you control the data**, re-encrypt it with something cryptolite does support: `CryptoJS.AES` (compat API) for crypto-js-shaped output, or `encrypt`/`decrypt` (modern API) for a clean, authenticated start.
- **This list will not grow by default.** If you have a real need for one of these, open an issue — `docs/DECISIONS.md` D6 calls this "revisit on demand," not "never."

## AES key sizes

crypto-js's `AES.encrypt(data, key)` (where `key` is meant to be a `WordArray`, not a passphrase string) silently accepts almost anything as `key` — a `WordArray` of any byte length, or even a plain string or number passed where a direct key was expected (as opposed to `AES.encrypt(data, 'a passphrase')`, which is a different, supported code path — see below). Internally it derives a key schedule for whatever it was given and produces output that **no other AES implementation — including `crypto-js` itself, on a slightly different code path — can be assumed to reproduce**, because AES itself is only defined for 128, 192 and 256-bit (16/24/32-byte) keys.

cryptolite rejects both cases instead of reproducing them. Wrong byte length:

```
cryptolite: AES key must be 16, 24 or 32 bytes (got 10). crypto-js silently accepted other
sizes and produced non-standard ciphertext that no other AES implementation can read. Pass a
string to use a passphrase instead, or derive a proper key with PBKDF2. See
MIGRATION.md#aes-key-sizes.
```

Not a `WordArray` at all (a string or number passed as a direct key, not a passphrase):

```
cryptolite: an AES key must be a WordArray with a whole number of bytes (16, 24 or 32).
(crypto-js accepted other values here and produced unusable ciphertext.) To encrypt with
a passphrase, pass a string to CryptoJS.AES.encrypt() instead.
```

**What to do:**

- **If you were passing a passphrase (a string) to `CryptoJS.AES.encrypt(data, passphrase)` itself**, neither error applies to you — that's the documented passphrase/`EvpKDF` path, which already produces a standard 32-byte key, and cryptolite reproduces it exactly. These errors are about a *direct* key (typically a `WordArray` from `enc.Hex.parse`/`enc.Utf8.parse`/`PBKDF2`/`lib.WordArray.random`, or a lower-level call like `algo.AES.createEncryptor(key, { iv })`) that isn't a standard-length `WordArray`.
- **If you were intentionally passing a `WordArray` key of a non-standard length**, derive a standard-length key from it instead — for example with `CryptoJS.PBKDF2(key, salt, { keySize: 256 / 32 })` (compat API) — and re-encrypt your data. The old ciphertext was never interoperable with anything but that exact build of crypto-js; there is no way to make cryptolite read it, because the key schedule it used isn't one AES defines.
- **If you were passing a string or number as a direct key by mistake** (not a passphrase, and not intentionally — this usually means `AES.encrypt(data, someString)` was meant to call the passphrase path but something upstream converted it, or a lower-level `createEncryptor` call was given the wrong type), the ciphertext it produced under crypto-js was not standard AES either; treat it the same as a non-standard key size above.

## Other deliberate differences

Two more exceptions to byte-identical output, both documented in `docs/DECISIONS.md` D14 and covered by the differential test suite (so a future accidental regression would fail a test, not just this doc):

- **`SHA3(data, { outputLength })` requires a multiple of 32 from 0 to 768.** crypto-js accepts other values and loops forever on some of them instead of returning or erroring. cryptolite throws `cryptolite: SHA3 outputLength must be a multiple of 32 from 0 to 768 (got <value>).` for anything outside that range — a hang turned into an error, not a silent behavior change for any value that previously worked.
- **A digest `WordArray` is an independent copy, not crypto-js's live internal hasher state.** In crypto-js, the `WordArray` returned by `finalize()` can alias the hasher's own buffer, so mutating it (or calling `finalize()` again on the same hasher instance) can retroactively change what you already read. cryptolite always returns an independent copy. No known real program depends on the aliasing; this direction (independent over shared) is the safer one to diverge in, and it's why this is listed as a difference rather than a bug.

Everything else — including inputs crypto-js itself can produce, like hashing a decrypted `WordArray` whose length isn't a multiple of 4, or `Hex.parse()` of an odd-length hex string — is byte-identical; see `docs/DECISIONS.md` D14 for how.
- **If you have existing data encrypted with a non-standard key size** (for example a bare `Utf8.parse('short-string')` passed as the key, rather than through PBKDF2/`EvpKDF`), cryptolite cannot read it at all — not "slowly" or "with a flag", because the bytes it would need to produce aren't standard AES output in the first place. You'll need `crypto-js` to decrypt that data one time; from there, treat it like any other migration: decrypt with `crypto-js`, then re-encrypt with cryptolite (`CryptoJS.AES.encrypt` with a proper key, or the modern `encrypt()`) and store the new ciphertext. Keep `crypto-js` installed only for that one-time read, not as a permanent dependency.

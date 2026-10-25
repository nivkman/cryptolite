# Security policy

## Reporting a vulnerability

Please report security issues using **GitHub's private vulnerability reporting**, not a public issue:

1. Go to [github.com/nivkman/cryptolite/security/advisories](https://github.com/nivkman/cryptolite/security/advisories).
2. Click **"Report a vulnerability"**.

This opens a private channel with the maintainer; it does not create a public issue. There is no security email address for this project — use GitHub's reporting flow above.

Please include: the version affected, a minimal reproduction, and what you believe the impact is (what an attacker gains, and what they need to already control or know). If your report concerns `@noble/hashes` or `@noble/ciphers` themselves rather than cryptolite's use of them, please also report it upstream ([noble-hashes](https://github.com/paulmillr/noble-hashes/security), [noble-ciphers](https://github.com/paulmillr/noble-ciphers/security)) — see [Bundled-dependency update policy](#bundled-dependency-update-policy) below for why a fix there still requires a cryptolite release.

## Supported versions

| Version | Supported |
|---|---|
| 1.x (latest) | yes |
| < 1.0 | no — pre-release |

Only the latest published major version receives security fixes. This project is maintained by one person (see `docs/DECISIONS.md` D9); there is no commitment to backport fixes to older majors.

## Threat model and non-goals

**What the modern API (`encrypt`/`decrypt`/`decryptBytes`/`upgrade`) protects:**

- Confidentiality and integrity of data encrypted under a password, via AES-256-GCM.
- Tampering with any part of the token — ciphertext or header (iteration count, salt, IV) — is detected (the header is authenticated as GCM's AAD) and reported as a single, detail-free `ERR_DECRYPT`/`ERR_FORMAT`, so an attacker cannot use error responses to distinguish "wrong password" from "tampered token" from "corrupted data".
- Brute-force resistance scales with the PBKDF2 iteration count carried in the token (default 600,000, OWASP 2023 guidance for PBKDF2-HMAC-SHA256); see `docs/DECISIONS.md` D10.
- Options are read from the caller's own properties only, never through the prototype chain — an application with an unrelated prototype-pollution bug (e.g. `Object.prototype.iterations = ...`) cannot use it to silently weaken cryptolite's defaults.

**What it does not do (explicit non-goals for v1, see `docs/SPEC-modern.md`):**

- **It cannot make a weak password strong.** PBKDF2 slows down guessing; it does not add entropy. A short or guessable password is the dominant risk in any password-based scheme, cryptolite's included.
- **No key-based (non-password) encryption, no streaming, no caller-supplied AAD, no asymmetric cryptography.** The modern API is deliberately narrow: one password-based, authenticated, synchronous-feeling (promise-returning) construction. If you need any of these, use `@noble/ciphers` directly.
- **No protection against a compromised runtime, a malicious dependency elsewhere in your tree, or a password captured before it reaches cryptolite.** Cryptography does not help if the password or plaintext is readable before `encrypt()` is called or after `decrypt()` returns.
- **Decrypting an untrusted token costs real CPU before authentication fails.** A token's PBKDF2 iteration count is attacker-controlled data; the format's hard ceiling is 2,000,000 (roughly 0.4s of CPU on Web Crypto, or 7s in the pure-JS fallback, for a maximal token on a 2026-era server CPU — see `docs/SPEC-modern.md`, "Security-review changes", S2), with no password needed to trigger it. `decrypt`/`decryptBytes`/`upgrade` accept a `maxIterations` option (default: the format's ceiling) specifically for this: if you decrypt tokens from an untrusted source (a URL, a cookie, a request body), set it to what you actually issue — for example `{ maxIterations: 600000 }` — so a hostile token is rejected by a cheap format check instead of running expensive PBKDF2.
- **Timing side channels**: cryptolite makes no constant-time guarantees of its own. Authentication-tag checks happen inside Web Crypto or `@noble/ciphers`; for the side-channel properties of the primitives themselves, see the security sections of [noble-hashes](https://github.com/paulmillr/noble-hashes#security) and [noble-ciphers](https://github.com/paulmillr/noble-ciphers#security). cryptolite's own glue code has not been independently reviewed for timing behaviour.

**What's audited, and what isn't.** cryptolite implements no cryptographic primitives; all of them come from `@noble/hashes` and `@noble/ciphers`. Per their own security sections: noble-hashes was audited by [Cure53](https://cure53.de) at v1.0.0 (Jan 2022), scope "everything, besides `blake3`, `sha3-addons`, `sha1` and `argon2`"; noble-ciphers was audited by Cure53 at v1.0.0 (Sep 2024), scope "everything". cryptolite bundles v2.4.0 of both, which is later than the audited versions. SHA-1 and MD5 are exposed only for crypto-js compatibility (documented "not for security" in the JSDoc); internally MD5 is used only to read crypto-js's legacy ciphertext format. **Not independently audited:** cryptolite's own code — the ported crypto-js framework (`src/compat/**`), the `cl1` token format and its parsing (`src/modern/cl1.ts`), and all argument validation. That code is covered by the differential test suite (`test/compat/**`, comparing against real `crypto-js@4.2.0`) and the modern API's unit tests, not by an independent security audit.

## The legacy-ciphertext caveat

The modern API's `{ legacy: true }` / `upgrade()` path reads crypto-js's default passphrase-mode output (`CryptoJS.AES.encrypt(text, passphrase).toString()`: OpenSSL `EVP_BytesToKey` with MD5 and a single iteration, AES-256-CBC, PKCS#7 padding). This format is **not authenticated**:

- A wrong password is only caught by a PKCS#7 padding check, and roughly **1 in 256 wrong passwords pass it**, producing garbage plaintext instead of an error. (`decrypt()`/`upgrade()` additionally require the result to be valid UTF-8, which catches most — not all — of those cases; `decryptBytes()` cannot catch any of them, and its JSDoc says so.)
- The ciphertext **can be modified without detection**. There is no tag, no MAC, nothing that would make a bit-flip visible as anything other than possibly-different plaintext after decryption.

This is not a bug in cryptolite — it is an exact reproduction of crypto-js's own behavior, required for byte-identical compatibility, and it was already true of every crypto-js deployment before cryptolite existed. It is disabled by default (`ERR_LEGACY_NOT_ALLOWED` unless you pass `{ legacy: true }`) specifically so that enabling it is a visible, deliberate choice. If you are migrating data, prefer reading it with `{ legacy: true }` and immediately calling `upgrade()` to re-encrypt it as an authenticated `cl1` token — see [MIGRATION.md](MIGRATION.md#migrating-stored-data-to-the-modern-format).

The crypto-js **compat API** (`CryptoJS.AES.decrypt(...)`) reproduces this same unauthenticated behavior unconditionally, with no flag to enable — exactly as crypto-js itself does, since the whole point of the compat API is byte-identical behavior. This is expected, not a vulnerability to report against the compat API, unless cryptolite's output diverges from real crypto-js's.

## Bundled-dependency update policy

Per `docs/DECISIONS.md` D5: cryptolite bundles pinned versions of `@noble/hashes` and `@noble/ciphers` directly into `dist/` and lists them as `devDependencies`, not runtime `dependencies` — this is how cryptolite ships with zero runtime dependencies while still being pure JS (required for React Native, which has no `crypto.subtle`).

**The consequence for security response:** a vulnerability fixed upstream in `@noble/hashes` or `@noble/ciphers` is **not** picked up by your lockfile or `npm audit` automatically, because noble isn't a runtime dependency of your project — it's compiled into cryptolite's own `dist/` files. A new cryptolite release is required to pick up the fix, every time.

What this project does about it:
- Exact-pinned noble versions (not ranges), so every cryptolite release has a known, reproducible noble version baked in.
- Dependabot/Renovate-style monitoring of these `devDependencies` for advisories.
- A cryptolite patch release follows promptly after any `@noble/hashes` or `@noble/ciphers` security advisory that affects code cryptolite actually uses.

What you should do: don't rely on `npm audit`/`npm audit signatures` on your own project to surface a noble-level issue inside cryptolite — watch cryptolite's own releases (GitHub "Watch → Custom → Releases", or `npm outdated`) instead.

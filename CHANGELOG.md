# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Contents of the first release, `v1.0.0`. Not yet published — see `docs/DECISIONS.md` D9 for the tag-triggered release process.

### Added

- **Compat API**: a byte-identical mirror of `crypto-js@4.2.0` — the package root (`import CryptoJS from 'cryptolite'`) and all 50 of crypto-js's module subpaths (`cryptolite/sha256`, `cryptolite/aes`, `cryptolite/hmac-sha256`, …), proven against the real `crypto-js@4.2.0` devDependency by a differential test suite (`test/compat/**`, including a dedicated regression suite for inputs crypto-js itself produces: hashing a decrypted `WordArray`, `Hex.parse()` of odd-length strings, reused encryptors — see `docs/DECISIONS.md` D14 for the short, closed list of what's still intentionally different).
- **Modern API**: password-based authenticated encryption on the package root —
  - `encrypt`, `decrypt`, `decryptBytes`, `isLegacy`, `upgrade` — AES-256-GCM + PBKDF2-HMAC-SHA256, the `cl1` token format, and an opt-in path (`{ legacy: true }`, `upgrade()`) to read and migrate existing crypto-js passphrase-mode ciphertexts. `decrypt`/`decryptBytes`/`upgrade` accept `maxIterations` to cheaply reject a token whose iteration count is higher than what you issue, before spending any PBKDF2 work on it.
  - Synchronous hashing: `md5`, `sha1`, `sha256`, `sha384`, `sha512`, `sha3_256`, `sha3_512`, each with `'hex' | 'base64' | 'base64url' | 'bytes'` output encodings.
  - `hmac` (`'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512'`).
  - `randomBytes`.
  - `CryptoliteError`, a single error class with a stable `code` (`ERR_DECRYPT`, `ERR_FORMAT`, `ERR_LEGACY_NOT_ALLOWED`, `ERR_PARAMS`, `ERR_RANDOM`, `ERR_UTF8`).
- **Zero runtime dependencies.** `@noble/hashes` and `@noble/ciphers` (both independently audited at v1.0.0; v2.4.0 bundled) are bundled into `dist/`, not installed separately — see `docs/DECISIONS.md` D5.
- **ESM and CommonJS** builds, both hand-verified against the built package (not just type-checked) — see `dist/index.js` / `dist/index.cjs` and the generated per-subpath shims.
- **TypeScript types**, a mechanical port of `@types/crypto-js@4.2.2` plus one additive, backwards-compatible fix (`enc.Base64url.stringify`'s `urlSafe` parameter); see `docs/DECISIONS.md` D12. Types for the modern API ship alongside.
- **npm package aliasing support**: `npm install crypto-js@npm:cryptolite`, and `overrides`/`resolutions`/`pnpm-workspace.yaml` `overrides` all work to replace `crypto-js` with cryptolite with no source changes, including for transitive dependencies — see the README's 10-second migration and `test/package/alias-install.test.ts`.
- **CI** (`.github/workflows/ci.yml`): typecheck, build, the full test suite and `publint`/`arethetypeswrong` on every push and PR, on Node 20/22/24, including a `FUZZ=1` run of the differential suite's wider randomized sweep on the Node 22 leg.
- **Release workflow** (`.github/workflows/release.yml`): tag-triggered (`v*`) publish with `npm publish --provenance`, gated on the same CI checks; owner-only (see `docs/DECISIONS.md` D9).
- **MIGRATION.md, SECURITY.md and CHANGELOG.md ship in the published tarball** (`package.json` "files"), alongside the always-included `LICENSE` and `README.md`, so the relative links between them resolve on npm as well as on GitHub.

### Deliberately not included or intentionally different

- `DES`, `TripleDES`, `RC4`, `RC4Drop`, `Rabbit`, `RabbitLegacy`, `Blowfish` — present as stubs that throw a clear error (see `docs/DECISIONS.md` D6 and [MIGRATION.md#unsupported-ciphers](MIGRATION.md#unsupported-ciphers)).
- AES with a non-standard key size, or a non-`WordArray` key — throws instead of silently producing unusable or non-standard output crypto-js itself can't portably reproduce (see [MIGRATION.md#aes-key-sizes](MIGRATION.md#aes-key-sizes)).
- `SHA3(data, { outputLength })` outside a multiple of 32 from 0 to 768 — throws instead of crypto-js's infinite loop on some out-of-range values (see `docs/DECISIONS.md` D14).
- A digest `WordArray` is always an independent copy, never crypto-js's live, aliasable hasher state (see `docs/DECISIONS.md` D14).
- A codemod — the root/subpath mirror makes one unnecessary.
- A UMD/`<script>` global build.
- Key-based (non-password) encryption, streaming, caller-supplied AAD, asymmetric cryptography (modern API non-goals for v1; see `docs/SPEC-modern.md`).

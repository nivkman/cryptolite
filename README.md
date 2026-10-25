# cryptolite

A maintained, drop-in successor to [`crypto-js`](https://www.npmjs.com/package/crypto-js) — same API, byte-identical output, built on audited [`@noble`](https://github.com/paulmillr) cryptography.

[![npm version](https://img.shields.io/npm/v/cryptolite)](https://www.npmjs.com/package/cryptolite)
[![npm downloads](https://img.shields.io/npm/dw/cryptolite)](https://www.npmjs.com/package/cryptolite)
[![minzipped size](https://img.shields.io/bundlephobia/minzip/cryptolite)](https://bundlephobia.com/package/cryptolite)
[![CI](https://img.shields.io/github/actions/workflow/status/nivkman/cryptolite/ci.yml?branch=main)](https://github.com/nivkman/cryptolite/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/cryptolite)](LICENSE)

```sh
npm install cryptolite
```

crypto-js's maintainers [discontinued it](https://github.com/brix/crypto-js): *"Active development of CryptoJS has been discontinued. This library is no longer maintained."* It is still enormous — about 11.8M downloads a week and 12,414 direct dependents (deps.dev, checked 2026-10-24) — with no maintained drop-in replacement on npm. cryptolite is one.

## The 10-second migration

**Option 1 — new code.** Install, then change the import:

```sh
npm install cryptolite
```

```diff
- import CryptoJS from 'crypto-js';
+ import CryptoJS from 'cryptolite';
```

Subpath imports work the same way: `require('crypto-js/sha256')` → `require('cryptolite/sha256')`.

**Option 2 — zero code changes.** Install cryptolite *as* crypto-js:

```sh
npm install crypto-js@npm:cryptolite
```

Every `require('crypto-js')` / `import ... from 'crypto-js'` in your code now resolves to cryptolite. Nothing to edit.

**Option 3 — a dependency you don't control imports crypto-js.** Override it at the root of your project so every copy in the tree (including nested ones) resolves to cryptolite:

<table>
<tr><th>npm</th><td>

```json
{
  "overrides": {
    "crypto-js": "npm:cryptolite@^1"
  }
}
```

</td></tr>
<tr><th>Yarn<br><sub>(Classic and Berry)</sub></th><td>

```json
{
  "resolutions": {
    "crypto-js": "npm:cryptolite@^1"
  }
}
```

</td></tr>
<tr><th>pnpm ≥ 11</th><td>

```yaml
# pnpm-workspace.yaml
overrides:
  crypto-js: "npm:cryptolite@^1"
```

</td></tr>
<tr><th>pnpm &lt; 11</th><td>

```json
{
  "pnpm": {
    "overrides": {
      "crypto-js": "npm:cryptolite@^1"
    }
  }
}
```

</td></tr>
</table>

pnpm moved `overrides` out of `package.json` and into `pnpm-workspace.yaml` in v11; the `pnpm.overrides` field in `package.json` still works on pnpm &lt; 11 but is ignored from v11 on. Check `pnpm --version` if unsure.

Then reinstall. `test/package/alias-install.test.ts` in this repo installs cryptolite under the name `crypto-js` both ways (direct dependency and `overrides` on a transitive one) and runs unmodified crypto-js code against it — that test is the proof, not just the claim.

See [MIGRATION.md](MIGRATION.md) for the full walkthrough, including library authors and migrating stored ciphertexts.

## Why switch

- **crypto-js is discontinued; cryptolite is maintained.** Same API and output, actively kept up.
- **We implement no cryptography ourselves.** Every primitive comes from [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) and [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers). Their own security sections state: noble-hashes was audited by [Cure53](https://cure53.de) at v1.0.0 (Jan 2022), scope "everything, besides `blake3`, `sha3-addons`, `sha1` and `argon2`"; noble-ciphers was audited by Cure53 at v1.0.0 (Sep 2024), scope "everything". cryptolite bundles v2.4.0 of both — later than the audited versions (see each project's changes since its audit). SHA-1 and MD5 are shipped only for crypto-js compatibility, never for security. What is **not** independently audited: cryptolite's own code — the ported crypto-js framework (WordArray, modes, padding, formats), the `cl1` token format, and argument validation.
- **Byte-identical output, proven, not asserted.** A differential test suite (`test/compat/**`) runs cryptolite against the real `crypto-js@4.2.0` devDependency — fixed vectors, randomized sweeps, and an opt-in `FUZZ=1` mode — and cross-decrypts in both directions, so a regression there is a failing test, not a changed docs claim. This includes inputs crypto-js itself produces, not just clean ones: hashing a decrypted `WordArray`, `Hex.parse()` of an odd-length string, and reusing a `createEncryptor()` across multiple `finalize()` calls all match crypto-js exactly (`docs/DECISIONS.md` D14). The only differences left are the short, closed list under [What's not supported](#whats-not-supported). Run the suite yourself with `npm test`.
- **TypeScript types included**, a mechanical port of `@types/crypto-js@4.2.2` (DefinitelyTyped) plus one additive, backwards-compatible fix (`enc.Base64url.stringify`'s `urlSafe` flag, which crypto-js has at runtime but `@types` omits). Code written against `@types/crypto-js` type-checks against cryptolite unchanged.
- **ESM and CJS**, zero runtime dependencies (`@noble/*` are bundled into `dist/`, not installed separately).
- **An actual security upgrade alongside the compat layer**: a modern, authenticated encryption API (below) and an opt-in path to read and upgrade old crypto-js ciphertexts.

**Where this runs.** Pure JS, ES2020, no Node built-ins or DOM types assumed by design (`docs/DECISIONS.md` D4, D7, D11) — targeting Node ≥ 20, browsers, Deno, Bun, Cloudflare Workers and React Native (Hermes). Honestly: **CI only runs Node 20/22/24** (`.github/workflows/ci.yml`, ubuntu-latest). Browsers/Deno/Bun/Workers/React Native are expected to work from the design and are not yet exercised by an automated cross-platform test matrix. One platform limit, per Cloudflare's own public issue tracker (not independently tested by this project): **Cloudflare Workers' `subtle.deriveBits` rejects PBKDF2 iteration counts above 100,000** ([workerd#1346](https://github.com/cloudflare/workerd/issues/1346)), so `encrypt`/`decrypt` at the 600,000 default fall back to pure-JS PBKDF2 there (R6 in `docs/SPEC-modern.md`) — about 2 seconds of CPU per call (2.1 s measured for that path on Node; not measured on Workers). Pass `{ iterations: 100000 }` on Workers to stay on the native, capped path; see [React Native](#react-native) below for the same trade-off spelled out. (Tokens already issued with a higher count still decrypt there — just slowly, on the same fallback.)

## cryptolite vs. the alternatives

| | **cryptolite** | crypto-js | crypto-es | `@noble/*` directly |
|---|---|---|---|---|
| Maintenance | maintained | **discontinued** by its maintainers | maintained, same ported code | actively maintained |
| Cryptographic primitives | `@noble/hashes`, `@noble/ciphers` (independently audited at v1.0.0) | hand-rolled, unaudited | hand-rolled, unaudited (ported from crypto-js) | audited |
| Drop-in for crypto-js imports | yes — byte-identical, proven by a differential suite against crypto-js 4.2.0 | itself | similar API, ESM-first port; not independently proven byte-identical here | no — different API, you write the glue |
| Authenticated encryption | yes — `encrypt`/`decrypt`, AES-256-GCM + PBKDF2-HMAC-SHA256 | no — CBC passphrase mode only, unauthenticated | no | yes, but you design the token format, KDF and parameters yourself |
| Reads old crypto-js ciphertexts | yes, opt-in (`{ legacy: true }`, `upgrade()`) | n/a | n/a | no |
| TypeScript types | bundled, compatible with `@types/crypto-js` | via separate `@types/crypto-js` package | bundled | bundled, noble's own shapes (not crypto-js-shaped) |
| Module formats | ESM + CJS | CJS/UMD | ESM + CJS | ESM + CJS |
| Runtime dependencies | 0 | 0 | 0 | 0 |

## Modern API

Named exports, alongside the compat default export. Promises, not callbacks; a single error type.

### Encrypt / decrypt

```ts
import { encrypt, decrypt } from 'cryptolite';

const token = await encrypt('meet at noon', password);
// 'cl1.600000.Xb3k…' — see "The cl1 token format" below
const text = await decrypt(token, password); // 'meet at noon'
```

### Migrating stored crypto-js ciphertexts

```ts
import { isLegacy, decrypt, upgrade } from 'cryptolite';

if (isLegacy(stored)) {
  // Read it once, explicitly opting into the unauthenticated legacy format...
  const text = await decrypt(stored, password, { legacy: true });
  // ...then re-encrypt it as a cl1 token as soon as possible:
  stored = await upgrade(stored, password);
}
```

`upgrade()` accepts both a crypto-js ciphertext and an existing `cl1` token (handy for raising the iteration count later) and always re-encrypts with a fresh salt and IV.

### Hashing, with encodings

```ts
import { sha256 } from 'cryptolite';

sha256('hello'); // '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
sha256('hello', 'base64url'); // 'LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ'
sha256('hello', 'bytes'); // Uint8Array(32)
```

`md5`, `sha1`, `sha384`, `sha512`, `sha3_256` and `sha3_512` share this signature. (`sha3_256`/`sha3_512` are standard FIPS-202 SHA-3 — **not** the same as crypto-js's `CryptoJS.SHA3`, which implements the original Keccak submission with different padding. Use the compat API for Keccak-compatible output.)

### HMAC

```ts
import { hmac } from 'cryptolite';

hmac('sha256', key, message, 'base64url');
```

### Random bytes

```ts
import { randomBytes } from 'cryptolite';

const key = randomBytes(32);
```

### Error codes

Every error is a `CryptoliteError` with a stable `code`; branch on `code`, not the message text:

```ts
import { decrypt, CryptoliteError } from 'cryptolite';

try {
  await decrypt(token, password);
} catch (err) {
  if (err instanceof CryptoliteError && err.code === 'ERR_DECRYPT') {
    // wrong password, or the token was corrupted or tampered with
  } else {
    throw err;
  }
}
```

`ERR_DECRYPT` · `ERR_FORMAT` · `ERR_LEGACY_NOT_ALLOWED` · `ERR_PARAMS` · `ERR_RANDOM` · `ERR_UTF8`. Full reference in [MIGRATION.md](MIGRATION.md) and the JSDoc on `CryptoliteError`.

**Decrypting tokens from an untrusted source** (a URL, a cookie, a request body)? A token's iteration count is attacker-controlled data, and decrypting one costs real PBKDF2 work before authentication can fail — pass `maxIterations` to cap it at what you actually issue:

```ts
await decrypt(token, password, { maxIterations: 600000 }); // reject anything higher, cheaply
```

`decrypt`, `decryptBytes` and `upgrade` all accept it; see [SECURITY.md](SECURITY.md#threat-model-and-non-goals) for why it matters.

### The `cl1` token format

`encrypt()` returns `cl1.<iterations>.<salt>.<iv>.<ciphertext>`: a self-describing, URL-safe string. The iteration count travels with the token (so raising the default later never breaks old tokens), the header is authenticated along with the ciphertext (AES-256-GCM AAD), and the key is PBKDF2-HMAC-SHA256 over the UTF-8 password. Full format in `docs/SPEC-modern.md`.

**Why not crypto-js's own passphrase mode?** `CryptoJS.AES.encrypt(text, passphrase)` derives its key with OpenSSL's `EVP_BytesToKey` — MD5, a single iteration, no salt-stretching to speak of — and encrypts with unauthenticated AES-CBC: a wrong password is caught only by a PKCS#7 padding check that roughly 1 in 256 wrong passwords slip past, and the ciphertext can be altered without detection. That was a reasonable default when crypto-js shipped it; it isn't one today. `encrypt`/`decrypt` use PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP 2023 guidance) and authenticate the whole token. The compat API still reproduces the old behavior exactly, on purpose — that's what byte-identical output requires — and the modern API's `{ legacy: true }` path exists precisely to read your way out of it.

## React Native

- Install [`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values) and `import 'react-native-get-random-values'` once, at the top of your entry file, before anything uses cryptolite. React Native has no built-in `crypto.getRandomValues`; without the polyfill, `randomBytes` (and anything that needs randomness) throws `ERR_RANDOM`.
- Hermes has no `crypto.subtle`, so `encrypt`/`decrypt`/`upgrade` run PBKDF2 in pure JS there, and that is **very slow**: on Hermes 0.12 (measured on a server CPU; Hermes V1 and real phones not measured) one `encrypt` or `decrypt` took **about 74 s** at the 600,000 default and **about 12 s** at the 100,000 minimum. In practice the modern password API on React Native needs a native Web Crypto implementation of `crypto.subtle` (PBKDF2 + AES-GCM). cryptolite does **not** silently lower the iteration count per platform (`docs/DECISIONS.md` D10, D15) — a token's strength shouldn't depend on which device made it.
- The **compat API is unaffected**: `CryptoJS.AES.encrypt(text, passphrase)` uses one MD5 round for its key, so it is as fast on React Native as it was with crypto-js (cryptolite's PBKDF2 there is about 1.15× crypto-js's, measured on Hermes).

## What's not supported

- **DES, TripleDES, RC4, RC4Drop, Rabbit, RabbitLegacy, Blowfish.** These throw a clear error pointing at [MIGRATION.md#unsupported-ciphers](MIGRATION.md#unsupported-ciphers) instead of silently working. They're broken or legacy constructions that `@noble` doesn't implement, and shipping our own copies would mean cryptolite implementing cryptography itself — the one thing it's designed not to do. Keep `crypto-js` installed for data that still needs them.
- **AES with a non-standard key size, or a non-`WordArray` key.** crypto-js silently accepts e.g. a 10-byte key (or even a plain string or number passed as a direct key, not a passphrase) and produces unusable or non-standard ciphertext. cryptolite throws instead — see [MIGRATION.md#aes-key-sizes](MIGRATION.md#aes-key-sizes).
- **A UMD/`<script>` global build.** Not shipped in v1; use a bundler or an ESM/CJS import.
- **`cryptolite/<name>.js` (the `.js`-suffixed subpath) under resolvers that ignore `package.json` "exports"** — old TypeScript `node10`/`classic` resolution, webpack 4, Metro without package exports, older Jest. The non-suffixed form (`cryptolite/sha256`) works everywhere via generated stub directories; the `.js` form only resolves where `exports` itself is honored (Node, modern bundlers, `node16`/`nodenext`/`bundler` TS resolution).
- **No codemod.** The root/subpath mirror makes one unnecessary — see Option 1 above.
- **A short, closed list of deliberate output differences from crypto-js** (see `docs/DECISIONS.md` D14 for the full rationale — everything not on this list is byte-identical, proven by the differential suite, including inputs crypto-js itself produces, like hashing a decrypted `WordArray` or `Hex.parse()` of an odd-length string):
  - AES keys: see the point above.
  - `SHA3(data, { outputLength })` requires a multiple of 32 from 0 to 768; crypto-js loops forever for some other values instead of erroring.
  - A digest `WordArray` crypto-js returns is its hasher's *live* internal state — mutating it can change what a later `finalize()` on the same hasher returns. cryptolite always returns an independent copy. (Safer; no real program should be relying on the aliasing.)
  - The unsupported ciphers above.
  - A few subpath/module-resolution differences, documented in `scripts/subpaths.mjs`: `require('crypto-js/cipher-core')` and `require('crypto-js/hmac')` evaluate to `undefined` in real crypto-js (their internal factories return nothing); cryptolite returns the whole `CryptoJS` object, so a side-effect-only `require` still works and a value import becomes useful. `require('crypto-js/pad-ansix923')` returns `undefined` in crypto-js (a typo in its own source); cryptolite returns the correct `pad.AnsiX923`. `require('crypto-js/crypto-js')` is a second, separate copy of the whole library in real crypto-js; in cryptolite it's the same single object as the package root.

## Benchmarks and size

Same calls on both libraries, identical output, measured on an AMD EPYC 7713 VM with Node 20.19.2 (each library in its own process, median of 5 runs). Full method, margins and raw data: [bench/RESULTS.md](bench/RESULTS.md).

| Compat API (vs crypto-js 4.2.0) | crypto-js | cryptolite | |
|---|--:|--:|--:|
| PBKDF2 at crypto-js 4.2's defaults (SHA-256, 250k iterations) | 3.38 s | 0.77 s | **4.4× faster** |
| PBKDF2, 10k iterations | 134 ms | 30.3 ms | 4.5× |
| SHA-512, 1 MiB | 176 ms | 32.0 ms | 5.5× |
| SHA3 (Keccak), 1 MiB | 763 ms | 170 ms | 4.4× |
| SHA-256, 1 MiB | 25.7 ms | 18.5 ms | 1.4× |
| SHA-256 progressive (`update()` × 16 × 64 KiB) | 21.8 ms | 19.0 ms | 1.15× |
| HmacSHA256, short | 43.0 µs | 17.3 µs | 2.5× |
| AES passphrase encrypt, short | 234 µs | 185 µs | 1.2× |
| AES-256-CBC encrypt, 1 MiB | 43.8 ms | 34.3 ms | 1.3× |
| Utf8 parse / stringify, 1 MiB | 47.6 / 84.5 ms | 5.3 / 6.8 ms | 9× / 12× |
| Base64 stringify / parse, 1 MiB | 96.0 / 19.4 ms | 80.8 / 19.8 ms | 1.2× / ~1× |

Short-input timings (≈40 bytes) vary by ±20% between processes; treat those ratios as ranges. The modern `encrypt`/`decrypt` take about 126 ms each at the default 600,000 iterations with Web Crypto (Node) — that cost is the point of the KDF.

**Size** (esbuild, minified): the whole library is 79 KB min / 27.8 KiB gzip, vs crypto-js's 71 KB / 25.5 KiB. Every import currently costs the whole library — including `cryptolite/sha256` and modern-only imports — because the compat layer isn't tree-shakeable yet; a slimmer modern-only entry is on the roadmap.

A size breakdown (including the bundled `@noble/*` code) is available once published at [bundlephobia](https://bundlephobia.com/package/cryptolite) and [pkg-size.dev](https://pkg-size.dev/cryptolite).

## Docs

- [MIGRATION.md](MIGRATION.md) — step-by-step migration, for apps and library authors
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities, threat model, supported versions
- [CONTRIBUTING.md](CONTRIBUTING.md) — setup, scripts, the differential-testing rule
- [CHANGELOG.md](CHANGELOG.md)
- [docs/DECISIONS.md](docs/DECISIONS.md) — why things are built the way they are
- [docs/SPEC-modern.md](docs/SPEC-modern.md) — the modern API's full specification

## License

MIT — [LICENSE](LICENSE) (includes third-party notices for the ported/bundled code).

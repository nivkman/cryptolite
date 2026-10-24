# cryptolite — decisions

Each entry: the decision, then why. Newest last. Owner of the repo: nivkman (Niv Kaufman).

## D1. What we are building (2026-10-24)
A maintained successor to `crypto-js`, which its maintainers deprecated
("Active development of CryptoJS has been discontinued. This library is no longer maintained.").
crypto-js still has ~11.8M weekly downloads, 12,414 direct dependents (deps.dev), and
@types/crypto-js has ~2.8M weekly downloads. No drop-in successor exists on npm (searched
"crypto-js replacement / drop-in / compatible"; `crypto-es` is a port of the same code at ~95K/wk).
**Why:** the research in this session showed replacement packages for deprecated, heavily
depended-on libraries are the most reliable route to npm adoption (tinyglobby, picocolors).

## D2. Name: `cryptolite`, unscoped, owned by nivkman
Chosen by the user. Free on npm when checked 2026-10-24.

## D3. Two APIs in one package
1. **Compat API** — the package root and subpaths mirror crypto-js 4.2.0 exactly
   (`import CryptoJS from 'cryptolite'`, `require('cryptolite/sha256')`, ...), producing
   byte-identical output. This enables a zero-code-change swap, including for transitive
   dependencies: `"overrides": { "crypto-js": "npm:cryptolite@^1" }`.
2. **Modern API** — named exports at the root (`encrypt`, `decrypt`, `upgrade`, `sha256`, ...):
   authenticated encryption (AES-256-GCM + PBKDF2-HMAC-SHA256) with an explicit, opt-in path
   to read legacy crypto-js ciphertexts.
**Why:** the compat layer gets people to switch (zero cost); the modern API is the actual
security improvement (crypto-js passphrase mode = MD5 EVP_BytesToKey + unauthenticated CBC).

## D4. No home-made cryptography
All primitives come from `@noble/hashes` and `@noble/ciphers` (audited, zero-dependency,
synchronous, pure JS). We port crypto-js's *framework* code (WordArray, modes, paddings,
formats, KDF plumbing — MIT) and delegate algorithm cores to noble.
**Why:** a solo-maintained crypto library is only credible if it implements no primitives.
Pure JS (not Web Crypto only) is required because React Native has no `crypto.subtle`, and
crypto-js's sync API cannot be built on async Web Crypto.

## D5. Bundle noble into dist; zero runtime dependencies
noble v2 is ESM-only (`"type": "module"`, Node >= 20.19). crypto-js users are heavily CommonJS
(Jest, older bundlers, React Native). We bundle pinned noble versions into both ESM and CJS
builds, list them as devDependencies, and credit them in LICENSE/README.
**Trade-off:** a noble security fix requires a cryptolite release. Mitigation: pin exact versions,
Renovate/Dependabot on devDependencies, and a documented release-on-noble-advisory policy.

## D6. Not in v1 (deliberately)
- DES, TripleDES, RC4, RC4Drop, Rabbit, RabbitLegacy, Blowfish: present as stubs that throw a
  clear error pointing to MIGRATION.md. Reason: broken/legacy ciphers that noble does not
  implement; shipping our own copies would contradict D4. Revisit on demand.
- AES with non-standard key sizes (crypto-js silently accepts e.g. a 10-byte key and produces
  non-standard output). cryptolite throws a clear error instead.
- A codemod. The root/subpath mirror (D3) makes a codemod unnecessary.

## D7. Runtime targets
Node >= 20, modern browsers, Deno, Bun, Cloudflare Workers, React Native (Hermes).
Randomness via `globalThis.crypto.getRandomValues`; on React Native that requires
`react-native-get-random-values` (same requirement as crypto-js 4.x).

## D8. License: MIT
More recognised than ISC for widely adopted libraries; compatible with the MIT code we port
(crypto-js) and bundle (noble), whose notices we keep.

## D9. Releases: tag-triggered publish with npm provenance, tests gate everything
Unlike the auto-patch-on-every-push pipeline used in the owner's other packages, a crypto
library needs a test gate and signed provenance. CI runs tests on every push/PR; publishing
happens only from a `v*` tag via `npm publish --provenance`. Nothing is published without the
owner's explicit go-ahead.

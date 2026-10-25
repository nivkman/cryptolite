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

## D10. Keep the 600,000-iteration default everywhere, including React Native
Measured: PBKDF2-HMAC-SHA256 at 600k iterations takes 128 ms via Web Crypto and 1,644 ms via
pure-JS noble on Node 20 (V8 JIT). React Native has no `crypto.subtle`, so it takes the pure-JS
path; on Hermes (no JIT) it will be slower — **not measured yet**.
**Decision:** we do not silently lower the security parameter per platform. The default stays at
600k (OWASP 2023). Docs tell React Native users their options: a native Web Crypto provider, or
an explicit `{ iterations: 100000 }` (the lowest `encrypt` accepts) as a conscious trade-off.
**Why:** a token's strength must not depend on which device created it, and the iteration count
is stored in the token, so a later change of default never breaks old tokens.

## D11. Compat UTF-8 uses TextEncoder/TextDecoder only when they behave correctly
`src/compat/core.ts` feature-detects both on `globalThis` at load time (TextDecoder must keep a BOM
and reject an encoded surrogate in `fatal` mode) and otherwise uses crypto-js's own
`unescape(encodeURIComponent())` / `decodeURIComponent(escape())`, which are plain ES and exist on
Hermes. **Why:** exact crypto-js behaviour on every platform, with the fast native path where safe.

## D12. Public types = @types/crypto-js 4.2.2, plus one additive fix
`src/compat/types.ts` is a mechanical port of @types/crypto-js so existing TypeScript code compiles
unchanged. One deliberate addition: `enc.Base64url` takes the optional `urlSafe` flag that
crypto-js 4.2 has at runtime but @types omits. It stays assignable to and from @types' `Encoder`
both ways. The unsupported cipher stubs (D6) are runtime-only and intentionally not typed.

## D13. Subpath stub directories are generated, not committed
The build writes 50 `<name>/package.json` stubs at the package root for resolvers that ignore
`exports`. They ship via `files` and are gitignored. Known gap: `cryptolite/<name>.js` (with the
suffix) does not resolve under those old resolvers; everything that honours `exports` is fine.
No UMD/`<script>` global build in v1.

## D14. Compat hashers reproduce crypto-js exactly, including its non-standard digests (2026-10-25)
The code review (docs/reviews/code-review.md, H1/H2) showed crypto-js hashes bytes *beyond*
`sigBytes` in a WordArray's last word into its padding (e.g. hashing `AES.decrypt` output
directly), and hashes fractional `sigBytes` (e.g. `Hex.parse('abc')`) as bit-length messages.
**Decision:** reproduce it. Hasher objects now run crypto-js's own buffering and verbatim
`_doFinalize` padding, delegating only the compression function to noble (`process()`/`get()`
on noble's MD classes, `keccakP` for Keccak). One-shot helpers keep a pure-noble fast path for
"clean" input (strings; WordArrays with whole bytes and nothing beyond them), which is where
the standard and crypto-js agree.
**Why:** a drop-in replacement — especially via `overrides` into dependencies — must not
silently change stored digests or keys. This still implements no primitive (D4): padding and
buffering are framework code; compression is noble's. The noble internals used are pinned and
bundled (D5) and covered by the differential suite.
**Remaining deliberate differences** (all are cases where crypto-js produces unusable output,
hangs, or which cannot matter): non-WordArray AES keys and AES keys that aren't 16/24/32 bytes
throw; SHA3 `outputLength` must be a multiple of 32 in 0..768 (crypto-js loops forever on some
values); a digest WordArray returned by crypto-js is its live internal state (mutating it changed
later `finalize()` results) — ours are independent copies; the unsupported ciphers (D6).

## D15. React Native: the modern password API needs native Web Crypto; defaults unchanged (2026-10-25)
Measured (bench/RESULTS.md §3): on Hermes 0.12, pure-JS PBKDF2-SHA256 takes ~74 s at 600k and
~12 s at 100k per `encrypt`/`decrypt` (≈40× slower than V8 on the same CPU). Hermes V1 and real
devices are not measured.
**Decision:** keep D10 (no per-platform lowering, `encrypt` minimum stays 100k). Document plainly
that the modern password API on React Native requires a native `crypto.subtle` provider, and
that the compat API (MD5-based crypto-js passphrase mode) is unaffected.
**Why:** lowering the minimum to make pure JS tolerable on phones (~10k) would make tokens
brute-forceable; a slow-but-correct API with an honest note is better than a fast weak one.
**Revisit** when Hermes V1 numbers or a vetted native provider recommendation are available.

## D16. No separate `cryptolite/modern` entry in v1 (2026-10-25)
Tried: a separate modern bundle shared by the root. Measured with esbuild: modern-only imports
dropped from 77.8 KB to 47 KB min, but the whole library grew from 77.8 KB to 109 KB because
each bundle carried its own copy of @noble. **Decision:** reverted for v1; the whole library
stays ~79 KB min / 27.8 KiB gzip (crypto-js: 71 KB / 25.5 KiB). Follow-up: a shared internal
chunk for @noble (or code splitting) so a modern entry costs nothing for compat users.

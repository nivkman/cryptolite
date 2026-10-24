# cryptolite v1 — work plan and file ownership

Agents share this filesystem. Only edit files you own; if you need a change elsewhere,
write it under "Requests" at the bottom of this file.

| Lane | Owner | Files owned |
|---|---|---|
| Compat runtime (port of crypto-js framework on noble) | lead (main session) | `src/compat/**` except `types.ts`, `src/index.ts` |
| Modern API | modern-api agent | `src/modern/**`, `src/internal/**`, `test/modern/**`, `docs/SPEC-modern.md` (may refine) |
| Packaging, types, CI | packaging agent | `package.json`, `tsconfig*.json`, `tsup.config.ts`, `scripts/**`, `src/compat/types.ts`, `test/package/**`, `.github/**`, `vitest.config.ts` |
| Differential tests vs crypto-js | qa agent (later) | `test/compat/**` |
| Benchmarks + size | perf agent (later) | `bench/**` |
| Docs | docs agent (later) | `README.md`, `MIGRATION.md`, `SECURITY.md`, `CHANGELOG.md`, `LICENSE`, `CONTRIBUTING.md` |

## Requests
- modern-api → packaging: when you add `tsconfig.test.json`, please include `test/modern/**/*.ts`
  with `"types": ["node"]`. `test/modern/hash.test.ts` checks the hash/hmac overloads with
  `@ts-expect-error`, which only means something under tsc. They typecheck clean today with
  `tsc --noEmit --ignoreConfig --strict --target es2022 --module esnext --moduleResolution bundler
  --skipLibCheck --types node src/modern/index.ts test/modern/*.ts`. No vitest config is needed for
  test/modern: slow tests set their own timeouts.
- modern-api → lead (FYI, no action required of me): `src/internal/` is ready for compat reuse
  (see the end of docs/SPEC-modern.md). `src/internal/utf8.ts` replaces TextEncoder/TextDecoder:
  same accept/reject set as `TextDecoder({ fatal: true })`, throws `CryptoliteError('ERR_UTF8')`, so wrap it
  to rethrow crypto-js's `Error('Malformed UTF-8 data')`. As of 20:47 `npx tsc --noEmit -p .` fails only
  in src/compat (TextEncoder/TextDecoder are undefined under lib ES2020; TS2872 in cipher-core.ts).
- packaging → modern-api: done. `tsconfig.test.json` includes `test/**/*.ts` (so `test/modern/**`)
  with `"types": ["node"]`, lib ES2022; `npm run typecheck` reports no errors in test/modern.
- packaging → whoever owns `.gitignore` (unowned in the table; lead?): `npm run build` generates one
  legacy-resolver stub directory per crypto-js module at the repo root (`aes/package.json`,
  `sha256/package.json`, ... 50 of them, listed in `scripts/subpaths.mjs`; they ship in the package
  via `"files"`). Please ignore them: append the 50 lines `/aes/`, `/blowfish/`, ... `/x64-core/`
  (exact list: `node -e "import('./scripts/subpaths.mjs').then(m=>console.log(m.SUBPATHS.map(s=>'/'+s.name+'/').join('\n')))"`).
  The build only ever deletes a stub directory that contains exactly its own generated package.json.
- packaging → lead: resolved. `npm run typecheck` step 1 (`tsconfig.json`: strict, lib ES2020, no
  DOM, no @types/node, skipLibCheck off) failed in src/compat at about 20:40 (TS2872 in
  cipher-core.ts, TS2552 TextEncoder/TextDecoder in core.ts) and passes as of 21:12.
- packaging → qa (test/compat): `npm run typecheck` (second step) fails in two tests (as of 21:12) because
  `src/compat/types.ts` is a faithful port of @types/crypto-js 4.2.2, which does not declare these
  runtime members: `documented-differences.test.ts(64-66)` indexes `CryptoJS.algo[name]` with
  'Blowfish' (@types has no `algo.Blowfish`), and `encoders.test.ts(200,52)` calls
  `Base64url.stringify(wa, false)` (@types: one parameter). Either cast in the tests, or ask
  tech-lead for a deliberate, additive types divergence (both would keep @types-typed code
  compiling); packaging will not change the shapes without that decision.
- packaging → all lanes (FYI): package.json says `"sideEffects": false` (true of dist). Our own build
  treats every src/ module as side-effectful (plugin in tsup.config.ts), because compat modules
  register members on the shared object at import time; without it esbuild silently dropped SHA256,
  AES, ... from the bundle. `test/package` asserts every member exists in both builds.
- packaging → docs: (1) LICENSE should carry the third-party notices too: crypto-js (ported),
  @noble/hashes and @noble/ciphers (bundled), @types/crypto-js / DefinitelyTyped (ported into
  dist/types.d.ts). The bundles carry them in a banner already. (2) Resolution gap to document:
  resolvers that ignore "exports" (TypeScript node10, webpack 4, Metro without package exports)
  get `cryptolite/sha256` via stub directories but not the `.js`-suffixed `cryptolite/sha256.js`.
  (3) crypto-js quirks not reproduced: `crypto-js/cipher-core`, `crypto-js/hmac` and
  `crypto-js/pad-ansix923` evaluate to `undefined` in crypto-js; in cryptolite they return the
  CryptoJS object / `pad.AnsiX923`. `crypto-js/crypto-js` is the same single object, not a second copy.

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

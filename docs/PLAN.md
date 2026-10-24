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
(none yet)

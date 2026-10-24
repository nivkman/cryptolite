# Type corpus

Typical crypto-js code, written against `cryptolite`. `test/package/types.test.ts` compiles it

- against the packed cryptolite under several TypeScript versions and module settings, and
- with every `'cryptolite'` specifier rewritten to `'crypto-js'`, against crypto-js 4.2.0 +
  @types/crypto-js 4.2.2, which proves the `compat-*` files are genuine crypto-js-typed code.

`compat-*` files must stay valid crypto-js code (no cryptolite-only API). `modern*` and
`mid-migration.ts` are cryptolite-only. Not compiled by `npm run typecheck`; files here only need
to be valid in the configurations listed in types.test.ts.

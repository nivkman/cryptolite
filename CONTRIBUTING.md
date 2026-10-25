# Contributing to cryptolite

## Setup

```sh
git clone https://github.com/nivkman/cryptolite.git
cd cryptolite
npm ci
```

Node >= 20 (see `package.json` `engines`). No other setup — zero runtime dependencies means there's nothing else to configure.

## Scripts

From `package.json`:

| Script | What it does |
|---|---|
| `npm run build` | Runs `scripts/build.mjs`: bundles `dist/index.{js,cjs}` with tsup, generates declaration files, generates the per-subpath shims and legacy stub directories from `scripts/subpaths.mjs`, and rewrites `package.json`'s `exports`/`files` if they've drifted. Re-runnable; only touches `dist/`, the generated stub directories, and those two `package.json` fields. |
| `npm run typecheck` | `tsc -p tsconfig.json` (library source, strict, no DOM/`@types/node` — the runtime targets Hermes/browsers/Workers too) then `tsc -p tsconfig.test.json` (tests, with Node types). |
| `npm test` | `npm run build && vitest run` — the full suite, both projects (`unit` and `package`; see below). This is what CI runs. |
| `npm run test:unit` | Just the `unit` project (`test/compat/**`, `test/modern/**`) against `src/` directly — no build needed. Fast; use this while iterating. |
| `npm run test:package` | Builds, then just the `package` project (`test/package/**`): runs against the **built** package, the packed tarball, and temporary installs (slow — it spawns `npm`, `node`, `tsc`). |
| `npm run lint:pkg` | `publint --strict` then `scripts/attw.mjs` (`@arethetypeswrong/cli` against the packed tarball, in two resolution profiles). Catches `package.json`/`exports` mistakes that typecheck and tests don't. |
| `npm run prepack` | Runs automatically on `npm pack`/`npm publish`. Refuses to pack a missing, partial or stale build (`scripts/verify-dist.mjs`) — it does not rebuild for you. |

Before sending a change, at minimum: `npm run typecheck && npm test && npm run lint:pkg`.

## The differential-testing rule

**Every change to the compat layer (`src/compat/**`) must be proven against real `crypto-js`, not just reasoned about.**

crypto-js is a `devDependency` (pinned at `4.2.0`, matching the version cryptolite mirrors) specifically so `test/compat/**` can run both libraries side by side: same input, same settings, compare the output byte-for-byte, in both directions (cryptolite reading crypto-js's output and vice versa). See `test/compat/_util.ts` for the shared helpers (seeded randomness, reference-vs-cryptolite comparison) and the existing suites (`aes-key-modes.test.ts`, `aes-passphrase.test.ts`, `encoders.test.ts`, `hashers.test.ts`, `hmac.test.ts`, `kdf.test.ts`, `word-array.test.ts`, `documented-differences.test.ts`, `review-regressions.test.ts`) for the pattern to follow. `review-regressions.test.ts` in particular is worth reading before touching the hashing or AES framework code: it's built from real crypto-js *outputs* (a decrypted `WordArray`, `Hex.parse()` of an odd-length string, a reused encryptor, …), not just clean inputs — see `docs/DECISIONS.md` D14 for why that distinction mattered.

If you touch compat code and don't add or extend a differential test that would have caught the change, the PR isn't done — "it looks right" and "it type-checks" are not evidence of byte-identical output; a comparison against the real library is.

A **deliberate** difference from crypto-js (one that's intentional, not a bug) still needs a test — in `test/compat/documented-differences.test.ts` — and a line in `scripts/subpaths.mjs`'s comment block or `docs/DECISIONS.md`, so the next person can tell "intentional" apart from "regression."

### `FUZZ=1`

```sh
FUZZ=1 npx vitest run test/compat/fuzz.test.ts
```

Runs a much wider, randomized sweep (AES key-mode matrix, `WordArray` stress, PBKDF2/EvpKDF parameter sweeps, HMAC over many key lengths) that's skipped by default because it's slow. It's deterministic: seeded by `SEED` (picked fresh via `node:crypto` under `FUZZ=1` unless you set `SEED` yourself), and the run logs the seed it used so a failure is reproducible:

```sh
SEED=<value> FUZZ=1 npx vitest run test/compat/fuzz.test.ts
```

Run it locally before a compat-layer change that touches anything parameterized (key sizes, lengths, iteration counts) — CI does not run it on every push (it would make every CI run as slow as the slowest fuzz sweep).

## Modern API and other lanes

`src/modern/**` and `src/internal/**` (the modern, authenticated-encryption API and its shared helpers) have their own unit tests in `test/modern/**`, run as part of `npm run test:unit`; they don't need a crypto-js comparison since there's no crypto-js equivalent to compare against. `docs/SPEC-modern.md` is the spec for that API — if your change affects its public behavior, update the spec in the same PR.

`docs/PLAN.md` records file ownership during the original build-out and a "Requests" log between lanes; it's historical context, not a live task board, but it's useful for understanding why a given file looks the way it does.

## Release process

Releases are **tag-triggered, by design owner-only** (`docs/DECISIONS.md` D9) — there is no "publish from CI on merge" path, and contributors cannot publish directly: the `NPM_TOKEN` repository secret and the `npm` GitHub Environment the publish job uses are both owner-controlled. As a contributor, you cannot make a release happen. (As of this writing, pushing a `v*` tag is not yet separately restricted by a repository ruleset, so this is enforced today by the credential, not by who can push a tag — a known hardening gap, not something a contributor should rely on or work around.)

For the owner, to ship a release:

1. Bump `"version"` in `package.json`.
2. `git tag v<version> && git push origin v<version>` — for example `git tag v1.0.1 && git push origin v1.0.1`.
3. `.github/workflows/release.yml` runs the same checks as every push (typecheck, build, test, `lint:pkg`), confirms the tag matches `package.json`'s version, then `npm publish --provenance --access public`.

Nothing is published without a `v*` tag; nothing is published without the checks passing first.

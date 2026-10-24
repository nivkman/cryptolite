# cryptolite v1.0.0 — pre-release security review

Reviewer: security-engineer. Date: 2026-10-24. Tree reviewed: commit `655a505` (working tree clean
apart from this file). Scope: `src/modern/**`, `src/internal/**`, `src/compat/**`, `.github/**`,
`scripts/**`, `package.json`, the build output and the docs. Review only: no source, test or config
was changed.

Every finding says whether it was **verified by running** a probe (scripts under the session
scratchpad `security/probe1..4-*.mjs`, run against the bundled `src/` internals and the freshly
built `dist/`) or found **by reading**. Numbers are from this machine (Node 20.19.2, V8 JIT).

## Summary

No Critical or High findings. The modern API's design is sound: PBKDF2-HMAC-SHA256 with a 16-byte
random salt, AES-256-GCM with a 12-byte random IV and the header as AAD, a fresh key per token (so
IV uniqueness rests on the 128-bit salt, not on a counter), strict canonical parsing before any key
derivation, one generic decryption error, no `Math.random` anywhere, noble pinned and bundled, dist
with zero runtime imports. The compat layer introduces no new weakness relative to crypto-js 4.2.0
in the cases probed, and is strictly safer in two (no caller mutation of HMAC keys, no non-standard
AES key sizes).

What should change before 1.0.0 (details below):

| # | Sev | Finding | Fix size |
|---|-----|---------|----------|
| M1 | Medium | Prototype pollution of `Object.prototype.iterations` / `.legacy` silently changes option defaults (600k → 100k; legacy decryption on) | 3 lines |
| M2 | Medium | Hostile-token work bound is loose: a 10,000,000-iteration token costs ~2 s native / ~36 s pure JS per attempt, with no caller control; amplified on PBKDF2-capped runtimes by the R6 fallback | small option |
| M3 | Medium | Release pipeline publishes with a long-lived `NPM_TOKEN`; any `v*` tag by any collaborator publishes; prereleases would land on `latest` | workflow/settings |
| L1 | Low | Web Crypto → noble fallback also fires on `OperationError` (= genuine auth failure): every wrong password or tampered token runs a second, pure-JS GCM pass over the whole ciphertext and masks real platform errors | 2 lines |
| L2 | Low | A throwing `getRandomValues` escapes as a foreign `TypeError`/`DOMException`, breaking the "only `CryptoliteError`" contract | 3 lines |
| L3 | Low | `upgrade()`/legacy docs should state the tamper-laundering property and that the UTF-8 check is probabilistic (and absent from `decryptBytes`) | docs |
| L4 | Low | Dependabot has no cooldown for the bundled `@noble/*` group | 2 lines |
| L5 | Low | Tarball has no LICENSE or SECURITY.md (D5's advisory policy is undocumented) | docs lane |

---

## 1. Modern API (`src/modern`, `src/internal`)

### Verified properties (by running, unless noted)

- **KDF and bounds.** `encrypt` accepts `iterations` in [100000, 10000000], default 600000;
  `decrypt` accepts tokens in [10000, 10000000] and rejects out-of-range counts with `ERR_FORMAT`
  before any derivation (`src/modern/cl1.ts:88-95`). Key is 32 bytes = one SHA-256 block, so PBKDF2
  costs one HMAC chain, not two.
- **Salt/IV.** `randomBytes(16)` and `randomBytes(12)` per call (`src/modern/encryption.ts:77-79`),
  evaluated before key derivation, so a missing RNG fails with `ERR_RANDOM` before any work (probe 4g).
  GCM IV uniqueness: the key itself is fresh per token (random 128-bit salt), so IV reuse under one
  key requires a salt collision. No counter or nonce-misuse-resistant mode is needed.
- **GCM/AAD.** Tag is 128-bit, appended; AAD is the exact header text (`cl1.ts:140,157`). Tampering
  with the iteration digits, salt, IV or ciphertext each gives `ERR_DECRYPT` (probe 1e). Because
  salt/iterations feed the key and the IV feeds GCM, the AAD is belt-and-braces; it costs nothing.
- **Strict parsing.** All 16 malformed variants probed (trailing dot, leading zero, `+`, Arabic-Indic
  digit, `1e7`, padding, wrong-alphabet, whitespace, NUL, six parts, uppercase prefix, short
  ciphertext, 9999 and 10000001 iterations, non-zero unused bits in the last base64url char) are
  `ERR_FORMAT` (probe 1d). `split('.', 6)` bounds allocation on dot-flood input. The `base64.ts`
  decoder rejects non-canonical trailing bits, which is the rule most hand-written decoders miss.
- **Error oracle.** cl1 wrong-password and tamper both end in GCM tag failure → one message
  (`cl1.ts:110-115`). Legacy padding failure and legacy invalid-UTF-8 both map to the same
  `ERR_DECRYPT` text (probe 3d). Timing on a 64 KiB legacy ciphertext, medians of 200 runs:
  padding-fail 2641 µs, valid-padding-but-invalid-UTF-8 2571 µs, success 3415 µs. The two failure
  paths are indistinguishable within noise (the UTF-8 decoder throws at the first bad byte, which in
  a CBC tamper is in the scrambled block); only success differs, which is not an oracle. Local
  measurement only; a remote attacker is further from this than the noise floor here.
- **Web Crypto vs noble.** `test/modern/engines.test.ts` already compares both engines against a
  `node:crypto` reference on fixed inputs. Probe 2 confirmed per-call engine selection, fallback
  on a simulated PBKDF2 cap, and that Node's auth failure is a `DOMException` named `OperationError`.
- **256 MiB bound.** Applied after UTF-8 encoding for `encrypt` and to the decrypted bytes for
  `upgrade` (`encryption.ts:68-75,167,321`) — by reading. 256 MiB × 4/3 + header stays under V8's
  ~512 MiB string ceiling.
- **Memory hygiene.** Password bytes, derived keys, the plaintext snapshot and decrypted bytes are
  zeroed in `finally` blocks; inputs are encoded into fresh `Uint8Array`s, never `Buffer.from`
  (which would use the shared pool). By reading. This is best-effort by nature (JS strings, Web
  Crypto's internal copies and noble's temporaries are not wiped); the public JSDoc does not claim
  more than "bytes are copied", which is correct. Keep it that way — do not advertise wiping.
- **No `Math.random`** in `src/` or `scripts/` (grep; the only hit is the JSDoc sentence saying so).

### M1 — Prototype pollution changes security defaults (Medium) — verified

`src/modern/args.ts:51-66` validates options by `Object.keys` (own keys only) and then returns the
caller's object; `src/modern/encryption.ts:59,64` destructure `iterations` / `legacy` from it, which
walks the prototype chain. When no options are passed, `readOptions` returns a fresh `{}` whose
prototype is `Object.prototype`.

Failure scenario (probe 1a/1b, exact output):

```
Object.prototype.iterations = 100000;  encrypt('x','pw')  → token header cl1.100000.…   (expected 600000)
Object.prototype.legacy = true;        decrypt(legacyCt,'pw') → OK                     (expected ERR_LEGACY_NOT_ALLOWED)
```

So an application that already has a prototype-pollution bug (a very common class in JS apps) gets
two silent downgrades from its crypto library: 6× weaker tokens and unauthenticated legacy input
accepted everywhere, with no error. Note that an *inherited* explicit value is still validated
(`Object.create({iterations: 1})` → `ERR_PARAMS`, probe 1c), so this is strictly about defaults.

Fix: have `readOptions` copy own properties onto a null-prototype object and read from that:

```ts
const out: Partial<Record<K, unknown>> = Object.create(null);
for (const key of Object.keys(options)) { /* existing allow-list check */ out[key as K] = (options as any)[key]; }
return out;            // and `if (options === undefined) return Object.create(null)`
```

(`integerOption`/`booleanOption` already treat `undefined` as "use default", so nothing else changes.)
Add a test that pollutes `Object.prototype.iterations` and `.legacy` and asserts the defaults hold.

### M2 — Hostile-token work bound is loose and not caller-adjustable (Medium) — verified cost

A token's iteration count is attacker-chosen data; the only limit is `MAX_ITERATIONS = 10_000_000`
(`cl1.ts:30`), 16× the default. Measured here for 1,000,000 iterations: Web Crypto 209 ms, noble
3567 ms (probe 2d). Extrapolated per decrypt attempt of a 10M token: **~2.1 s native, ~36 s pure
JS**; on Hermes (no JIT) several times more.

Failure scenarios:
- A server that decrypts user-supplied tokens (the canonical use: tokens in URLs/cookies) burns
  2 s of CPU per hostile request with no password needed; 50 requests/s saturate a core.
- On Cloudflare Workers, `subtle.deriveBits` rejects >100,000 iterations (`NotSupportedError:
  Pbkdf2 failed: iteration counts above 100000 are not supported`, cloudflare/workerd#1346 — this
  confirms R6's "unverified" note). The R6 fallback then runs the attacker's count in pure JS:
  any token above 100k costs seconds, a 10M token exceeds the isolate's CPU budget and kills the
  request. The fallback turns "this platform cannot read big tokens" into "any client can burn
  36 s of CPU here".
- In a React Native app that receives tokens, a 10M token means minutes of background CPU
  (`pbkdf2Async` yields, so the UI survives, but battery and the operation do not).

The bound itself is not wrong — some ceiling is required and 10M is defensible as a hard cap —
but the application knows what it issues and should be able to say so. Fix: add
`maxIterations?: number` to `DecryptOptions` (and `upgrade`), default `MAX_ITERATIONS`, bounded to
[`MIN_TOKEN_ITERATIONS`, `MAX_ITERATIONS`], checked in `parseCl1` before derivation and reported as
`ERR_FORMAT` like the existing range check. Document in the `decrypt` JSDoc that the hard cap is
~2 s / ~36 s of work and that servers should set `maxIterations` to what they issue (e.g. 600000).
Optionally lower the hard cap to 2,000,000: nothing in the spec needs more.

### L1 — Fallback on `OperationError` doubles the cost of every failed decryption (Low) — verified

`src/modern/engine.ts:120-121` retries `open` in noble whenever Web Crypto rejects, for any reason.
Web Crypto reports an authentication failure as `DOMException` `OperationError` (probe 2e), so
(probe 2a/2b, instrumented counters):

```
wrong password:       { webDecrypt: 1, nobleOpen: 1 }
tampered ciphertext:  { webDecrypt: 1, nobleOpen: 1 }
```

Every wrong password or tampered token runs GCM twice, the second time in pure JS over the full
ciphertext (up to ~384 MiB for a maximal hostile token, with a second output buffer allocated).
It also means a real Web Crypto defect on a valid token would be silently papered over rather than
surfaced. Is the fallback ever dangerous for correctness? No: both engines compute the same
function, a valid token stays valid and an invalid one stays invalid, and the engines-test proves
equivalence. The cost is the only issue.

Fix: do not fall back on `OperationError` for `open` (and `seal`, where it cannot be an auth
failure but also cannot succeed in noble if the key/IV were accepted):

```ts
open: (key, iv, aad, sealed) =>
  web.open(key, iv, aad, sealed).catch((err) => {
    if ((err as { name?: string })?.name === 'OperationError') throw err; // genuine auth failure
    return nobleEngine.open(key, iv, aad, sealed);
  }),
```

Keep the unconditional fallback for `deriveKey`, where the cap is real.

### L2 — Foreign errors escape from `randomBytes` and compat `random` (Low) — verified

`src/internal/random.ts:54-58` and `src/compat/core.ts:38-48` only check that `getRandomValues`
exists. If it throws (probe 4f: a shim throwing `TypeError`; in real life a browser throwing
`QuotaExceededError` for a non-`Uint8Array` view, or a sandbox that stubs the function), the raw
error propagates. `errors.ts:25-27` promises "the only error type cryptolite's modern API throws",
and the `encrypt` JSDoc lists `ERR_RANDOM` for "no secure RNG". Fix: wrap the call and rethrow as
`ERR_RANDOM` with the original as `cause`. A no-op shim that returns the array unfilled yields all
zeros (probe 4f) — undetectable in principle; not a finding, but worth one sentence in the React
Native note ("install the real polyfill, not a stub").

### L3 — Docs honesty on the legacy path (Low) — verified numbers, docs by reading

The design is sound: legacy is off by default, `ERR_LEGACY_NOT_ALLOWED` names the fix,
`DecryptOptions.legacy` (`encryption.ts:43-52`) states unauthenticated + "roughly 1 in 256 wrong
passwords pass". Measured: `decryptBytes` accepted 21/4096 wrong passwords (1 in 195 — consistent
with the 1/256 padding estimate plus shorter-padding hits), `decrypt` 0/4096 (probe 3b). Empty
passwords rejected (R8). R9 scope is correct.

What the `upgrade()` JSDoc (`encryption.ts:281-312`) does not say explicitly: (1) `upgrade` cannot
detect that a legacy ciphertext was modified before it got there, so it will mint a *fully
authenticated* cl1 token of tampered plaintext — it launders tampering into something later checks
will trust; (2) the UTF-8 check that "stops most wrong passwords" is also the only thing that
stops CBC bit-flipping, and it is probabilistic: a flipped ciphertext block scrambles one
plaintext block, which is valid UTF-8 with probability on the order of 2^-16, so one in tens of
thousands of tampers passes; (3) via the documented binary route (`decryptBytes` + `encrypt`) there
is no check at all. Probe 3a confirmed the naive attack is caught (`ERR_DECRYPT`); the point is
to state the limits, since "upgrade" reads as "make safe". Suggested sentence for `upgrade` and
`DecryptOptions.legacy`: "Upgrading authenticates the token from now on; it cannot tell whether the
legacy ciphertext was altered before. Treat the first decrypt of legacy data as untrusted input."

Also mark in `SPEC-modern.md` R6 that the Cloudflare cap is now confirmed (workerd#1346).

### Other observations (Info)

- `MIN_TOKEN_ITERATIONS` (10k) < `MIN_ENCRYPT_ITERATIONS` (100k): tokens the library never issues
  are accepted. No attack follows (an attacker who can forge a 10k token knows the password), but
  the asymmetry deserves one line of rationale in `cl1.ts`.
- `checkPlaintextSize` includes the byte count in the message; harmless, but SPEC says messages
  carry no information about plaintext. Consider "exceeds 268435456 bytes".
- Passwords are UTF-8 encoded without Unicode normalization (same as crypto-js). Correct for
  interop, but worth a line in docs: the same visual password typed on iOS (NFD) and Android (NFC)
  derives different keys.
- `parseCl1` decodes the whole ciphertext before PBKDF2; unavoidable (the tag needs the bytes) and
  bounded by the string length as R12 says.

## 2. Legacy path (`src/modern/legacy.ts`)

By reading: `parseLegacy` requires canonical padded base64 of `Salted__` ‖ 8-byte salt ‖ ≥1 full
block; `evpBytesToKey` is the OpenSSL MD5/1-iteration derivation and wipes intermediates;
`legacyDecrypt` uses noble's CBC with PKCS#7 validation and maps every failure to the one
`ERR_DECRYPT`. Verified by running: real `crypto-js@4.2.0` output decrypts; `isLegacy` is `false`
for trailing space, stripped padding, non-strings and the bare prefix (probe 1g). No padding-oracle
exposure beyond what the format inherently has (see timing above). See L3 for the documentation
gap; nothing in the code needs to change.

## 3. Randomness

- Modern: `globalThis.crypto.getRandomValues` in 65536-byte chunks, bounds-checked length,
  `ERR_RANDOM` when absent (probe 4f/4g). Never `Math.random`.
- Compat: `WordArray.random` → `secureRandomInt()` → `getRandomValues(new Uint32Array(1))`, throws
  crypto-js's own message when absent (probe 4f). Used by `OpenSSLKdf` (8-byte salt) and
  `Iso10126.pad`. Equivalent to crypto-js 4.x's native path.
- See L2 for the throwing-shim case.

## 4. Compat layer (`src/compat`) — new weaknesses vs crypto-js 4.2.0?

None found. Probed against the real `crypto-js@4.2.0` devDependency (probe 4):

| Case | crypto-js | cryptolite |
|---|---|---|
| `SHA256({words:[0x41424344], sigBytes:12})` (reads past `words`) | `18e7c2…` | identical |
| AES key `sigBytes:32`, 4 words (reads past `words`) | `515e7e…` | identical |
| Fast path mutates caller's message / key WordArray | no / no | no / no |
| `HmacSHA256('m', key)` mutates caller's key (`clamp()`) | **yes** | no (safer; output identical) |
| cfg from `JSON.parse('{"__proto__":{…}}')` pollutes `Object.prototype` | no | no (`mixIn` uses `hasOwnProperty.call`; `__proto__` only re-parents the cfg copy, as in crypto-js) |
| `AES.decrypt` with wrong key | empty/garbage, no error | identical (non-validating `Pkcs7.unpad`, as intended) |
| `PBKDF2('pw','salt')` default | `3f5baa…` (SHA256/250k) | identical |
| 10-byte / 17-byte AES key | non-standard ciphertext | throws (D6) |

Read-through of the fast paths: `toBytes` reads exactly `sigBytes` bytes and masks per byte
(`core.ts:343-363`), `fastFinalize` reads the IV as raw `words[0..3]` ignoring `sigBytes` like
crypto-js, declines anything unusual (non-integer words, `process()` used, other modes/paddings,
odd lengths) to the verbatim path, and never lets noble validate padding on decrypt
(`aes.ts:41-82`). `NOBLE_EQUIVALENT` is keyed by identity so user subclasses take the generic path
(`hashers.ts:119-128`). `kdf.ts` PBKDF2/EvpKDF fast paths gate on integer iterations ≥ 1 and
integer, positive `dkLen`.

Garbage-in differences, for the compat lead's awareness (not security):
- Negative or fractional `sigBytes` give different digests from crypto-js (`SHA256(sigBytes:-4)`:
  crypto-js hashes stale words, cryptolite hashes the empty string; `sigBytes:7.5`: cryptolite hashes
  7 bytes because `new Uint8Array(7.5)` truncates in V8). No real program depends on these.
- A WordArray-like object with `sigBytes: 2**31` kills crypto-js in ~4 s (V8 fatal) and keeps
  cryptolite busy >20 s with a 2 GiB eager allocation in `toBytes`. Both are DoS under hostile
  *code-level* input; such objects do not arise from parsing untrusted strings (every parser sets a
  consistent `sigBytes`). Not worth a fix at the cost of fidelity.
- D6's AES key-size error is a deliberate, security-positive break, but note for MIGRATION.md
  that apps which (mis)used e.g. `Utf8.parse('secret1234')` as a key cannot read their own data
  with cryptolite at all — they need crypto-js to decrypt once and `upgrade`-style re-encryption.
- `PBKDF2` defaults match 4.2.0, not 4.1.1 (SHA-1 / 1 iteration). Users jumping from 4.1.x see
  different output exactly as they would upgrading crypto-js; worth a MIGRATION.md line.

## 5. Supply chain and release

Verified by running `npm run build` and `npm pack --dry-run --json`:
- `dist/index.js` / `dist/index.cjs` have no non-relative `import`/`require` (grep; the build's own
  `moduleReferences` AST check also enforces this). Banner records `@noble/hashes 2.4.0` and
  `@noble/ciphers 2.4.0 (bundled)`; both pinned exactly in `package.json` and resolved from
  `registry.npmjs.org` with `sha512` integrity in the lockfile. 2.4.0 is the latest published
  version of both (npm registry, today).
- Tarball: 256 files, all `dist/*`, the 50 `<name>/package.json` stubs, `README.md`, `package.json`.
  No tests, scratch, maps or env files. `prepack` (`scripts/verify-dist.mjs`) refuses a stale build.
- `npm audit`: 0 vulnerabilities (dev tree). No `.npmrc`/`.env` in the tree or history; secret-pattern
  grep clean.
- Workflows: actions pinned by commit SHA, and the SHAs match the `v7.0.1` / `v7.1.0` tags (checked
  against the GitHub API). `persist-credentials: false`, top-level `contents: read`, `id-token: write`
  only on the publish job, `NODE_AUTH_TOKEN` exposed only to the `npm publish` step (not to
  `npm ci`/build), tag = `package.json` version check, provenance on, concurrency guard, timeouts.
  This is a good baseline.

### M3 — Publish path hardening (Medium, by reading + public docs)

1. **Long-lived token.** `release.yml:58-60` publishes with `secrets.NPM_TOKEN`. npm now recommends
   Trusted Publishing (OIDC) over tokens, limits new write tokens to ≤90 days, and generates
   provenance automatically for trusted publishes from GitHub Actions (npm CLI ≥ 11.5.1, Node
   ≥ 22.14 — the job already uses Node 24). A token can be exfiltrated by any compromised dev
   dependency that runs in the same job *if* it were in scope — it is correctly scoped to one step
   today, but OIDC removes the secret entirely. Trusted Publishing can only be configured once the
   package exists, so: publish 1.0.0 from the owner's machine with 2FA (or with a 7-day token used
   once and deleted), then configure the trusted publisher (repo `nivkman/cryptolite`, workflow
   `release.yml`, environment `npm`) and delete the `NPM_TOKEN` secret and the `env:` line.
2. **Who can publish.** Any collaborator with push rights can push `v1.0.1` and publish. Add a
   repository ruleset restricting tag creation matching `v*` to the owner, and add the owner as a
   required reviewer on the `npm` environment (the workflow comment already anticipates this).
3. **Prereleases.** `npm publish` with version `1.1.0-rc.1` sets dist-tag `latest`. Either refuse
   prerelease versions in the "Tag matches" step, or pass `--tag next` when the version contains `-`.
4. Hygiene (Info): `npm ci --ignore-scripts` in the publish job (the build does not need install
   scripts; esbuild resolves its binary via optional deps), then `npm run build`. Keep `prepack`
   running on `npm publish`.

### L4 — Dependabot cooldown for bundled noble (Low, by reading)

`@noble/*` updates ship *inside* cryptolite's bundle, so a compromised noble release that is picked
up and released within hours becomes a cryptolite incident. Add a cooldown to the `npm` ecosystem
(e.g. `cooldown: { default-days: 7 }`, longer for the `noble` group) so updates are at least a
week old before a PR is opened. Also pin the noble group to exact versions in the PR (already
exact in `package.json`).

### L5 — Missing files in the tarball (Low, verified by pack)

No `LICENSE` (MIT + third-party notices; the banners inside the bundles do carry the notices, which
satisfies MIT, but npm, GitHub and license scanners look for the file) and no `SECURITY.md`
(D5 promises a "documented release-on-noble-advisory policy"; it should state: supported versions,
how to report, and that noble advisories trigger a cryptolite patch release). Both are in the docs
lane; they are release blockers from a reviewer's seat.

## 6. Claims

- README (as rewritten by the docs lane during this review) / `package.json`: "built on audited
  @noble cryptography" is accurate and the README now scopes it precisely — Cure53 audits of noble,
  SHA-1 explicitly outside noble-hashes' audit scope, and "what is **not** independently audited:
  cryptolite's own code". That is exactly the honesty bar this review would ask for; keep that
  paragraph through future edits. The comparison table's "audited" cell for cryptolite should read
  "audited primitives" (it does in the column header context, but the cell alone can be quoted).
- README "Where this runs" lists Cloudflare Workers without the PBKDF2 caveat: Workers caps
  `deriveBits` at 100,000 iterations, so the default 600,000 falls back to pure JS (~2 s CPU per
  `encrypt`/`decrypt` on V8), which is over the free plan's CPU budget and costly on paid plans.
  One sentence there (and in `EncryptOptions.iterations`) plus the `maxIterations` option from M2
  closes this.
- README links `LICENSE`, `MIGRATION.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`; none
  exist in the tree yet (L5). The license badge also points at the missing file.
- README "797 tests, currently all passing" — not verified by this review (the suite was not run
  here; the number should be regenerated at release time, not hand-maintained).
- `SPEC-modern.md`: "No constant-time compare: nothing in the modern API needs one" — correct (tag
  checks are inside noble / Web Crypto). The `hmac` JSDoc rightly tells users to compare MACs in
  constant time.
- `decrypt` JSDoc: "bounds the work a hostile token can cause" — true but unquantified; see M2.
- "Same API and byte-identical output" (README) — true with the D6 exceptions; link them.
- `encrypt` JSDoc: "Bytes are copied when the call starts" — accurate; no wiping claim is made.

## Method note

The `security-review` skill targets pending changes on a branch; the working tree was clean and the
request was a whole-tree pre-release review, so it was not invoked. `npm run build` was run (it
regenerates `dist/` and the gitignored stub directories only; the `package.json`/lockfile diff
present at the end of the review is `tinybench` added by the perf lane, and `README.md` was
rewritten by the docs lane while this review ran — both are outside this review's edits). The
full test suite was not run here; CI is the evidence for it. Probe scripts and their raw output
live in the session scratchpad under `security/` and are reproducible with
`esbuild internals-entry.ts --bundle --format=esm --platform=node --outfile=internals.mjs` followed by
`node probeN-*.mjs`.

# cryptolite v1.0.0 — pre-release code review

Reviewer: `code-reviewer` (reports to `tech-lead`). Date: 2026-10-24, 21:20–21:45 UTC.

**Tree reviewed.** HEAD `dc5ff81` ("Fix security review findings") plus the uncommitted changes
present at 21:41: `README.md` (docs lane), `package.json`/`package-lock.json` (+`tinybench`
devDependency, bench lane) and the untracked `LICENSE`, `MIGRATION.md`, `SECURITY.md`,
`CHANGELOG.md`, `CONTRIBUTING.md`, `bench/`. The modern-API files changed under me during the
review (security fixes M1/M2/L1/L2 landed as `dc5ff81`); every modern-API statement below is
about the committed `dc5ff81` content. `src/compat/**` changed only in `secureRandomInt`
(try/catch), so all compat findings apply to HEAD.

**Method.** Read `docs/DECISIONS.md`, `docs/PLAN.md`, `docs/SPEC-modern.md`, every file under
`src/`, `scripts/`, `test/`, `.github/`, `tsup.config.ts`, `vitest.config.ts`, and the
`crypto-js@4.2.0` reference sources in `node_modules`. Ran the full CI-equivalent locally and
differential probe scripts that execute identical code against `crypto-js` and the built
`dist/index.cjs`. Scripts and raw outputs:
`/tmp/claude-0/-root/050ff15a-4ac2-4860-b546-73df398a609f/scratchpad/review/`
(`compat-diff.cjs`, `compat-diff2.cjs`, `hash-after-decrypt.cjs`, `modern-probe2.mjs`, `*.out`,
`ci-run.log`, `fuzz-run.log`, `rerun2.log`). Node v20.19.2, npm 9.2.0. Only Node 20 was run
here; CI's 22/24 legs are **unverified**.

Cross-reference: `docs/reviews/security.md` (security-engineer) covers prototype pollution,
hostile-token cost, the OperationError fallback, foreign RNG errors and the publish path. Those
are fixed in `dc5ff81` and are not repeated here, except where this review verified the fix.

---

## Summary (ranked)

| # | Sev | Area | Finding | Evidence |
|---|-----|------|---------|----------|
| H1 | High | compat hashers | Hashers/HMAC/PBKDF2/EvpKDF ignore the bits crypto-js hashes beyond `sigBytes` in an unclamped WordArray. `CryptoJS.SHA256(CryptoJS.AES.decrypt(ct, key, cfg))` gives a different digest from crypto-js for 3 of every 4 plaintext lengths. | verified (ran) |
| H2 | High | compat core | `toBytes` floors a fractional `sigBytes` (what `Hex.parse` of an odd-length string produces) where crypto-js reads `ceil`; `SHA256(Hex.parse('abc'))`, `HmacSHA256`, `PBKDF2(.., salt)`, `EvpKDF`, `AES.encrypt(.., 'pw', { salt })`, `Utf8.stringify`, `Base64` output all differ. | verified (ran) |
| M1 | Medium | compat core/kdf | `toBytes` turns any non-WordArray object (`Buffer`, `Uint8Array`, number, `{}`) into **zero bytes**; `PBKDF2(Buffer.from(pw), salt)`, `PBKDF2(pw, Buffer.from(salt))`, `EvpKDF(123, salt)` silently derive keys from an empty password/salt where crypto-js throws. Hash helpers return the empty-input digest where crypto-js returns a (useless) constant. | verified (ran) |
| M2 | Medium | compat AES | Calling `finalize()` twice on one `createEncryptor()` re-runs the one-shot fast path with the *original IV*; crypto-js chains CBC from the previous ciphertext block. Second output differs and reuses an IV. The fast path also reads `cfg.iv` at finalize time instead of the mode's captured IV. | verified (ran) |
| M3 | Medium | compat hashers | A second `finalize()` (or `update()` after `finalize()`) on a hasher or `algo.HMAC` instance throws noble's `Error: hash was destroyed`; crypto-js returns a value. | verified (ran) |
| L1 | Low | compat core | `Utf8.parse(undefined)` / `Utf8.parse(null)` throw `TypeError` (property read on `undefined`); crypto-js returns the bytes of `"undefined"` / `"null"`. | verified (ran) |
| L2 | Low | compat core | `WordArray.random()` words are signed (`| 0`); crypto-js on every runtime with `getRandomValues` returns unsigned words, and the code comment cites the wrong crypto-js path. | verified (ran) |
| L3 | Low | compat | Undocumented behaviour differences: subclass overrides of `encryptBlock`/`_doFinalize` are bypassed by the fast paths; a string key passed to `createEncryptor` (key mode) is used as real key bytes; `SHA3` with out-of-spec `outputLength` throws; `.words.length` of SHA3-224/PBKDF2 outputs differs. None are in `documented-differences.test.ts` or `MIGRATION.md`. | verified (ran) |
| L4 | Low | packaging | `MIGRATION.md`, `SECURITY.md`, `CHANGELOG.md` are not in the tarball (`files` whitelist; npm auto-includes only README/LICENSE/package.json). Error messages link to MIGRATION.md on GitHub, so this is a choice to make, not a break. | verified (`npm pack --dry-run`) |
| L5 | Low | CI | The `FUZZ=1` differential suite never runs in CI (skipped by default); the `concurrency.cancel-in-progress` expression in `ci.yml` can never be `false` when called from `release.yml`. | by reading; fuzz suite run locally (77 passed) |
| — | — | modern API | No blocking defects. Async contract, strict parsing, engine fallback, option validation and the `maxIterations` change verified. Two API nits below. | verified (ran) |
| — | — | build/packaging | `clean()` deletion logic, CJS `module.exports` shape, shim generation, `exports`/`files` sync, publint, attw: verified. | verified (ran) |

H1 and H2 are the ones that contradict the README's "byte-identical output" claim for inputs
real programs produce. H1 needs a decision outside my lane (see "Decision needed"); H2, M1, M2
are small code fixes.

---

## 1. Correctness: compat output differs from crypto-js

### H1 — Hashers drop the bits beyond `sigBytes`; crypto-js hashes them (High)

**Where.** `src/compat/hashers.ts:27,33` (`NobleHasher.update/finalize` → `toBytes`),
`hashers.ts:81,91` (one-shot helpers), `src/compat/kdf.ts:42,97` (PBKDF2/EvpKDF fast paths),
all via `src/compat/core.ts:348-368` (`toBytes` masks every byte to `sigBytes`).

**Defect.** crypto-js's `_doFinalize` ORs the 0x80 padding bit into the *existing* last word
(`dataWords[nBitsLeft >>> 5] |= 0x80 << ...`) without clamping, so any bits set beyond `sigBytes`
in the final partial word become part of the hashed padding block. cryptolite feeds noble exactly
`sigBytes` clean bytes. The two agree only when the input is clamped.

**Who produces unclamped WordArrays?** crypto-js itself: every `AES.decrypt` result whose
length is not a multiple of 4 keeps the PKCS#7 bytes in its last word (`words` =
`68656c6c 6f0b0b0b ...` for `"hello"`, `sigBytes` = 5); any digest truncated by assigning
`sigBytes` to a non-multiple of 4; `WordArray.random(n)` with `n % 4 != 0`; `concat` results in the
aligned branch.

**Failure scenario (ran, `hash-after-decrypt.out`).** "Verify the checksum after decrypting":

```
SHA256(AES.decrypt(AES.encrypt('hello', key, {iv}), key, {iv}))
  crypto-js : 078592d816461a2725b9733fa0e5ed61c83cdc4c6cdb7eb1fba2d05b05cf3c1a
  cryptolite: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  (= SHA256('hello'))
MD5(decrypt('hello'))            crypto-js c508ed66…  cryptolite 5d41402a…
HmacSHA256(decrypt('hello'),'k') crypto-js 0c0359d7…  cryptolite 406e4b43…
passphrase mode SHA256(AES.decrypt(AES.encrypt('hello','pw').toString(),'pw'))  differs the same way
SHA256(decrypt('hell'))  (4 bytes, aligned)                                     SAME
```

Also (`compat-diff.out`): `SHA256(WordArray.create([0x41424344], 2))`, `MD5(...)`, a digest with
`h.sigBytes = 10` re-hashed, `algo.SHA256.create().update(unclamped).finalize()`,
`HmacSHA256(unclampedMsg, 'key')`, `HmacSHA256('msg', unclampedKey > blockSize)`,
`PBKDF2(unclampedPassword > blockSize, salt)`, `SHA3(unclamped)` — all DIFF. The decrypted
*bytes* are identical (1,000,003-byte CBC round trip: same hex, same length); only the digest of
the WordArray object differs. An app that stored `CryptoJS.SHA256(decryptedWordArray)` as an
integrity value under crypto-js will reject every record under cryptolite.

**Why the tests did not see it.** Every compat test builds inputs with
`WordArray.create(bytes)` (always clamped) and hashes strings; nothing hashes a decrypt result or
a truncated digest.

**Decision needed (tech-lead / product-owner), not mine to make.** Two honest options:
1. Reproduce it: when the last appended word carries bits beyond `sigBytes`, run the message
   through a ported crypto-js finaliser (MIT) instead of noble — this contradicts D4 for that
   rare path, but it is padding arithmetic, not a primitive. Needs the same for HMAC/PBKDF2/EvpKDF
   since they route through the hasher.
2. Declare it a deliberate difference (D6-style): document in `DECISIONS.md` + `MIGRATION.md` with
   the hash-after-decrypt example, add it to `documented-differences.test.ts`, and soften the
   "byte-identical" claim in `README.md` to "byte-identical for clamped inputs; see differences".
Either way the current silent state is not acceptable for a package whose pitch is zero-change
drop-in.

### H2 — Fractional `sigBytes` is floored, crypto-js reads `ceil` (High)

**Where.** `src/compat/core.ts:353-354` (`new Uint8Array(sigBytes)` — V8's `ToIndex` truncates
1.5 → 1, so `out` has 1 slot) and `:364` (the loop then writes index 1 into nothing). Reached from
every hasher path (`hashers.ts:27,33,81,91`), `Utf8.stringify` (`core.ts:314`), `Base64*.stringify`
(`enc.ts:62`), `kdf.ts:42,97-98`. `isWordArrayLike` (`core.ts:336-345`) rejects non-integer
`sigBytes` so the *one-shot* helpers fall back — but the fallback (`NobleHasher.finalize`) uses
the same `toBytes`, so the fallback does not help.

**Who produces it?** `CryptoJS.enc.Hex.parse()` of any odd-length string (`'abc'.sigBytes ===
1.5` in both libraries — a missing leading zero, a hex id built with `n.toString(16)`).

**Failure scenario (ran, `compat-diff.out`, `compat-diff2.out`).**

```
SHA256(Hex.parse('abc'))                 crypto-js 551501b3…  cryptolite 087d80f7…
MD5(Hex.parse('abc'))                    crypto-js 631fdae2…  cryptolite 2408ad11…
HmacSHA256(Hex.parse('abc'), 'key')      DIFF
PBKDF2('pw', Hex.parse('abc'), {iterations:2})            DIFF
EvpKDF('pw', Hex.parse('abc'))                             DIFF
AES.encrypt('m', 'pw', {salt: Hex.parse('abc')})           DIFF (different key/IV derived)
Hex.parse('414').toString(Utf8)          crypto-js "A\u0004"  cryptolite "A"
Hex.parse('abcde').toString(Base64)      crypto-js "q80A"     cryptolite "q80="
Hex.parse('abcde').toString(Latin1)      SAME  (Latin1 is the verbatim loop)
AES.encrypt(Hex.parse('abc'), key, {iv}) SAME  (block path is verbatim)
```

**Fix (small).** In `toBytes`, allocate `Math.ceil(sigBytes)` bytes and iterate
`for (i = fullWords*4; i < sigBytes; i++)` exactly as crypto-js's per-byte readers do; keep
`sigBytes <= 0 → 0`. Then the one-shot guards can stay as they are. Add `Hex.parse('abc')`,
`'abcde'` to the hasher/encoder/KDF differential tests.

### M1 — `toBytes` silently empties non-WordArray input; KDFs derive keys from nothing (Medium)

**Where.** `src/compat/core.ts:352-353` (`data.words` undefined, `data.sigBytes > 0` false →
zero-length output, no error). `src/compat/kdf.ts:32-43` — the PBKDF2 fast path checks hasher,
iterations and `dkLen` but **never checks the types of `password`/`salt`**; `evpFast`
(`kdf.ts:94-95`) checks them but the generic path's `hasher.update()` still goes through
`toBytes`.

**Failure scenario (ran, `compat-diff.out`, `compat-diff2.out`).**

```
PBKDF2(Buffer.from('pw'), 'salt')   crypto-js THROWS TypeError      cryptolite f135c279… (= PBKDF2('', 'salt'))
PBKDF2(123, 'salt')                 crypto-js THROWS TypeError      cryptolite f135c279… (= empty password)
PBKDF2('pw', Buffer.from('salt'))   crypto-js THROWS RangeError     cryptolite 6a651927… (= empty salt)
EvpKDF(123, 'salt')                 crypto-js THROWS RangeError     cryptolite ceb20772…
EvpKDF('pw', Buffer.from('salt'))   crypto-js 7597127e… (garbage)   cryptolite 8fe4c114… (empty salt)
MD5(Buffer.from('abc')) / MD5(new Uint8Array([1,2,3])) / SHA256(12345) / SHA256({}) / SHA256(true)
                                    crypto-js: one constant per algo (487f7b22… / 4ea5c508…)
                                    cryptolite: digest of the empty input (d41d8cd9… / e3b0c442…)
HmacSHA256(123, 'k')                DIFF (same mechanism);  HmacSHA256('m', 123) SAME (both throw)
```

A caller who passes a `Buffer`/`Uint8Array` where crypto-js wanted a WordArray (a very common
mistake) used to get an exception from crypto-js; under cryptolite they get a key derived from an
empty password or empty salt and no signal. That is a silent weak-key path in a crypto library.
The hash-helper constant is harmless (it is the same for every such input in crypto-js, so
nothing can depend on it) but should be listed as a documented difference.

**Fix.** `toBytes` should throw a `TypeError` when `data` is not a string and `data.words` is not
an array (crypto-js throws in all the KDF/HMAC/AES cases above); gate the PBKDF2 fast path on
`isMessage(password) && isMessage(salt)` like `evpFast` does. Add the `Buffer`/number cases to
`documented-differences.test.ts`.

### M2 — AES encryptor reused after `finalize()` repeats the IV (Medium)

**Where.** `src/compat/aes.ts:42` guards the fast path with `_data.sigBytes !== 0 ||
_nDataBytes !== 0`, both of which are still 0 after a fast-path `finalize`; `aes.ts:54` reads
`cfg.iv.words` instead of the IV the mode captured (`self._mode._iv`). After the fast path the
mode object is untouched (`_iv` still set, `_prevBlock` unset).

**Failure scenario (ran, `compat-diff.out`).**

```
const e = CryptoJS.algo.AES.createEncryptor(key, { iv });
e.finalize('first message!!!');   // SAME on both
e.finalize('second message!!');   // crypto-js a2ff513d… (CBC chained from block 1)
                                  // cryptolite a2c543dd… (== a fresh encryptor with the same IV)
e.cfg.iv = otherIv; e.finalize('hello')   // crypto-js uses the IV captured at reset(); cryptolite uses otherIv → DIFF
```

With `reset()` between the calls both agree (verified). The second cryptolite output also reuses
the IV with the same key, which is the CBC property crypto-js's chaining happened to avoid.

**Fix.** Take the IV from `self._mode._iv` (and decline the fast path when it is `undefined`),
and after a fast-path finalize update the mode state the way the verbatim path leaves it:
`_mode._iv = undefined`, `_mode._prevBlock = last block (ciphertext for encrypt, input for
decrypt)`, `_nDataBytes += data.length`. That makes a later `finalize`/`process` take the generic,
crypto-js-identical route. The decryptor case happens to match today only because the unpadded
result is empty garbage in both (verified).

### M3 — Hasher / HMAC reuse after `finalize()` throws instead of returning (Medium → Low if documented)

**Where.** `src/compat/hashers.ts:27,33-35`: `finalize` calls `this._noble.digest()`, after which
noble refuses `update()`/`digest()`.

**Failure scenario (ran).**

```
h = algo.SHA256.create(); h.finalize('a'); h.finalize('b')     crypto-js 3b5e25ee…   cryptolite THROWS Error: hash was destroyed
h.update('a'); h.finalize(); h.finalize()                       crypto-js 1aba48f5…   cryptolite THROWS
hm = algo.HMAC.create(algo.SHA256, 'k'); hm.finalize('a'); hm.finalize('b')
                                                                crypto-js 70ea61a5…   cryptolite THROWS
```

crypto-js's second value is not a correct digest of anything, so nobody can be *relying* on its
value; but code that calls `finalize()` twice (once to log, once to use) runs under crypto-js and
crashes under cryptolite with a message that names neither crypto-js nor the cause. Cannot be
matched with noble. Recommend: throw a clear `Error('cryptolite: hasher already finalized; call
reset()')` and list it as a documented difference.

### L1 — `Utf8.parse(undefined | null)` throws `TypeError`

**Where.** `src/compat/core.ts:291` reads `(s as Any).isWellFormed` before anything coerces `s`.
crypto-js runs `encodeURIComponent(s)`, which stringifies: `Utf8.parse(undefined)` →
`756e646566696e6564` ("undefined"), `null` → `6e756c6c`. `Utf8.parse(123)` is the same in both.
Scenario: `CryptoJS.HmacSHA256(msg, CryptoJS.enc.Utf8.parse(process.env.KEY))` with `KEY` unset
works (with a terrible key) under crypto-js and throws `Cannot read properties of undefined
(reading 'isWellFormed')` under cryptolite. Fix: `s = String(s)` at the top of `utf8Encode`
(matching `encodeURIComponent`), or throw deliberately with a clear message and document it.

### L2 — `WordArray.random()` words are signed

**Where.** `src/compat/core.ts:43` (`| 0`) and the comment at `:37-38` ("like crypto-js's
`readInt32LE` path"). crypto-js 4.2.0 `core.js:65-67` prefers `getRandomValues(new
Uint32Array(1))[0]` (unsigned) on every runtime that has it, including Node >= 19; the
`readInt32LE` branch is the Node-without-WebCrypto fallback. Ran: 200 draws — crypto-js 0 negative
words, cryptolite ~50%. Observable through `.words` / `JSON.stringify(wordArray)`; the encoded
bytes are fine. Fix: drop `| 0`.

### L3 — Differences that exist but are documented nowhere

All ran (`compat-diff.out`, `compat-diff2.out`); none appear in `documented-differences.test.ts`,
`MIGRATION.md`, `DECISIONS.md` or `scripts/subpaths.mjs`:
- `algo.AES.extend({ encryptBlock })`: the fast path (`aes.ts:41-82`) never calls the override
  (crypto-js e7eab831…, cryptolite 181547ce…). `algo.SHA256.extend({ _doFinalize })`: never
  called (crypto-js `00000001…`, cryptolite a real digest). Inherent in D4; say so, or guard the
  fast paths with identity checks on `encryptBlock`/`decryptBlock`/`_doProcessBlock`/`_doFinalize`.
- `algo.AES.createEncryptor('0123456789abcdef', { iv })` (string key in *key* mode): crypto-js
  produces deterministic non-AES output (857cab2b…); cryptolite uses the UTF-8 bytes as an AES-128
  key (d601dd9b…) or throws for other lengths. D6 talks about sizes, not string keys.
- `SHA3('abc', { outputLength: 0 | 100 | 1024 })`: crypto-js returns zeros/empty, cryptolite
  throws noble `RangeError`s. `SHA3(..., {outputLength: 224}).words.length` 8 vs 7;
  `PBKDF2(.., {keySize: 5}).words.length` 8 vs 5 (bytes identical).
- `createEncryptor(stringKey)` error text says `(got undefined)` (`aes.ts:101` prints
  `key.sigBytes`); print the byte count `n`.

### Verified identical (so nothing to do)

Falsy messages (`SHA256()`, `null`, `''`, `0`, `AES.encrypt(undefined|''|0, …)`), holes and
non-integer words, `sigBytes` larger than `words`, negative/NaN `sigBytes` through every encoder,
lone surrogates (same `URIError` on both), `cfg` objects made with `Base.extend`, mode/padding
subclasses (`CBC.extend()`, `Object.create(Pkcs7)`) correctly take the verbatim path, short IVs,
IVs with odd word values, `iv` as a plain `{words}` object, `process()` then `finalize()`,
`process('')`, Iso10126 (random pad bytes, correct length byte, cross-decrypt), custom and short
Base64 `_map`s, the Base64url single-cache quirk, OpenSSL base64 with embedded newlines, 1 MB CBC
and ECB one-shot encrypt/decrypt (hex-identical), progressive 1 MB decrypt, passphrase mode
cross-decryption both ways, wrong-key garbage.

---

## 2. Modern API (`src/modern`, `src/internal`) — no blocking findings

Verified by running (`modern-probe2.out`, unit suite): every public function rejects rather than
throws (`encrypt(1, pw)` → Promise, `ERR_PARAMS`); strict cl1 parsing (trailing `\n` →
`ERR_FORMAT`); `readOptions` after `dc5ff81` copies own enumerable keys to a null-prototype
object, so inherited and polluted keys are neither validated nor honoured (consistent now; before
the fix `Object.create({iterations:1e5})` was honoured while unknown inherited keys were not);
`hmac` leaves caller `Buffer` keys intact; `encrypt` from a pooled `Buffer.subarray` round-trips;
cross-realm `Uint8Array`s accepted; `isLegacy` rejects CRLF-suffixed and `format.Hex` ciphertexts;
`upgrade` preserves bytes; the default export carries the modern functions and the same
`CryptoliteError` class. Engine fallback, tamper matrix, legacy padding-oracle statistics and the
node:crypto reference implementation are covered by `test/modern/**` (805 passing at 21:40).

The `maxIterations` change (`encryption.ts`, `cl1.ts`, `MAX_ITERATIONS` 2,000,000) is internally
consistent after `dc5ff81`: option keys per function, bounds `[10000, 2000000]`, checked after
`parseCl1` and before key derivation with `ERR_FORMAT`, `UpgradeOptions` exported and picked up by
the generated `dist/index.d.ts` namespace. `test/modern/tamper.test.ts` was updated in the same
commit (my 21:38 run caught the intermediate state failing on the old 10,000,000 literal; the
21:40 run on `dc5ff81` passes).

API nits (suggestions, not defects):
- `isLegacy(token: string)` promises "never throws; `false` for non-strings"; type the parameter
  as `unknown` so TypeScript callers can pass what the runtime already accepts.
- `README.md` says "797 tests, currently all passing"; the unit project alone is 805 + 77 skipped,
  the full run 831 before `dc5ff81`. Drop the number or generate it.
- `test/modern/encryption.test.ts:119` is named "at any iteration count in [10000, 2000000]" but
  exercises 10,000 / 12,345 / 100,000 only; rename or add the upper bound at parser level (the
  tamper test already does).

---

## 3. Build, packaging, CI

Verified by running (`ci-run.log`, 21:22–21:30, Node 20): `npm run typecheck` exit 0;
`npm test` = build + unit + package projects, 22 files / 831 tests passed, 78 skipped (FUZZ);
`npm run lint:pkg`: publint strict clean, attw strict profile "No problems found", node16 profile
clean with the documented node10 × `.js` gap; `git status` unchanged by the build (exports/files in
sync); re-run on `dc5ff81` at 21:40: typecheck 0, unit 805 passed.

- **CJS shape** (`dist/index.cjs`): exactly one `module.exports = src_default;`, no `__esModule`,
  `Object.assign(compat_default, modern_exports)` present, bundled noble notices at EOF; the ESM
  named-export consts survive as dead `var X2 = compat_default.X` lines in the CJS bundle
  (harmless, a few hundred bytes).
- **`sideEffects` plugin** (`tsup.config.ts:22-39`): relies on `path.resolve('src')`, i.e. on the
  cwd being the repo root — true for `scripts/build.mjs` (`cwd: ROOT`), not for a bare `npx tsup`.
  Effectiveness is asserted indirectly by `test/package` (every CryptoJS member present). Fine.
- **Stub deletion** (`scripts/build.mjs:65-79`): refuses unless the directory contains exactly one
  entry, `package.json`, byte-equal to `stubContent(name)`; validated for all 50 before deleting
  any; ran a symlink check (`rmSync` on a symlinked stub dir removes the link only, target
  intact). A *file* named like a stub makes `readdirSync` throw before any deletion. Correct.
- **Shims / exports / files** (`build.mjs:269-332`, `subpaths.mjs`): generated from one list,
  pinned to crypto-js's shipped `.js` modules by `test/package/subpaths.test.ts`; `./name` and
  `./name.js` both map; `./package.json` exported. OK.
- **L4 — tarball root files.** `npm pack --dry-run` on the current tree ships `LICENSE`,
  `README.md`, `package.json` only (257 files, 540,711 bytes). `MIGRATION.md`, `SECURITY.md`,
  `CHANGELOG.md`, `CONTRIBUTING.md` are not auto-included by npm and are not in `files`
  (`dist.test.ts:96` *allows* them, which is why no test says so). Error messages point at the
  GitHub URL, so nothing breaks; decide whether to add them to `files` before tagging. The docs
  files are still untracked — they must be committed before the `v1.0.0` tag or the published
  package has no LICENSE.
- **`verify-dist.mjs`** staleness check covers `src/`, the build scripts and configs but not
  `node_modules/@noble/*`: a local `npm update` of noble followed by `npm publish` without
  `npm run build` would pass prepack with the old bundle. CI/release always rebuild, so low.
- **L5 — CI runs what it claims**, with two gaps: (a) `fuzz.test.ts` is `describe.skip` unless
  `FUZZ=1`, so the matrix/length sweeps never run in CI (I ran `FUZZ=1 npx vitest run
  test/compat/fuzz.test.ts`: 77 passed); add a scheduled or main-branch job. (b)
  `ci.yml:16` `cancel-in-progress: ${{ github.event_name != 'workflow_call' }}` — inside a called
  workflow `github.event_name` is the caller's event (`push`), so the expression is always `true`;
  harmless because the tag-based group is unique, but the comment's intent is not implemented.
  Action SHAs are pinned; I could not verify them offline (**unverified**).
- `package.json`/`package-lock.json` carry an uncommitted `tinybench` devDependency (bench lane);
  the lock has the `node_modules/tinybench` entry, so `npm ci` will work once committed together.

---

## 4. Test quality

- **Input diversity is the gap.** `test/compat/**` constructs every WordArray with
  `WordArray.create(bytes)` and every message as a string; nothing exercises unclamped data,
  fractional `sigBytes`, non-WordArray objects, a second `finalize()`, `Utf8.parse(undefined)`,
  or hashing a decrypt result. H1–M3 and L1 all pass the suite. Add a "crypto-js-produced inputs"
  file: `SHA256/MD5/HmacSHA256(AES.decrypt(...))` for lengths 1..20, `digest.sigBytes = 10`,
  `Hex.parse('abc' | 'abcde')` through every encoder/hasher/KDF, `Buffer`/number inputs (pin the
  decided behaviour), double `finalize()`.
- `word-array.test.ts:95-106` (`WordArray.random`) asserts only `sigBytes`/length; an RNG returning
  zeros passes. Assert two draws differ and that the output is not all zero.
- AES differential coverage stops at 300 bytes (37 bytes by default); the one-shot path is the
  production path for large data. Add >= 1 MiB CBC/ECB encrypt + decrypt (ran: identical) and a
  length that is a multiple of 16 for both encrypt and decrypt.
- `documented-differences.test.ts` should pin every intentional difference once L3 and the H1
  decision are settled, so a future "fix" cannot silently flip them.
- No instance of comparing `undefined` to `undefined` or a library to itself found: the shared
  `libEntries.map(...)` pattern calls `.toString()` on results (throws on `undefined`), and the
  package tests compare against vectors computed from the real crypto-js.
- `aes-passphrase.test.ts:99-112` and `aes-key-modes.test.ts:202-222` accept "both throw with the
  same message" as a pass; acceptable, since the message equality is asserted.

---

## 5. Simplification / reuse (suggestions; no failure scenario)

- `isMessage` is defined twice, identically (`hashers.ts:71`, `kdf.ts:122`); move it next to
  `isWordArrayLike` in `core.ts`.
- `fastFinalize` should take the IV from `self._mode._iv` (see M2) — removes the `cfg.iv` re-read
  and one divergence.
- Two UTF-8 codecs ship in the bundle: `src/compat/core.ts` (TextEncoder/TextDecoder probe +
  `unescape(encodeURIComponent())` fallback, D11) and `src/internal/utf8.ts` (pure JS, same
  accept/reject set). Note before unifying: compat must keep throwing `URIError` on lone
  surrogates (verified identical to crypto-js today); `internal/utf8` throws `CryptoliteError`, so
  a wrapper would be needed, and the native TextEncoder path is faster for large strings. Leave
  as is unless size matters; if unified, delete the probes and `isWellFormed`.
- `WordArray.random` (`core.ts:156-162`) calls `getRandomValues(new Uint32Array(1))` once per
  word, as crypto-js does; one call per <= 65,536 bytes gives the same words and is ~100x faster
  for `random(1 << 16)` / Iso10126-heavy code.
- `HEX_TABLE` in `core.ts` and `hexEncode` in `internal/hex.ts` duplicate hex encoding; harmless.
- `src/index.ts` named exports produce dead `var` lines in the CJS bundle; acceptable.

---

## Appendix — commands run and results

| Command | Result |
|---|---|
| `npm run typecheck` (21:22, HEAD 655a505 + wip) | exit 0 |
| `npm test` (build + vitest unit + package) | exit 0; 22 files passed, 1 skipped; 831 tests passed, 78 skipped |
| `npm run lint:pkg` (publint --strict, attw x2) | exit 0; "No problems found" (strict profile), node16 profile clean except documented node10 `.js` NoResolution |
| `FUZZ=1 npx vitest run --project unit test/compat/fuzz.test.ts` | exit 0; 77 passed |
| `npm run typecheck && npx vitest run --project unit` (21:38, mid-edit tree) | typecheck 0; 1 failed (`tamper.test.ts` expected 10,000,000; test not yet updated) |
| same (21:40, tree == `dc5ff81` + untracked docs) | typecheck 0; 18 files passed, 1 skipped; 805 passed, 77 skipped |
| `node compat-diff.cjs`, `compat-diff2.cjs`, `hash-after-decrypt.cjs` | outputs in `*.out`; DIFF/SAME per case as quoted above |
| `node modern-probe2.mjs` | outputs in `modern-probe2.out` |
| `npm pack --dry-run --json` | 257 files; root files LICENSE, README.md, package.json |
| symlink `rmSync` check | link removed, target intact |

Not run: Node 22/24 legs, browsers/Deno/Bun/Workers/React Native, the GitHub workflows
themselves, `npm publish`. Nothing was pushed or published; no file outside this review was
edited by me.

---

## Resolution (lead, 2026-10-25)

| Finding | Status |
|---|---|
| H1 bytes beyond sigBytes | **Fixed** — hashers run crypto-js's buffering/padding with noble compression (DECISIONS D14). |
| H2 fractional sigBytes | **Fixed** — `toBytes` reads `ceil(sigBytes)`; fast paths require whole bytes; Base64 uses crypto-js's loop for fractional input. |
| M1 non-WordArray inputs | **Fixed** — fast paths only accept clean strings/WordArrays; everything else takes the verbatim path (identical results or identical throws). |
| M2 encryptor reuse / cfg.iv | **Fixed** — AES fast path only on a fresh cipher, IV from `_mode._iv`, CBC chain state updated afterwards; subclasses overriding block functions skip it. |
| M3 finalize twice | **Fixed** — word-mode hashers continue like crypto-js, incl. MD5/RIPEMD-160 in-place state swap and SHA-224's shrinking sigBytes. |
| L1 Utf8.parse(non-string) | **Fixed.** |
| L2 random words signed | **Fixed** — unsigned, crypto-js word count, batched. |
| L3 fast-path bypass of subclasses | **Fixed** (identity checks); string/number AES keys and odd SHA3 lengths are documented differences (D14). |
| L4 docs not in tarball | **Fixed** — MIGRATION/SECURITY/CHANGELOG added to `files`. |
| L5 FUZZ never in CI | **Fixed** — FUZZ=1 step on the Node 22 leg. |
| Utf8.stringify(string) (found while verifying) | **Fixed** — returns '' like crypto-js. |

Evidence: `test/compat/review-regressions.test.ts` (41 cases, each vs crypto-js); the reviewer's
probe scripts now report SAME for every case except the D14 differences; `npm test` 880 passed,
`FUZZ=1` compat 2691 passed.

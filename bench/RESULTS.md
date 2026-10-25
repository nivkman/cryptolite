# cryptolite — speed and size results

Measured **2026-10-25** (UTC) against the **built** package: `dist/index.js` built by `npm run build`
from commit `f7442a1` (the later commit `4b858cd` is documentation only; no build input changed),
`dist/index.js` sha256 `6e74d9b7f415f8f84ca412b73328916d0455d411aad1816ca58e26db80629c3d`, no
uncommitted build inputs. Every result file in `bench/raw/` records this hash; the runner aborts
if `dist/` changes during a run.

**How to read the provenance tags:** **[run]** = `bench/run.mjs`, **[size]** = `bench/size.mjs`,
**[hermes]** = `bench/hermes.mjs`, **[exp: name]** = `bench/experiments/<name>.mjs`. Raw output of
each is in `bench/raw/`. Anything not tagged is arithmetic on tagged numbers, or labelled
*unverified*.

## Machine and toolchain

| | |
|---|---|
| CPU | AMD EPYC 7713 64-Core Processor (`/proc/cpuinfo`), KVM guest, **4 vCPUs** (4 cores × 1 thread), L3 64 MiB |
| RAM | 7.8 GiB (MemTotal 8,138,044 kB) |
| OS | Linux 6.12.88+deb13-amd64, x64 |
| Node | v20.19.2 (V8 11.3.244.8-node.38) |
| Compared | crypto-js 4.2.0 vs cryptolite 1.0.0 (dist above) |
| Tools | tinybench 6.2.2 (devDependency), esbuild 0.28.2 (via tsup 9.0.0), rollup 4.65.0, Hermes 0.12.0 (`hermes-engine-cli@0.12.0`), @babel/core 7.29.7, @react-native/babel-preset 0.88.0 (Hermes toolchain installed outside the repo) |

**Load.** This VM is shared with other agent sessions; nobody else was benchmarking. The 1-minute
load average was 0.46 when the speed run started and 1.18 when it ended, and 0.68–1.79 (median
1.31) across the 280 samples taken after each measurement. It was 1.12 → 1.04 for the Hermes run.
Absolute numbers on a quiet machine may be higher. **Ratios travel better than absolute ops/s.**

## Exact commands

```sh
npm ci && npm run build
uptime
node --expose-gc bench/run.mjs --runs 5 --json bench/raw/run.json > bench/raw/run.md     # ~22 min
node bench/size.mjs --json bench/raw/size.json > bench/raw/size.md                      # ~10 s

# Hermes toolchain: anywhere outside the repo
DIR=$(mktemp -d) && (cd "$DIR" && npm init -y >/dev/null && \
  npm i --save-exact hermes-engine-cli@0.12.0 @babel/core@7.29.7 @react-native/babel-preset@0.88.0)
node bench/hermes.mjs --toolchain "$DIR" --json bench/raw/hermes.json > bench/raw/hermes.md  # ~8 min

# Evidence for "Opportunities" (each prints its own method)
node bench/experiments/esbuild-const.mjs
node bench/experiments/pure-annotations.mjs
node bench/experiments/target-es2022.mjs
node bench/experiments/encoders.mjs
node bench/experiments/profile.mjs
```

`npm run bench` runs `npm run build`, then `bench/run.mjs` (5 runs) and `bench/size.mjs`.
`node bench/run.mjs --quick` is a smoke test; its numbers are not for publication.

## Method

**Speed [run].** First, every case runs once per library in the parent process. Outputs must be
identical: hash hex, ciphertext, plaintext; random-salt passphrase ciphertexts are decrypted by
the *other* library, and modern tokens are decrypted. After that check, each (case, library) pair
is measured in its **own fresh `node --expose-gc` process**. This is repeated 5 times, interleaved
(run 1 of every case, then run 2, ...).

Inside a process, timing uses tinybench 6.2.2 (sequential, hrtime clock) after a forced GC. Calls
under ~2 ms are batched so that one sample takes ~2 ms. The batch size comes from a 150 ms
calibration loop, which also warms the JIT, followed by tinybench's own warm-up. Budgets are at
least 30 samples / 2 s for fast calls, 15 / 3 s for slow ones, and a fixed sample count where
stated.

**Within-run RME** is tinybench's relative margin of error: the 95 % CI of the mean, Student's t.
A run at or above 5 % RME is re-run with twice the budget, at most twice; if it is still at or
above 5 %, the table marks it **(!)**.

What the tables show:
- **ops/s** is the median over the 5 runs.
- **runs ±x %** is half the min–max range over the runs, relative to the median.
- **Speedup** is the median over runs of cryptolite ÷ crypto-js, pairing run *i* with run *i*.
  Its min–max over runs is in parentheses.

**Why isolated processes.** Two earlier single-process passes on this same build
(`bench/raw/in-process-A.*`, `in-process-B.*`, made with the single-process mode, now
`--in-process`) disagreed by up to **51 %** on 43-byte rows, though each reported about 1 % RME.
The 1 MiB rows agreed within about 10 %. Even in fresh processes, the short-input rows still vary
by up to ±21 % from process to process: the JIT does not always reach the same code. The "runs ±"
column shows this. **For short inputs, quote ranges, not single figures.**

**Inputs** (`bench/inputs.mjs`), all fixed:
- *short*: the 43-byte ASCII string `"The quick brown fox jumps over the lazy dog"`.
- *1 MiB*: 1,048,576 xorshift32 bytes (fixed seed). Passed as a WordArray to crypto-js and the
  compat API, and as a `Uint8Array` to the modern API.
- *1 MiB text* (Utf8 rows): exactly 1 MiB of UTF-8, mostly ASCII, with 2-, 3- and 4-byte
  sequences.
- *keys*: AES key 32 bytes, IV 16 bytes, PBKDF2 salt 16 bytes, password
  `"correct horse battery staple"`.

Hash rows include `.toString()` (hex), the usual call. On Node, modern `encrypt`/`decrypt` use
Web Crypto. The "noble path" rows hide `globalThis.crypto.subtle`, so the same build takes its
pure-JS route, which is what React Native runs.

**Size [size].** esbuild 0.28.2 bundles each import as a consumer would: `bundle`, `minify`,
ESM, platform `browser`, target es2020. `cryptolite` resolves through package.json `"exports"` by
self-reference, so `dist/` and `"sideEffects": false` apply exactly as for an installed copy.

Columns:
- **min**: legal comments removed (webpack/terser extract them to a separate file by default).
- **gzip**: level 9. **brotli**: quality 11, text mode.
- **+ legal comments**: extra bytes when they are kept, which is esbuild's default for bundles.

Every bundle is **executed** with Node and its output checked, so a bundle that silently lost
code cannot look small. "Compat layer in output?" looks for three strings that exist only in
`src/compat`; the script fails if any of them has disappeared from dist.

**Hermes [hermes].** The pipeline mirrors a React Native release build of app code:
1. esbuild bundles `bench/hermes-entry.mjs` + `dist/index.js` + crypto-js into an IIFE, with
   Metro-like resolution.
2. Babel applies `@react-native/babel-preset` with profile `default`. Hermes 0.12 cannot parse
   `class`/`async`, and the preset's default profile now targets Hermes V1, which keeps them.
3. `hermesc -O` compiles to bytecode, then `hermes` runs it.

Times are `Date.now()` wall times; Hermes 0.12 has no `performance`. PBKDF2 results are checked
against Node's `crypto.pbkdf2Sync`, and every token made on Hermes is decrypted on Node.
`getRandomValues` is a deterministic benchmark-only stand-in, since the Hermes CLI has no RNG.
It is 28 bytes per `encrypt`, negligible.

## 1. Speed on Node 20 — crypto-js 4.2.0 vs cryptolite [run]

Isolated processes, 5 runs per (case, library). Cells read `median ops/s (within-run RME of the
median run, runs ±half-range)`.

*Generated by the command above; copied verbatim from `bench/raw/run.md`.*

### Compat API (same call on both libraries)

| Case | crypto-js ops/s | cryptolite ops/s | crypto-js time/op | cryptolite time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|
| MD5 short (43 B string) | 135,999 (±0.6%, runs ±14%) | 187,273 (±1.3%, runs ±21%) | 7.35 µs | 5.34 µs | 1.38× (1.21–1.79) |
| SHA1 short (43 B string) | 137,943 (±0.8%, runs ±16%) | 181,972 (±1.3%, runs ±1%) | 7.25 µs | 5.50 µs | 1.32× (1.23–1.73) |
| SHA256 short (43 B string) | 130,940 (±0.7%, runs ±1%) | 159,607 (±1.5%, runs ±15%) | 7.64 µs | 6.27 µs | 1.23× (1.15–1.49) |
| SHA512 short (43 B string) | 27,944 (±1.2%, runs ±2%) | 97,158 (±1.6%, runs ±8%) | 35.8 µs | 10.3 µs | 3.51× (3.47–3.92) |
| SHA3 short (43 B string) | 14,398 (±0.7%, runs ±7%) | 55,724 (±0.8%, runs ±7%) | 69.5 µs | 17.9 µs | 4.06× (3.42–4.33) |
| MD5 1 MiB (WordArray) | 27.6 (±1.7%, runs ±4%) | 53.7 (±0.8%, runs ±3%) | 36.2 ms | 18.6 ms | 1.95× (1.88–2.05) |
| SHA1 1 MiB (WordArray) | 43.9 (±1.9%, runs ±5%) | 54.5 (±1.2%, runs ±4%) | 22.8 ms | 18.4 ms | 1.25× (1.21–1.29) |
| SHA256 1 MiB (WordArray) | 38.9 (±3.8%, runs ±4%) | 54 (±1.7%, runs ±2%) | 25.7 ms | 18.5 ms | 1.38× (1.30–1.43) |
| SHA512 1 MiB (WordArray) | 5.7 (±1.2%, runs ±3%) | 31.2 (±1.1%, runs ±4%) | 176 ms | 32.0 ms | 5.47× (5.46–5.64) |
| SHA3 1 MiB (WordArray) | 1.31 (±0.6%, runs ±3%) | 5.88 (±0.6%, runs ±2%) | 763 ms | 170 ms | 4.44× (4.22–4.65) |
| SHA256 progressive: create() + 16 × 64 KiB update() + finalize() — *before the O5 fix* | 45.9 (±2.4%, runs ±2%) | 25 (±2.1%, runs ±3%) | 21.8 ms | 40.0 ms | 0.540× (0.525–0.560) |
| SHA256 progressive — **after the O5 fix** (re-run, `--filter progressive --runs 5`, `bench/raw/progressive-after-o5.json`) | 45.8 (±2.7%, runs ±4%) | 52.5 (±1.3%, runs ±4%) | 21.8 ms | 19.0 ms | 1.15× (1.10–1.18) |
| HmacSHA256 short | 23,259 (±1.6%, runs ±2%) | 57,770 (±1.5%, runs ±16%) | 43.0 µs | 17.3 µs | 2.46× (2.32–3.05) |
| PBKDF2 SHA256, 10k iterations, keySize 8 | 7.47 (±3.8%, runs ±4%) | 33.1 (±0.9%, runs ±4%) | 134 ms | 30.3 ms | 4.50× (4.27–4.65) |
| PBKDF2 crypto-js 4.2 defaults (SHA256, 250k, keySize 4) | 0.296 (±7.6% (!), runs ±5%) | 1.3 (±7.9% (!), runs ±3%) | 3.38 s | 771 ms | 4.39× (4.35–4.98) |
| AES passphrase encrypt + toString (short) | 4,275 (±2.4%, runs ±6%) | 5,404 (±2.2%, runs ±5%) | 234 µs | 185 µs | 1.22× (1.17–1.36) |
| AES passphrase decrypt + toString(Utf8) (short) | 5,619 (±2.0%, runs ±2%) | 6,786 (±2.0%, runs ±1%) | 178 µs | 147 µs | 1.20× (1.20–1.23) |
| AES-256-CBC key+iv encrypt 1 MiB | 22.8 (±1.9%, runs ±4%) | 29.1 (±2.3%, runs ±4%) | 43.8 ms | 34.3 ms | 1.29× (1.24–1.35) |
| AES-256-CBC key+iv decrypt 1 MiB | 22.8 (±1.5%, runs ±4%) | 25.7 (±1.1%, runs ±7%) | 43.9 ms | 39.0 ms | 1.13× (1.00–1.18) |
| Base64 stringify 1 MiB | 10.4 (±2.7%, runs ±9%) | 12.4 (±5.0%, runs ±1%) | 96.0 ms | 80.8 ms | 1.19× (1.03–1.25) |
| Base64 parse 1 MiB | 51.5 (±2.8%, runs ±5%) | 50.5 (±2.7%, runs ±4%) | 19.4 ms | 19.8 ms | 0.965× (0.955–1.05) |
| Utf8 parse 1 MiB | 21 (±2.1%, runs ±4%) | 188 (±2.4%, runs ±7%) | 47.6 ms | 5.33 ms | 9.14× (7.88–9.31) |
| Utf8 stringify 1 MiB | 11.8 (±1.6%, runs ±4%) | 147 (±2.2%, runs ±4%) | 84.5 ms | 6.81 ms | 12.4× (11.8–13.4) |

### Modern API

| Case | crypto-js ops/s | cryptolite ops/s | crypto-js time/op | cryptolite time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|
| encrypt() short, Web Crypto path, 600k iterations | – | 7.94 (±1.8%, runs ±1%) | – | 126 ms | – |
| decrypt() short, Web Crypto path, 600k iterations | – | 7.88 (±1.4%, runs ±2%) | – | 127 ms | – |
| sha256() short (43 B string) | 132,842 (±0.7%, runs ±3%) | 156,683 (±1.1%, runs ±14%) | 7.53 µs | 6.38 µs | 1.20× (1.15–1.47) |
| sha256() 1 MiB (Uint8Array; crypto-js: WordArray) | 40.7 (±2.2%, runs ±4%) | 59.3 (±1.5%, runs ±4%) | 24.6 ms | 16.9 ms | 1.46× (1.36–1.57) |

### Supplementary

| Case | crypto-js ops/s | cryptolite ops/s | cryptolite modern ops/s | crypto-js time/op | cryptolite time/op | cryptolite modern time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|--:|--:|
| encrypt() short, noble path (crypto.subtle hidden), 600k | – | 0.474 (±1.9%, runs ±4%) | – | – | 2.11 s | – | – |
| decrypt() short, noble path (crypto.subtle hidden), 600k | – | 0.47 (±1.3%, runs ±3%) | – | – | 2.13 s | – | – |
| compat PBKDF2 SHA256, 600k, keySize 8 (sync noble) | – | 0.547 (±1.9%, runs ±2%) | – | – | 1.83 s | – | – |
| SHA256 of the 1 MiB UTF-8 text as a string | 13.3 (±1.9%, runs ±3%) | 51.5 (±1.1%, runs ±2%) | 41.2 (±1.4%, runs ±21%) | 75.4 ms | 19.4 ms | 24.3 ms | cryptolite: 3.88× (3.77–3.92); cryptolite modern: 3.11× (2.04–3.22) |

(isolated, 5 run(s) per case; dist/index.js sha256 6e74d9b7f415; load average 1m: 0.46 at start, 1.18 at end)

**Reading the table**
- The compat API is faster than crypto-js in 20 of 22 rows:
  - Utf8 parse/stringify: 9–12×
  - SHA-512 and SHA3: 3.5–5.5×
  - PBKDF2: 4.4–4.5×
  - HmacSHA256: about 2.5×
  - MD5 1 MiB: about 2×
  - SHA-1/SHA-256 on 1 MiB: 1.25–1.4×
  - Short MD5/SHA-1/SHA-256: 1.2–1.4×, with wide run-to-run ranges
  - AES (passphrase and key+IV): 1.1–1.3×
  - Base64: 1.0–1.2×
- **Two rows are not faster:**
  - **Base64 parse** is at parity (0.97×, range 0.96–1.05).
  - **Progressive SHA-256 is slower: 0.54×** (40.0 ms vs 21.8 ms; range 0.53–0.56 over 5
    runs). This path changed in `f7442a1` (D14). It is bimodal from process to process: running
    the same child directly gave ~26 ms in 3 of 4 tries and 40.5 ms in one (one-off check, not
    in `bench/raw/`). Either way it is never faster than crypto-js, unlike the one-shot call on
    the same bytes (1.38×). crypto-js measured 21.8 ms here and 23–32 ms in one-off standalone
    scripts. See Opportunity O5.
- PBKDF2 at crypto-js 4.2's defaults (SHA-256, 250k iterations) takes **3.38 s per call in
  crypto-js vs 0.77 s in cryptolite** (n = 3 per run, so RME is 7–8 %, marked).
- Modern `encrypt`/`decrypt` at the 600k default: **126 ms / 127 ms** via Web Crypto. This
  reproduces D10's "128 ms".
- The same build's pure-JS (noble) path takes **2.11 s / 2.13 s**, and a synchronous PBKDF2 at
  600k takes **1.83 s**. D10's "1,644 ms" is **not** reproduced here; the current README's
  "order of 1.6 seconds" (Workers fallback) should cite these numbers or be re-measured.
- The *Supplementary* rows were not in the brief; they support O4, O8 and the README notes.
  Hashing a 1 MiB **string** is 3.9× faster than crypto-js through the compat API but 3.1× through
  modern `sha256(string)`. The modern API encodes UTF-8 in pure JS on purpose (no
  `TextEncoder`, for Hermes), which costs about 5 ms per MiB.

## 2. Bundle size [size]

*Generated by the command above; copied verbatim from `bench/raw/size.md`.*

| Import | min | min + gzip | min + brotli | + legal comments (esbuild default) | compat layer in output? |
|---|--:|--:|--:|--:|---|
| **Whole library** | | | | | |
| import CryptoJS from 'crypto-js' | 69.5 KiB (71,219 B) | 25.5 KiB | 20.8 KiB | +1,589 B | n/a |
| import CryptoJS from 'cryptolite' | 76.0 KiB (77,827 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| **One hash, crypto-js style** | | | | | |
| import sha256 from 'crypto-js/sha256' | 6.3 KiB (6,418 B) | 2.6 KiB | 2.4 KiB | +0 B | n/a |
| import sha256 from 'cryptolite/sha256' | 76.0 KiB (77,823 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| import { SHA256 } from 'cryptolite' | 76.0 KiB (77,801 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| **AES via subpaths (extra)** | | | | | |
| import AES from 'crypto-js/aes' + Utf8 from 'crypto-js/enc-utf8' | 18.4 KiB (18,836 B) | 6.6 KiB | 5.7 KiB | +0 B | n/a |
| import AES from 'cryptolite/aes' + Utf8 from 'cryptolite/enc-utf8' | 76.0 KiB (77,867 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| **Modern API only** | | | | | |
| import { sha256 } from 'cryptolite' | 76.0 KiB (77,801 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| import { encrypt, decrypt } from 'cryptolite' | 76.0 KiB (77,830 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| **Diagnosis: dist/index.js minus `Object.assign(compat_default, modern_exports)` and `__export(modern_exports, {...})`** | | | | | |
| { sha256 } from patched dist | 62.1 KiB (63,610 B) | 22.4 KiB | 19.1 KiB | +4,049 B | yes (3/3 markers) |
| { encrypt, decrypt } from patched dist | 73.9 KiB (75,625 B) | 26.7 KiB | 22.7 KiB | +4,049 B | yes (3/3 markers) |
| **Hypothetical entries (built from src/ like tsup.config.ts; not shipped)** | | | | | |
| `cryptolite/modern` (= src/modern/index.ts): { sha256 } | 9.6 KiB (9,795 B) | 4.2 KiB | 3.8 KiB | +136 B | no |
| `cryptolite/modern` (= src/modern/index.ts): { encrypt, decrypt } | 33.1 KiB (33,939 B) | 12.5 KiB | 11.1 KiB | +136 B | no |
| split `cryptolite/sha256` (= src/compat core.ts + hashers.ts) | 30.3 KiB (31,012 B) | 11.5 KiB | 10.0 KiB | +0 B | yes (2/3 markers) |
| compat object without the modern API (= src/compat/index.ts) | 58.4 KiB (59,790 B) | 21.0 KiB | 17.9 KiB | +136 B | yes (3/3 markers) |

Extra bytes a modern-only import pays for importing from the package root (root minus hypothetical `cryptolite/modern`):
- { sha256 }: 68,006 B min / 23,713 B gzip / 20,092 B brotli
- { encrypt, decrypt }: 43,891 B min / 15,287 B gzip / 12,613 B brotli
Removing those two statements from dist (diagnosis) saves:
- { sha256 }: 14,191 B min / 5,133 B gzip / 4,405 B brotli
- { encrypt, decrypt }: 2,205 B min / 709 B gzip / 668 B brotli
cryptolite/sha256 minus crypto-js/sha256: 71,405 B min / 25,351 B gzip / 21,488 B brotli

**Findings**
- **Whole library:** cryptolite is 77,827 B min vs 71,219 B for crypto-js (+9 %). That is
  27.4 vs 25.5 KiB gzip and 23.4 vs 20.8 KiB brotli. cryptolite is larger even though it ships
  stubs instead of DES/TripleDES/RC4/Rabbit/Blowfish. Kept legal comments add 4,049 B per bundle
  (crypto-js: 1,589 B).
- **Subpath imports do not get smaller.** `cryptolite/sha256` is the whole library: 77,823 B vs
  6,418 B for `crypto-js/sha256` (12.1×; gzip 27.4 vs 2.6 KiB). AES + Utf8 via subpaths: 77,867 B
  vs 18,836 B (4.1×).
- **Tree-shaking does not remove the compat layer for modern-only imports.**
  `import { sha256 } from 'cryptolite'` bundles 77,801 B where 9,795 B would do, and
  `{ encrypt, decrypt }` bundles 77,830 B where 33,939 B would do. All three compat-only marker
  strings are present in both bundles. The cause and the fix are in O2 and O3.

## 3. React Native engine: Hermes [hermes]

A Hermes VM binary *is* obtainable from npm: `hermes-engine-cli@0.12.0` (published Aug 2022;
ships `hermes`/`hermesc` for Linux, macOS and Windows; the Linux `hermes` is statically linked).
That is the newest VM on npm that I found. The `hermes-compiler` package (checked
260318099.0.4) ships only `hermesc`, the compiler, not a VM. Current React Native ships
**Hermes V1**, which this does **not** measure.

*Generated by the command above; copied verbatim from `bench/raw/hermes.md`.*

| Case | Library | samples (wall time each) | mean |
|---|---|---|--:|
| PBKDF2 SHA256 10k, keySize 8 (compat call) | crypto-js | 1.37 s, 1.35 s, 1.35 s | 1.36 s |
| PBKDF2 SHA256 10k, keySize 8 (compat call) | cryptolite | 1.18 s, 1.18 s, 1.18 s | 1.18 s |
| encrypt() short, 100k iterations (lowest allowed), noble path | cryptolite | 12.24 s, 12.29 s, 12.27 s | 12.27 s |
| PBKDF2 SHA256 600k, keySize 8 (compat call, sync noble) | cryptolite | 72.94 s, 73.28 s | 73.11 s |
| encrypt() short, default 600k iterations, noble path | cryptolite | 73.95 s, 74.36 s | 74.15 s |
| decrypt() short, 600k iterations, noble path | cryptolite | 73.35 s, 72.77 s | 73.06 s |

(engine probe: {"engine":"hermes","textEncoder":"undefined","subtle":"undefined"})

- **PBKDF2-SHA256 at 600k on Hermes 0.12: 73–74 s per call.** That holds for synchronous noble,
  modern `encrypt()` and `decrypt()` alike, about **40× the 1.83 s on Node/V8** on the same CPU.
  At the lowest iteration count `encrypt` accepts (100k), it takes **12.3 s**.
- cryptolite's PBKDF2 lead over crypto-js nearly disappears on Hermes: **1.15×** at 10k (1.18 s
  vs 1.36 s), against 4.5× on V8.
- `pbkdf2Async`'s yields cost about 1.4 % in the Hermes CLI (74.15 s vs 73.11 s) and about 15 % on
  Node (2.11 s vs 1.83 s).
- *Unverified:* real phones (per-core speed relative to this server CPU not measured), Hermes V1,
  and React Native's timer latency. noble yields with `setTimeout(0)` every 10 ms of work, and the CLI does
  not model RN's timers.

## Opportunities

These are ordered by measured impact. Each one names who has to decide; nothing in `src/` was
changed. The experiment numbers come from modified *copies* or prototypes and are estimates of
the gain, not product numbers.

### O1. esbuild turns noble's top-level `const` into `var`, which costs up to 1.6× on hashing — [exp: esbuild-const]
esbuild's bundler rewrites top-level `const` declarations as `var`, at every target including
esnext. noble's hot loops read module-level tables (`SHA256_W`, `SHA256_K`, `SHA512_Kh`, the
Keccak rotation tables, ...). As `var`, V8 can no longer treat them as constants.

The experiment takes a temp copy of the shipped `dist/index.js` and turns back to `const` the 109
declarations that noble's own sources declare `const` and that are never reassigned. Outputs are
identical. Measured gains (median of 3 fresh processes each):

| Operation | shipped | consts restored | gain |
|---|--:|--:|--:|
| SHA256 1 MiB (compat) | 55.4 ops/s | 86.1 ops/s | 1.55× |
| `sha256()` 1 MiB (modern) | 61.8 | 101 | 1.63× |
| SHA512 1 MiB | 31.0 | 50.5 | 1.63× |
| SHA3 1 MiB | 5.86 | 6.78 | 1.16× |
| PBKDF2 SHA256 10k | 32.6 | 44.3 | 1.36× |
| AES-256-CBC encrypt 1 MiB | 28.9 | 29.7 | 1.03× (no gain) |
| SHA256 short | 167,246 | 157,751 | 0.94× (noise) |

Separately, bundling only `@noble/hashes/sha2.js` with esbuild turns noble's own 9.5–9.9 ms per
1 MiB into 15.0–15.7 ms. Restoring 3 consts in that bundle brings it back to 8.6–9.2 ms. That was
a one-off scratch script, not in `bench/`; the experiment above is the reproducible evidence.

A 1.36× PBKDF2 gain would cut the Node pure-JS path at 600k from about 1.83 s to about 1.35 s.
That is an estimate; Workers is not measured. Hermes is likely unaffected, because Metro's Babel
lowers `const` to `var` anyway (*unverified*).

**Proposal (packaging lane / tech-lead):** emit the runtime bundles with a bundler that preserves
`const`. Rollup is already a devDependency. Alternatively, an explicitly tested post-build step.
Report it to esbuild as well. Re-run `bench/run.mjs` to confirm.

### O2. Modern-only imports carry the whole compat layer — [size], [exp: pure-annotations]
`dist/index.js` is one flat module. Two kinds of top-level statements keep everything alive:

1. `import * as modern` + `Object.assign(CryptoJS, modern)` in `src/index.ts` compile to
   `__export(modern_exports, {...})` and `Object.assign(...)`. These retain every modern
   function. The diagnosis copy of dist without just these two statements saves 14,191 B min
   (5,133 B gzip) on `{ sha256 }`.
2. Every compat registration (`C.SHA256 = hashHelper(...)`, `C_algo.MD5 = ...`) is a side
   effect. The named compat exports (`export const SHA256 = CryptoJS.SHA256`) are property reads,
   which esbuild and Rollup also treat as side effects. This is the remaining ~54 KB.

`"sideEffects": false` cannot help here: it only drops *whole modules*.

Options, cheapest first:
- **(a) Add a `cryptolite/modern` entry** (ESM+CJS) built from `src/modern/index.ts`: measured
  9,795 B for `{ sha256 }` and 33,939 B for `{ encrypt, decrypt }`, vs 77.8 KB today. This is
  additive and leaves the root unchanged.
- **(b) Make the root ESM entry tree-shakeable.** Attach the modern API only in the CJS entry
  (`scripts/cjs-entry.cts`), build the compat object in one function called as
  `/* @__PURE__ */ build()`, and write the named compat exports as `/* @__PURE__ */ (() =>
  CryptoJS.SHA256)()`. On a synthetic module this pattern lets both esbuild 0.28.2 and Rollup
  4.65.0 drop compat entirely. The factory alone (without the pure IIFEs) does not; webpack was
  not tested.
  - Side effect: the ESM default object would lose `encrypt`, `sha256`, ... . SPEC-modern only
    promises those on the CommonJS object, but it is a visible change.

Decision: tech-lead (public entry points and exports map).

### O3. Subpath imports are 4–12× larger than crypto-js's — [size]
Each `dist/<name>.js` shim imports `./index.js`, so `cryptolite/sha256` weighs the same as the
whole library: 77,823 B vs 6,418 B. crypto-js users who imported subpaths to stay small get a
regression.

A split build would fix this: ESM entries per subpath with esbuild/Rollup code splitting, sharing
a core chunk so there is still exactly one `CryptoJS` object, like crypto-js's own modules.
Measured estimate: core.ts + hashers.ts = 31,012 B (11.5 KiB gzip). That is still 4.8× crypto-js,
because `hashers.ts` imports every noble hash family. Splitting hashers per algorithm would go
further (*not measured*).

CJS subpaths would need a shared `core.cjs`, or could stay whole. Decision: tech-lead
(architecture of the build and the shared-object guarantee).

### O4. The 600k default on React Native means over a minute per `encrypt`/`decrypt` — [hermes]
On Hermes 0.12 it takes 73–74 s on this CPU, and 12.3 s at the 100k minimum. That is not a code
inefficiency: it is noble's PBKDF2 speed in a JIT-less interpreter. D10 keeps 600k everywhere on
purpose, and the README calls RN "noticeably slower". The measured magnitude is likely to change
that conversation.

Options that are not mine to pick:
- a pluggable native PBKDF2 provider for RN
- louder docs with these numbers
- re-measuring on Hermes V1 and on a device before release

Decision: product-owner + tech-lead (security parameter vs usability), with this data in D10.

### O5. Progressive hashing got slower than crypto-js in `f7442a1` — [run], [exp: profile], [exp: encoders]

**Status: fixed by the lead** — clean updates now stream into noble's own `update()`; word mode is entered only for unusual input or at `finalize()`. Re-measured: 1.15× crypto-js (row above).
`create()` + 16 × 64 KiB `update()` + `finalize()` runs at **0.54×** crypto-js in the benchmark
(26–40 ms per process vs 22–32 ms for crypto-js; ranges include one-off checks, see section 1).
The profile:
- 52 % in noble `process()` per 64-byte block, fed one block at a time through a `DataView`
  (`MDHasher._doProcessBlock`)
- 19 % in crypto-js's own `concat` buffering
- 12 % in `_process`

A prototype that feeds clean chunks to noble's streaming `update()` runs in **12.4 ms**,
about 1.8–2.6× crypto-js, with an identical digest. That is only exact while every update is
"clean" (D14's gate), so it needs a fall-back once an unclean update arrives. A cheaper partial
fix is to process all ready blocks of one `_process` call through a single reused view
(*not measured*).

Decision: tech-lead (complexity vs D14's exactness guarantee).

### O6. Class-field lowering (target es2020) costs 20–45 % on short hashes and HMAC — [exp: target-es2022], [exp: profile]
`__defNormalProp`, esbuild's helper for the 91 lowered class fields, is about 15 % of the self
time of `CryptoJS.SHA256(short)`. The experiment rebuilds src exactly like tsup.config.ts.

Median ops/s, 3 processes each:

| Call | es2020 rebuild | es2022 rebuild |
|---|--:|--:|
| `CryptoJS.SHA256(short)` | 179,718 | 256,514 |
| `sha256(short)` | 145,083 | 173,733 |
| `HmacSHA256(short)` | 58,852 | 79,504 |
| AES passphrase decrypt | 7,045 | 6,707 (no change) |

1 MiB SHA-256 rows were unchanged, at 16–17 ms modern and 18–20 ms compat for both targets (one-off
scratch check, not in `bench/`). The trade-off is syntax: class fields in dist would not parse in old
toolchains such as webpack 4 (acorn < 8). Metro's Babel lowers them anyway.

Decision: tech-lead / packaging (support matrix). Low priority next to O1–O3.

### O7. Base64 encode/decode are only at crypto-js speed — [exp: profile], [exp: encoders]
- **`Base64.stringify(1 MiB)`** spends 76 % of its time in GC, from `out +=` per character.
  Writing char codes into a `Uint16Array` and converting in 32K chunks takes 30.5–31.2 ms instead
  of 73–80 ms (≈2.5×), with identical output.
- **`Base64.parse(1 MiB)`** is crypto-js's verbatim loop, with 81 % of its time in `parseLoop`. A
  4-chars → 3-bytes decoder over a reverse table takes 6.6–8.5 ms instead of 17.7–18.9 ms (≈2.4×)
  on valid input. It falls back to the verbatim loop on any character outside the alphabet, so
  crypto-js's lenient parsing is kept.

Owner: compat lane. Base64 matters because `CipherParams#toString()` and every passphrase
ciphertext go through it.

### O8. `pbkdf2Async` yields cost 15 % on Node — [run]
The noble-path `encrypt` takes 2.11 s vs 1.83 s for a synchronous PBKDF2 of the same cost. noble
yields every 10 ms (`asyncTick`) via `setTimeout(0)`, which costs at least 1 ms each in Node. A
larger `asyncTick` (e.g. 50 ms) would trade UI responsiveness for about 12 % of that time
(*estimate*). On RN the timer cost may be larger (*unverified*).

Decision: tech-lead.

### O9. License banner: +4,049 B per bundle where legal comments are kept — [size]
That is three full MIT texts, vs 1,589 B for crypto-js. A one-line `/*!` pointer to the LICENSE
file would save about 4 KB. Whether that satisfies the notice requirement is a licensing call for
the owner, not a performance one.

**Not worth pursuing now:** AES. noble's cipher is 65–70 % of the profile, and noble's own CBC
takes 27.3 ms per MiB under the profiler vs 34–39 ms through the compat layer, so at most about
20 % is left to gain.

## Numbers suitable for the README

Quote with the machine line ("AMD EPYC 7713 VM, Node 20.19.2") and a link to this file:

- Compat API vs crypto-js, same calls and identical output: **4.4–4.5× faster PBKDF2**,
  **3.5–5.5× SHA-512/SHA3**, **9–12× UTF-8**, **1.1–1.4× SHA-1/SHA-256/AES**; **Base64 about
  equal**; progressive (`update()`) SHA-256 **1.15×** after the O5 fix (0.54× before it).
- PBKDF2 at crypto-js's defaults (250k): 3.4 s → 0.77 s per call.
- Modern `encrypt`/`decrypt` (600k): about 126 ms with Web Crypto (Node). About 2.1 s pure JS on
  Node; **about 74 s on Hermes 0.12** (12 s at 100k).
- Bundle: whole library 76.0 KiB min / 27.4 KiB gzip (crypto-js 69.5 / 25.5). Every import
  currently costs the whole library, including `cryptolite/sha256` and modern-only imports.

Short-input figures (43 B) vary ±20 % between processes; quote them as ranges if at all.

## Not measured

- Browsers, Deno, Bun, Cloudflare Workers, Node 22/24.
- Hermes V1 and any real device.
- webpack (for tree-shaking).
- Memory use.
- Cold start / module evaluation time.

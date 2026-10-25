// Runs inside the Hermes VM (bundled, Babel-transformed and compiled by bench/hermes.mjs).
// Prints one JSON line per measurement with Hermes's `print`. Times are Date.now() deltas
// (Hermes 0.12 has no `performance`), which is fine for runs of a second or more.
//
// __BENCH__ is injected at build time: { samples, known } where `known` holds PBKDF2 results
// computed by Node's own crypto, so every Hermes result is checked before it is reported.
/* global __BENCH__, print */
import CryptoJS from 'crypto-js';
import Cryptolite, { decrypt, encrypt } from 'cryptolite';
import { PASSWORD, SALT_HEX, SHORT } from './inputs.mjs';

// Hermes has no crypto.getRandomValues (React Native apps add react-native-get-random-values).
// BENCHMARK-ONLY stand-in, NOT secure: deterministic bytes. encrypt() draws 28 bytes per call,
// so its cost is negligible next to PBKDF2.
let seed = 0x9e3779b9;
globalThis.crypto = {
  getRandomValues(array) {
    for (let i = 0; i < array.length; i++) {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      array[i] = seed >>> 24;
    }
    return array;
  },
};

const config = __BENCH__;
const emit = (record) => print(JSON.stringify(record));

function check(name, actual, expected) {
  if (actual !== expected) throw new Error(`${name}: got ${actual}, expected ${expected}`);
}

async function timeIt(name, label, n, fn, verify) {
  const ms = [];
  let last;
  for (let i = 0; i < n; i++) {
    const t0 = Date.now();
    last = await fn();
    ms.push(Date.now() - t0);
  }
  const extra = verify(last);
  emit({ name, label, ms, ...extra });
}

const pbkdf2 = (X, iterations) =>
  X.PBKDF2(PASSWORD, X.enc.Hex.parse(SALT_HEX), { keySize: 8, iterations, hasher: X.algo.SHA256 }).toString();

async function main() {
  const { samples, known } = config;
  emit({ engine: typeof HermesInternal === 'object' ? 'hermes' : 'unknown', textEncoder: typeof TextEncoder, subtle: typeof (globalThis.crypto && globalThis.crypto.subtle) });

  // Warm-up (no JIT on Hermes, but keeps first-call effects out of the samples).
  pbkdf2(Cryptolite, 1000);
  pbkdf2(CryptoJS, 1000);

  await timeIt('PBKDF2 SHA256 10k, keySize 8 (compat call)', 'crypto-js', samples.small, () => pbkdf2(CryptoJS, 10000), (r) => {
    check('crypto-js PBKDF2 10k', r, known.pbkdf2_10k);
    return {};
  });
  await timeIt('PBKDF2 SHA256 10k, keySize 8 (compat call)', 'cryptolite', samples.small, () => pbkdf2(Cryptolite, 10000), (r) => {
    check('cryptolite PBKDF2 10k', r, known.pbkdf2_10k);
    return {};
  });
  await timeIt('encrypt() short, 100k iterations (lowest allowed), noble path', 'cryptolite', samples.small, () => encrypt(SHORT, PASSWORD, { iterations: 100000 }), (token) => ({ token }));
  await timeIt('PBKDF2 SHA256 600k, keySize 8 (compat call, sync noble)', 'cryptolite', samples.large, () => pbkdf2(Cryptolite, 600000), (r) => {
    check('cryptolite PBKDF2 600k', r, known.pbkdf2_600k);
    return {};
  });
  let token;
  await timeIt('encrypt() short, default 600k iterations, noble path', 'cryptolite', samples.large, () => encrypt(SHORT, PASSWORD), (t) => {
    token = t;
    return { token: t };
  });
  await timeIt('decrypt() short, 600k iterations, noble path', 'cryptolite', samples.large, () => decrypt(token, PASSWORD), (p) => {
    check('decrypt', p, SHORT);
    return {};
  });
  emit({ done: true });
}

main().catch((e) => emit({ error: String((e && e.stack) || e) }));

// Collects facts about the CommonJS side of an installed cryptolite, for test/package/*.test.ts.
// Runs in a plain Node child process so resolution is Node's own (exports map, require condition).
//
// usage: node runtime-facts.cjs <package specifier>   (e.g. cryptolite, or crypto-js when aliased)
// env:   SUBPATHS_JSON  scripts/subpaths.mjs SUBPATHS as JSON
//        VECTORS_JSON   expected values computed with the real crypto-js
'use strict';

const spec = process.argv[2];
const subpaths = JSON.parse(process.env.SUBPATHS_JSON);
const vectors = JSON.parse(process.env.VECTORS_JSON);
const resolvePath = (obj, p) => (p === '' ? obj : p.split('.').reduce((v, k) => (v == null ? undefined : v[k]), obj));
const attempt = (fn) => {
  try {
    return fn();
  } catch (error) {
    return `threw ${error && (error.code || error.name)}: ${error && error.message}`;
  }
};

const root = require(spec);
const facts = {
  resolved: require.resolve(spec),
  type: typeof root,
  ownEsModule: Object.prototype.hasOwnProperty.call(root, '__esModule'),
  hasDefault: 'default' in root,
  keys: Object.keys(root),
  undefinedMembers: Object.keys(root).filter((k) => root[k] === undefined),
  subpaths: {},
  behaviour: {},
};

for (const { name, path } of subpaths) {
  for (const specifier of [`${spec}/${name}`, `${spec}/${name}.js`]) {
    facts.subpaths[specifier] = attempt(() => {
      const value = require(specifier);
      const expected = resolvePath(root, path);
      if (value === undefined) return 'undefined';
      if (expected === undefined) return 'expected value is undefined';
      return value === expected ? 'same' : 'different';
    });
  }
}

const { AES, enc, SHA256, HmacSHA256, PBKDF2, lib } = require(spec);
const b = facts.behaviour;
b.sha256 = attempt(() => SHA256('abc').toString());
b.sha256Subpath = attempt(() => require(`${spec}/sha256`)('abc').toString());
b.hmacSha256 = attempt(() => HmacSHA256('message', 'key').toString());
b.hmacSubpath = attempt(() => require(`${spec}/hmac-sha256`)('message', 'key').toString(require(`${spec}/enc-base64`)));
b.pbkdf2 = attempt(() => PBKDF2('password', 'salt', { keySize: 8, iterations: 1000 }).toString());
b.base64 = attempt(() => enc.Base64.stringify(enc.Utf8.parse('hello')));
b.randomSigBytes = attempt(() => lib.WordArray.random(16).sigBytes);
b.decryptCryptoJsCiphertext = attempt(() => AES.decrypt(vectors.aesCiphertext, vectors.password).toString(enc.Utf8));
b.decryptViaSubpaths = attempt(() =>
  require(`${spec}/aes`).decrypt(vectors.aesCiphertext, vectors.password).toString(require(`${spec}/enc-utf8`)),
);
b.aesRoundTrip = attempt(() => AES.decrypt(AES.encrypt('round trip', 'pw').toString(), 'pw').toString(enc.Utf8));
b.modernAttached = typeof root.encrypt === 'function' && typeof root.CryptoliteError === 'function';

process.stdout.write(JSON.stringify(facts));

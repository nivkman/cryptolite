// Collects facts about the ESM side of an installed cryptolite, for test/package/*.test.ts.
// Runs in a plain Node child process so resolution is Node's own (exports map, import condition).
//
// usage: node runtime-facts.mjs <package specifier>   (e.g. cryptolite, or crypto-js when aliased)
// env:   SUBPATHS_JSON  scripts/subpaths.mjs SUBPATHS as JSON
//        VECTORS_JSON   expected values computed with the real crypto-js
const spec = process.argv[2];
const subpaths = JSON.parse(process.env.SUBPATHS_JSON);
const vectors = JSON.parse(process.env.VECTORS_JSON);
const resolvePath = (obj, p) => (p === '' ? obj : p.split('.').reduce((v, k) => (v == null ? undefined : v[k]), obj));
const attempt = async (fn) => {
  try {
    return await fn();
  } catch (error) {
    return `threw ${error && (error.code || error.name)}: ${error && error.message}`;
  }
};

const ns = await import(spec);
const root = ns.default;
const named = Object.keys(ns).filter((k) => k !== 'default');
const facts = {
  resolved: import.meta.resolve(spec),
  defaultType: typeof root,
  named,
  namedNotOnDefault: named.filter((k) => ns[k] !== root[k]),
  undefinedNamed: named.filter((k) => ns[k] === undefined),
  defaultKeys: Object.keys(root),
  subpaths: {},
  wholeObjectNamedExports: {},
  behaviour: {},
};

for (const { name, path } of subpaths) {
  for (const specifier of [`${spec}/${name}`, `${spec}/${name}.js`]) {
    facts.subpaths[specifier] = await attempt(async () => {
      const module = await import(specifier);
      const expected = resolvePath(root, path);
      if (module.default === undefined) return 'undefined';
      if (expected === undefined) return 'expected value is undefined';
      return module.default === expected ? 'same' : 'different';
    });
    if (path === '') {
      facts.wholeObjectNamedExports[specifier] = await attempt(async () => {
        const module = await import(specifier);
        return named.filter((k) => module[k] !== ns[k]);
      });
    }
  }
}

const b = facts.behaviour;
b.sha256 = await attempt(() => ns.SHA256('abc').toString());
b.sha256Subpath = await attempt(async () => (await import(`${spec}/sha256`)).default('abc').toString());
b.decryptCryptoJsCiphertext = await attempt(() =>
  ns.AES.decrypt(vectors.aesCiphertext, vectors.password).toString(ns.enc.Utf8),
);
b.decryptViaSubpaths = await attempt(async () => {
  const AES = (await import(`${spec}/aes.js`)).default;
  const Utf8 = (await import(`${spec}/enc-utf8.js`)).default;
  return AES.decrypt(vectors.aesCiphertext, vectors.password).toString(Utf8);
});
b.namespaceImportSha256 = await attempt(() => ns.default.SHA256('abc').toString(ns.enc.Hex));
b.modernNamed = typeof ns.encrypt === 'function' && typeof ns.CryptoliteError === 'function';

process.stdout.write(JSON.stringify(facts));

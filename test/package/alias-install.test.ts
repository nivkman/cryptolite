/*
 * The swap users make: install the packed tarball under the name `crypto-js` and run unchanged
 * crypto-js code against it.
 *
 * `npm i crypto-js@npm:cryptolite` cannot point at a local file (npm: aliases resolve from a
 * registry), so the tests use the two file-based equivalents npm offers:
 * 1. a direct dependency `"crypto-js": "file:<tgz>"` — npm installs the tarball under the
 *    dependency key, exactly like an alias (the lockfile records `"name": "cryptolite"`);
 * 2. `"overrides": { "crypto-js": "file:<tgz>" }` replacing the crypto-js that a third-party
 *    dependency declares (`"crypto-js": "^4.2.0"`) and `require`s — the zero-code-change route for
 *    transitive dependencies. The dependency is packed too: npm does not apply overrides inside
 *    `file:` directory (symlinked) dependencies. npm < 10 rejects `file:` override specs
 *    ("Invalid comparator"), so case 2 is skipped there and says so.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { collectFacts, expectCjsFacts, expectEsmFacts } from './expectations';
import { FIXTURES, npmMajor, output, parsePackJson, readJson, run, runNode, runNpm, tarball, tempDir } from './helpers';

function writeJson(file: string, value: unknown) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function install(dir: string) {
  const result = runNpm(['install', '--prefer-offline'], { cwd: dir });
  expect(result.status, output(result)).toBe(0);
}

/** Copy the runtime-facts scripts into a project, so `crypto-js` resolves from there. */
function copyFactScripts(dir: string) {
  for (const ext of ['cjs', 'mjs']) {
    fs.copyFileSync(path.join(FIXTURES, `runtime-facts.${ext}`), path.join(dir, `runtime-facts.${ext}`));
  }
}

describe('installed as crypto-js', () => {
  it('direct dependency "crypto-js": "file:<tgz>": unchanged crypto-js code runs on cryptolite', () => {
    const dir = tempDir('alias-direct');
    writeJson(path.join(dir, 'package.json'), {
      name: 'alias-direct',
      version: '0.0.0',
      private: true,
      dependencies: { 'crypto-js': `file:${tarball()}` },
    });
    install(dir);

    const installed = readJson<{ name: string; dependencies?: object }>(path.join(dir, 'node_modules/crypto-js/package.json'));
    expect(installed.name).toBe('@nivkman/cryptolite');
    expect(installed.dependencies).toBeUndefined();
    // Zero runtime dependencies: nothing but the aliased package was installed.
    expect(fs.readdirSync(path.join(dir, 'node_modules')).filter((f) => !f.startsWith('.'))).toEqual(['crypto-js']);

    // The two lines from the task, verbatim crypto-js usage.
    fs.writeFileSync(
      path.join(dir, 'app.cjs'),
      [
        "const sha256 = require('crypto-js/sha256');",
        "const AES = require('crypto-js').AES;",
        "const Utf8 = require('crypto-js/enc-utf8');",
        "const ciphertext = AES.encrypt('secret message', 'passphrase').toString();",
        "console.log(JSON.stringify({ hash: sha256('abc').toString(), plain: AES.decrypt(ciphertext, 'passphrase').toString(Utf8), salted: ciphertext.startsWith('U2FsdGVkX1') }));",
      ].join('\n'),
    );
    const app = runNode(['app.cjs'], { cwd: dir });
    expect(app.status, output(app)).toBe(0);
    expect(JSON.parse(app.stdout)).toEqual({
      hash: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      plain: 'secret message',
      salted: true,
    });

    copyFactScripts(dir);
    expectCjsFacts(collectFacts('cjs', 'crypto-js', dir, path.join(dir, 'runtime-facts.cjs')), 'crypto-js');
    expectEsmFacts(collectFacts('mjs', 'crypto-js', dir, path.join(dir, 'runtime-facts.mjs')), 'crypto-js');
  });

  const npm = npmMajor();
  it.skipIf(npm < 10)(
    `overrides replace a transitive crypto-js dependency (npm ${npm}${npm < 10 ? ': skipped, needs npm >= 10' : ''})`,
    () => {
      const dir = tempDir('alias-overrides');
      // A third-party package written for crypto-js, published as a tarball.
      const depSource = path.join(dir, 'legacy-dep-src');
      fs.mkdirSync(depSource);
      writeJson(path.join(depSource, 'package.json'), {
        name: 'legacy-dep',
        version: '1.0.0',
        main: 'index.js',
        dependencies: { 'crypto-js': '^4.2.0' },
      });
      fs.writeFileSync(
        path.join(depSource, 'index.js'),
        [
          "const sha256 = require('crypto-js/sha256');",
          "const CryptoJS = require('crypto-js');",
          "exports.impl = require('crypto-js/package.json').name;",
          "exports.hash = (s) => sha256(s).toString();",
          "exports.roundTrip = (s, k) => CryptoJS.AES.decrypt(CryptoJS.AES.encrypt(s, k).toString(), k).toString(CryptoJS.enc.Utf8);",
        ].join('\n'),
      );
      const pack = runNpm(['pack', '--json', '--pack-destination', dir], { cwd: depSource });
      expect(pack.status, output(pack)).toBe(0);
      const depTarball = path.join(dir, parsePackJson(pack.stdout)[0]!.filename);

      writeJson(path.join(dir, 'package.json'), {
        name: 'alias-overrides',
        version: '0.0.0',
        private: true,
        dependencies: { 'legacy-dep': `file:${depTarball}` },
        overrides: { 'crypto-js': `file:${tarball()}` },
      });
      install(dir);

      // No real crypto-js anywhere in the tree: every node_modules/crypto-js package is cryptolite.
      // (The pattern skips cryptolite's own legacy stub crypto-js/crypto-js/package.json.)
      const found = run('find', ['node_modules', '-path', '*node_modules/crypto-js/package.json'], { cwd: dir });
      const manifests = found.stdout.trim().split('\n').filter(Boolean);
      expect(manifests.length).toBeGreaterThan(0);
      for (const manifest of manifests) expect(readJson<{ name: string }>(path.join(dir, manifest)).name, manifest).toBe('@nivkman/cryptolite');

      const app = runNode(
        ['-e', "const d = require('legacy-dep'); console.log(JSON.stringify({ impl: d.impl, hash: d.hash('abc'), rt: d.roundTrip('hello', 'pw') }))"],
        { cwd: dir },
      );
      expect(app.status, output(app)).toBe(0);
      expect(JSON.parse(app.stdout)).toEqual({
        impl: 'cryptolite',
        hash: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        rt: 'hello',
      });
    },
  );
});

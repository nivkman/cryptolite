/*
 * Static checks of what ships: zero runtime dependencies, syntax level, module shape, license
 * notices, package.json fields, and the exact contents of the packed tarball.
 */
import fs from 'node:fs';
import path from 'node:path';
import { parse } from 'acorn';
import { describe, expect, it } from 'vitest';
import { moduleReferences } from '../../scripts/build.mjs';
import { SUBPATHS } from '../../scripts/subpaths.mjs';
import { DIST, ROOT, output, readJson, run, tarball } from './helpers';

const read = (file: string) => fs.readFileSync(path.join(DIST, file), 'utf8');

describe('dist bundles', () => {
  it('parse as ES2020 (React Native/Hermes, older bundlers): ESM as a module, CJS as a script', () => {
    expect(() => parse(read('index.js'), { ecmaVersion: 2020, sourceType: 'module' })).not.toThrow();
    expect(() => parse(read('index.cjs'), { ecmaVersion: 2020, sourceType: 'script' })).not.toThrow();
    for (const { name } of SUBPATHS) {
      if (name === 'index') continue;
      expect(() => parse(read(`${name}.js`), { ecmaVersion: 2020, sourceType: 'module' }), name).not.toThrow();
      expect(() => parse(read(`${name}.cjs`), { ecmaVersion: 2020, sourceType: 'script' }), name).not.toThrow();
    }
  });

  it('load no modules at runtime: @noble/* and everything else is bundled', () => {
    expect(moduleReferences(path.join(DIST, 'index.js'))).toEqual([]);
    expect(moduleReferences(path.join(DIST, 'index.cjs'))).toEqual([]);
  });

  it('shims only re-export the single root bundle (one copy of the code)', () => {
    for (const { name } of SUBPATHS) {
      if (name === 'index') continue;
      expect(moduleReferences(path.join(DIST, `${name}.js`)), name).toEqual(['./index.js']);
      expect(moduleReferences(path.join(DIST, `${name}.cjs`)), name).toEqual(['./index.cjs']);
      expect(fs.statSync(path.join(DIST, `${name}.js`)).size, name).toBeLessThan(400);
    }
  });

  it('CJS assigns module.exports once and has no __esModule interop flag', () => {
    const cjs = read('index.cjs');
    expect(cjs.match(/^module\.exports = /gm)).toHaveLength(1);
    expect(cjs).not.toContain('__esModule');
  });

  it('carry the MIT notices of crypto-js and the bundled @noble packages', () => {
    for (const file of ['index.js', 'index.cjs']) {
      const banner = read(file).slice(0, 8000);
      expect(banner.startsWith('/*!'), file).toBe(true);
      expect(banner).toContain('Copyright (c) 2009-2013 Jeff Mott');
      expect(banner).toContain('Copyright (c) 2013-2016 Evan Vosberg');
      expect(banner).toMatch(/@noble\/hashes \d+\.\d+\.\d+ \(bundled\)/);
      expect(banner).toMatch(/@noble\/ciphers \d+\.\d+\.\d+ \(bundled\)/);
      expect(banner).toContain('Copyright (c) 2022 Paul Miller');
    }
    expect(read('types.d.ts')).toContain('DefinitelyTyped');
    expect(read('types.d.ts')).toContain('Copyright (c) Microsoft Corporation.');
  });
});

describe('package.json', () => {
  const pkg = readJson<Record<string, unknown>>(path.join(ROOT, 'package.json'));

  it('declares zero runtime dependencies', () => {
    for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies', 'bundleDependencies']) {
      expect(pkg[field], field).toBeUndefined();
    }
  });

  it('has the required metadata', () => {
    expect(pkg).toMatchObject({
      name: 'cryptolite',
      type: 'module',
      sideEffects: false,
      license: 'MIT',
      author: 'Niv Kaufman',
      engines: { node: '>=20' },
      main: './dist/index.cjs',
      types: './dist/index.d.cts',
      repository: { type: 'git', url: 'git+https://github.com/nivkman/cryptolite.git' },
    });
    expect(pkg.description).toMatch(/drop-in replacement for .*crypto-js/i);
    expect(pkg.keywords).toEqual(
      expect.arrayContaining(['crypto-js', 'cryptojs', 'crypto', 'aes', 'sha256', 'hmac', 'pbkdf2', 'md5', 'encryption', 'hash', 'react-native', 'webcrypto', 'noble']),
    );
  });
});

describe('npm pack', () => {
  it('ships only the build, the legacy stubs and the standard files', () => {
    const list = run('tar', ['-tzf', tarball()]);
    expect(list.status, output(list)).toBe(0);
    const files = list.stdout.trim().split('\n').map((f) => f.replace(/^package\//, '')).sort();
    const stubs = new Set(SUBPATHS.map((s) => `${s.name}/package.json`));
    const unexpected = files.filter(
      (f) => !f.startsWith('dist/') && !stubs.has(f) && !/^(package\.json|README(\.md)?|LICENSE(\.md)?|CHANGELOG\.md|SECURITY\.md|MIGRATION\.md)$/i.test(f),
    );
    expect(unexpected).toEqual([]);
    for (const stub of stubs) expect(files).toContain(stub);
    for (const file of ['dist/index.js', 'dist/index.cjs', 'dist/index.d.ts', 'dist/index.d.cts', 'dist/types.d.ts', 'dist/modern.d.ts']) {
      expect(files).toContain(file);
    }
    // Nothing from the repo that is not meant for users.
    expect(files.some((f) => /^(src|test|scripts|bench|docs|node_modules)\//.test(f))).toBe(false);
  });
});

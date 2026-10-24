/*
 * scripts/subpaths.mjs is the single list every generated file comes from. These tests pin it to
 * crypto-js 4.2.0 itself, and pin package.json and the generated legacy stubs to the list.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { exportsMap, filesList, stubContent } from '../../scripts/build.mjs';
import { CRYPTO_JS_DIFFERENCES, ROOT_ALIAS, SUBPATHS, resolvePath } from '../../scripts/subpaths.mjs';
import { ROOT, readJson, requireFromRoot } from './helpers';

const cryptoJsDir = path.dirname(requireFromRoot.resolve('crypto-js/package.json'));

describe('scripts/subpaths.mjs', () => {
  it('lists exactly the .js modules crypto-js 4.2.0 ships (top level; not bower.json/docs)', () => {
    expect(readJson<{ version: string }>(path.join(cryptoJsDir, 'package.json')).version).toBe('4.2.0');
    const shipped = fs
      .readdirSync(cryptoJsDir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith('.js'))
      .map((entry) => entry.name.slice(0, -'.js'.length))
      .sort();
    const listed = SUBPATHS.map((s) => s.name).sort();
    expect(listed).toEqual(shipped);
    expect(new Set(listed).size).toBe(listed.length);
  });

  it("maps each module to the value crypto-js's own module returns (documented exceptions only)", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const CryptoJS: any = requireFromRoot('crypto-js');
    const mismatches: Record<string, string> = {};
    for (const { name, path: member } of SUBPATHS) {
      const actual = requireFromRoot(`crypto-js/${name}`);
      const expected = resolvePath(CryptoJS, member);
      if (expected === undefined) mismatches[name] = `CryptoJS.${member} does not exist in crypto-js`;
      else if (actual !== expected) {
        mismatches[name] =
          actual === undefined ? 'undefined' : typeof actual === 'object' && actual.SHA256 ? 'copy' : 'different';
      }
    }
    // crypto-js quirks cryptolite deliberately does not reproduce (see scripts/subpaths.mjs).
    expect(mismatches).toEqual(CRYPTO_JS_DIFFERENCES);
  });

  it('every documented exception still names a real CryptoJS member in cryptolite terms', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const CryptoJS: any = requireFromRoot('crypto-js');
    for (const name of Object.keys(CRYPTO_JS_DIFFERENCES)) {
      const entry = SUBPATHS.find((s) => s.name === name);
      expect(entry, name).toBeDefined();
      expect(resolvePath(CryptoJS, entry!.path), name).toBeDefined();
    }
  });
});

describe('package.json and generated files follow the list', () => {
  const pkg = readJson<Record<string, unknown>>(path.join(ROOT, 'package.json'));

  it('"exports" is generated from the list (run npm run build after editing it)', () => {
    expect(pkg.exports).toEqual(exportsMap());
    const keys = Object.keys(pkg.exports as object);
    for (const { name } of SUBPATHS) {
      expect(keys).toContain(`./${name}`);
      expect(keys).toContain(`./${name}.js`);
    }
  });

  it('"files" ships dist/ plus one legacy stub directory per module', () => {
    expect(pkg.files).toEqual(filesList());
  });

  it('every legacy stub points main/types at an existing CJS shim and its declaration', () => {
    for (const { name, path: member } of SUBPATHS) {
      const dir = path.join(ROOT, name);
      const stubFile = path.join(dir, 'package.json');
      expect(fs.readFileSync(stubFile, 'utf8')).toBe(stubContent(name));
      const stub = readJson<{ main: string; types: string }>(stubFile);
      expect(fs.existsSync(path.resolve(dir, stub.main)), `${name} main`).toBe(true);
      expect(fs.existsSync(path.resolve(dir, stub.types)), `${name} types`).toBe(true);
      // What a resolver that ignores "exports" (webpack 4, Metro without package exports,
      // TypeScript moduleResolution node10) loads: the stub's main, by path.
      const legacyValue = requireFromRoot(path.resolve(dir, stub.main));
      const root = requireFromRoot(path.join(ROOT, 'dist/index.cjs'));
      expect(legacyValue, name).toBeDefined();
      expect(legacyValue === resolvePath(root, member), name).toBe(true);
    }
  });

  it('the root alias has no separate shim: crypto-js/index is the package root', () => {
    expect(fs.existsSync(path.join(ROOT, 'dist', `${ROOT_ALIAS}.js`))).toBe(true);
    const map = exportsMap() as Record<string, unknown>;
    expect(map[`./${ROOT_ALIAS}`]).toEqual(map['.']);
  });
});

/*
 * Shared helpers for the package tests (test/package/**), which exercise the BUILT package:
 * dist/, the tarball `npm pack` produces, and temp projects that install it.
 * Owned by the packaging lane.
 */
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { inject } from 'vitest';
import { ROOT, output, run } from './proc';

export * from './proc';

export const DIST = path.join(ROOT, 'dist');
export const FIXTURES = path.join(ROOT, 'test/package/fixtures');
export const CORPUS = path.join(ROOT, 'test/package/types-corpus');
export const requireFromRoot = createRequire(path.join(ROOT, 'package.json'));

export const TSC7 = path.join(ROOT, 'node_modules/typescript/bin/tsc');
export const TSC6 = path.join(ROOT, 'node_modules/@typescript/typescript6/bin/tsc6');

export const tarball = (): string => inject('tarball');

/** A fresh, empty directory under this run's temp root. */
export function tempDir(label: string): string {
  const root = inject('tmpRoot');
  return fs.mkdtempSync(path.join(root, `${label}-`));
}

/** Extract a packed tarball into <dir>/node_modules/<as> (what npm would install). */
export function extractTarballAs(tgz: string, dir: string, as: string): string {
  const target = path.join(dir, 'node_modules', as);
  fs.mkdirSync(target, { recursive: true });
  const result = run('tar', ['-xzf', tgz, '-C', target, '--strip-components=1']);
  if (result.status !== 0) throw new Error(`tar failed: ${output(result)}`);
  return target;
}

/** Symlink a package from the repo's node_modules into a temp project's node_modules. */
export function linkDevPackage(dir: string, name: string): void {
  const source = path.join(ROOT, 'node_modules', name);
  const target = path.join(dir, 'node_modules', name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.symlinkSync(source, target, process.platform === 'win32' ? 'junction' : 'dir');
}

export function readJson<T = unknown>(file: string): T {
  return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
}

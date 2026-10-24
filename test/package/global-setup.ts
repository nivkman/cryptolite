/*
 * Global setup for the `package` vitest project: verifies the build is complete and fresh, packs
 * it once with `npm pack` (exactly what would be published), and provides the tarball path and a
 * per-run temp directory to the test files.
 *
 * Temp files go under os.tmpdir() (set TMPDIR to relocate them); KEEP_TMP=1 keeps them.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { TestProject } from 'vitest/node';
import { ROOT, output, parsePackJson, runNode, runNpm } from './proc';

export default function setup(project: TestProject) {
  const verify = runNode([path.join(ROOT, 'scripts/verify-dist.mjs')], { cwd: ROOT });
  if (verify.status !== 0) {
    throw new Error(`The package tests need a fresh build (npm run build).\n${output(verify)}`);
  }

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptolite-package-'));
  const pack = runNpm(['pack', '--json', '--pack-destination', tmpRoot], { cwd: ROOT });
  if (pack.status !== 0) throw new Error(`npm pack failed.\n${output(pack)}`);
  const [info] = parsePackJson(pack.stdout);
  if (!info) throw new Error(`npm pack produced no tarball.\n${output(pack)}`);
  const tarball = path.join(tmpRoot, info.filename);
  if (!fs.existsSync(tarball)) throw new Error(`npm pack reported ${info.filename} but it is not in ${tmpRoot}`);

  project.provide('tarball', tarball);
  project.provide('tmpRoot', tmpRoot);

  return () => {
    if (process.env.KEEP_TMP === '1') {
      process.stdout.write(`[package tests] kept temp files in ${tmpRoot}\n`);
      return;
    }
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  };
}

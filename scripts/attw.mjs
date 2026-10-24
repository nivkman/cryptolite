#!/usr/bin/env node
// npm run lint:pkg (after publint): @arethetypeswrong/cli on the packed tarball, in two passes.
//
// Known, documented gap: resolvers that ignore package.json "exports" (TypeScript
// moduleResolution node10, webpack 4, Metro without package exports) reach subpaths through the
// <name>/package.json stubs, which serve `cryptolite/sha256` but cannot serve the `.js`-suffixed
// form `cryptolite/sha256.js`. attw reports exactly those 50 node10 cases as NoResolution, so:
//   1. strict profile (node10 + node16 CJS/ESM + bundler) on every entry point except the `.js`
//      forms, which must have zero problems;
//   2. node16 profile (node16 CJS/ESM + bundler) on every entry point, `.js` forms included,
//      which must have zero problems.
// Together that is every (entry point, resolution mode) pair except node10 x `.js`.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SUBPATHS } from './subpaths.mjs';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const attw = path.join(path.dirname(require.resolve('@arethetypeswrong/cli/package.json')), 'dist/index.js');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptolite-attw-'));
let status = 0;
try {
  const pack = spawnSync('npm', ['pack', '--json', '--pack-destination', tmp, '--loglevel=error'], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
    shell: process.platform === 'win32',
  });
  if (pack.status !== 0) throw new Error(`npm pack failed (exit ${pack.status})`);
  const start = pack.stdout.search(/^\[\s*\{/m);
  const tarball = path.join(tmp, JSON.parse(pack.stdout.slice(start))[0].filename);

  const passes = [
    {
      title: 'strict profile, all entry points except the .js-suffixed subpaths',
      args: ['--exclude-entrypoints', ...SUBPATHS.map(({ name }) => `./${name}.js`)],
    },
    { title: 'node16 profile, all entry points', args: ['--profile', 'node16'] },
  ];
  for (const { title, args } of passes) {
    process.stdout.write(`\n[attw] ${title}\n`);
    const result = spawnSync(process.execPath, [attw, tarball, '--format', 'table-flipped', ...args], { stdio: 'inherit' });
    if (result.status !== 0) status = result.status ?? 1;
  }
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
process.exit(status);

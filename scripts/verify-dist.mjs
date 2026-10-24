#!/usr/bin/env node
// Runs on `prepack` (so on `npm pack` and `npm publish`): refuses to pack a missing, partial or
// stale build. It checks, without rebuilding:
//   - every file scripts/build.mjs generates exists (bundles, declarations, shims, legacy stubs)
//   - package.json "exports"/"files" equal what scripts/subpaths.mjs generates
//   - no build input (src/, the build scripts, tsup.config.ts, tsconfig.json) is newer than the
//     build, and the bundles were built for the current package.json version
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportsMap, filesList, stubContent } from './build.mjs';
import { ROOT_ALIAS, SUBPATHS } from './subpaths.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const problems = [];

const expected = ['index.js', 'index.cjs', 'index.d.ts', 'index.d.cts', 'types.d.ts', 'types.d.cts', 'modern.d.ts', 'modern.d.cts'];
for (const { name } of SUBPATHS) {
  if (name !== ROOT_ALIAS) expected.push(`${name}.js`, `${name}.cjs`, `${name}.d.ts`, `${name}.d.cts`);
}
for (const file of expected) {
  if (!fs.existsSync(path.join(ROOT, 'dist', file))) problems.push(`missing dist/${file}`);
}
for (const { name } of SUBPATHS) {
  const stub = path.join(ROOT, name, 'package.json');
  if (!fs.existsSync(stub)) problems.push(`missing ${name}/package.json`);
  else if (fs.readFileSync(stub, 'utf8') !== stubContent(name)) problems.push(`${name}/package.json differs from the generated stub`);
}

const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
if (JSON.stringify(pkg.exports) !== JSON.stringify(exportsMap())) problems.push('package.json "exports" is out of date');
if (JSON.stringify(pkg.files) !== JSON.stringify(filesList())) problems.push('package.json "files" is out of date');

// Build inputs. (package.json is rewritten by the build itself, so its mtime cannot be used; the
// version it contributes is checked through the bundle banner instead.)
const INPUTS = ['src', 'scripts/build.mjs', 'scripts/subpaths.mjs', 'scripts/cjs-entry.cts', 'tsup.config.ts', 'tsconfig.json'];
if (fs.existsSync(path.join(ROOT, 'dist', 'index.cjs')) && fs.existsSync(path.join(ROOT, 'dist', 'index.js'))) {
  const builtAt = Math.min(...['index.js', 'index.cjs'].map((f) => fs.statSync(path.join(ROOT, 'dist', f)).mtimeMs));
  const newer = [];
  const visit = (full) => {
    const stat = fs.statSync(full);
    if (stat.isDirectory()) for (const entry of fs.readdirSync(full)) visit(path.join(full, entry));
    else if (stat.mtimeMs > builtAt) newer.push(path.relative(ROOT, full));
  };
  for (const input of INPUTS) visit(path.join(ROOT, input));
  if (newer.length > 0) problems.push(`build is older than: ${newer.slice(0, 5).join(', ')}${newer.length > 5 ? ', ...' : ''}`);
  for (const file of ['index.js', 'index.cjs']) {
    const head = fs.readFileSync(path.join(ROOT, 'dist', file), 'utf8').slice(0, 200);
    if (!head.includes(`cryptolite ${pkg.version} |`)) problems.push(`dist/${file} was built for a different version than ${pkg.version}`);
  }
}

if (problems.length > 0) {
  process.stderr.write(`[verify-dist] refusing to pack; run \`npm run build\` first:\n  - ${problems.join('\n  - ')}\n`);
  process.exit(1);
}
process.stderr.write(`[verify-dist] ok: ${expected.length} dist files, ${SUBPATHS.length} legacy stubs, exports/files in sync\n`);

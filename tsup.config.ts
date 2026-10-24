// JavaScript builds only. Run through `npm run build` (scripts/build.mjs), which cleans dist/ first,
// then bundles the declarations and generates the type entry points, the subpath shims and
// package.json "exports" around these two outputs.
// Paths are relative to the repository root, where scripts/build.mjs runs tsup.

import fs from 'node:fs';
import path from 'node:path';
import { defineConfig, type Options } from 'tsup';

type EsbuildPlugin = NonNullable<Options['esbuildPlugins']>[number];

const SRC = path.resolve('src') + path.sep;

/**
 * package.json says `"sideEffects": false`, which is true of the shipped dist files, but esbuild
 * also applies it to our own src/ while bundling. The compat modules register their members on
 * the shared CryptoJS object when imported (as crypto-js's modules do), so esbuild would drop
 * them and silently ship an object without SHA256, AES, ... . This marks every module under src/
 * as having side effects for our build only.
 */
const srcHasSideEffects: EsbuildPlugin = {
  name: 'cryptolite-src-has-side-effects',
  setup(build) {
    build.onResolve({ filter: /^\./ }, async (args) => {
      if (args.pluginData === srcHasSideEffects.name) return undefined;
      const resolved = await build.resolve(args.path, {
        kind: args.kind,
        importer: args.importer,
        resolveDir: args.resolveDir,
        pluginData: srcHasSideEffects.name,
      });
      if (resolved.errors.length > 0 || !resolved.path.startsWith(SRC)) return undefined;
      return { path: resolved.path, sideEffects: true };
    });
  },
};

/**
 * MIT requires the copyright and permission notices to travel with every copy. @noble/hashes 2.x
 * files carry no `/*!` header (so esbuild's legal-comment handling cannot keep it), and the
 * compat layer is a port of crypto-js, so the notices are written into each bundle verbatim from
 * the installed packages' LICENSE files.
 */
function licenseBanner(): string {
  const read = (file: string) => fs.readFileSync(path.resolve(file), 'utf8');
  const version = (pkg: string) => JSON.parse(read(`node_modules/${pkg}/package.json`)).version as string;
  const self = JSON.parse(read('package.json'));
  const notices = [
    ['crypto-js', 'framework code, ported'],
    ['@noble/hashes', 'bundled'],
    ['@noble/ciphers', 'bundled'],
  ].map(([pkg, how]) => {
    const text = read(`node_modules/${pkg}/LICENSE`).replace(/\*\//g, '* /').trim();
    return `${pkg} ${version(pkg)} (${how}):\n\n${text}`;
  });
  const body = [
    `cryptolite ${self.version} | ${self.license} License | https://github.com/nivkman/cryptolite`,
    'This file contains code from the following MIT-licensed projects.',
    ...notices,
  ].join('\n\n');
  return `/*!\n${body.split('\n').map((line) => ` * ${line}`.trimEnd()).join('\n')}\n */`;
}

const runtime: Options = {
  outDir: 'dist',
  // ES2020 keeps the output friendly to React Native (Hermes/Metro) and older bundlers.
  target: 'es2020',
  // No Node built-ins or Node-only globals may be pulled in: the same files run in browsers,
  // Deno, Bun, Workers and React Native.
  platform: 'neutral',
  // @noble/* are ESM-only devDependencies; bundle them so both builds have zero runtime
  // dependencies (docs/DECISIONS.md D5). Everything else must already be bundled source.
  noExternal: [/^@noble\//],
  splitting: false,
  sourcemap: false,
  minify: false,
  esbuildPlugins: [srcHasSideEffects],
  banner: { js: licenseBanner() },
  // Keep the MIT notices of the bundled code (noble's `/*! ... */` headers) in the output.
  esbuildOptions(options) {
    options.legalComments = 'eof';
  },
  clean: false,
  dts: false,
};

export default defineConfig([
  // ESM: default export + named exports, as written in src/index.ts.
  {
    ...runtime,
    entry: { index: 'src/index.ts' },
    format: ['esm'],
    outExtension: () => ({ js: '.js' }),
  },
  // CJS: `module.exports = CryptoJS` (see scripts/cjs-entry.cts).
  {
    ...runtime,
    entry: { index: 'scripts/cjs-entry.cts' },
    format: ['cjs'],
    outExtension: () => ({ js: '.cjs' }),
  },
]);

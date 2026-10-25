#!/usr/bin/env node
// Can a single-file ESM bundle let bundlers drop a compat object that modern-only importers do not
// use? Synthetic modules (not cryptolite code), bundled by esbuild and by Rollup, both resolved
// from this repo's devDependencies. Evidence for bench/RESULTS.md "Opportunities".
//
//   A: compat object built by a /* @__PURE__ */ factory; named compat exports read its properties
//   B: same, but each named compat export is a /* @__PURE__ */ IIFE around the property read
//
//   node bench/experiments/pure-annotations.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as esbuild from 'esbuild';
import { rollup } from 'rollup';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptolite-pure-'));
process.on('exit', () => fs.rmSync(TMP, { recursive: true, force: true }));

const factory =
  "function buildCompat() { const C = {}; C.SHA256 = function () { return 'COMPAT_CODE'; }; C.AES = { encrypt() { return 'COMPAT_CODE'; } }; return C; }\n" +
  'const CryptoJS = /* @__PURE__ */ buildCompat();\nexport default CryptoJS;\n' +
  "export function sha256() { return 'MODERN_CODE'; }\n";
const variants = {
  A: `${factory}export const SHA256 = CryptoJS.SHA256;\nexport const AES = CryptoJS.AES;\n`,
  B: `${factory}export const SHA256 = /* @__PURE__ */ (() => CryptoJS.SHA256)();\nexport const AES = /* @__PURE__ */ (() => CryptoJS.AES)();\n`,
};
fs.writeFileSync(path.join(TMP, 'package.json'), '{ "type": "module", "sideEffects": false }\n');
for (const [name, code] of Object.entries(variants)) fs.writeFileSync(path.join(TMP, `lib-${name}.js`), code);

const report = (bundler, variant, imported, out) =>
  console.log(
    `${bundler.padEnd(15)} variant ${variant}  import { ${imported} }: compat code kept: ${out.includes('COMPAT_CODE') ? 'yes' : 'no '}  modern code kept: ${out.includes('MODERN_CODE') ? 'yes' : 'no'}`,
  );

for (const variant of Object.keys(variants)) {
  for (const imported of ['sha256', 'SHA256']) {
    const entry = path.join(TMP, `entry-${variant}-${imported}.js`);
    fs.writeFileSync(entry, `import { ${imported} } from './lib-${variant}.js';\nconsole.log(${imported}());\n`);
    const e = await esbuild.build({ entryPoints: [entry], bundle: true, minify: true, format: 'esm', write: false, logLevel: 'error' });
    report(`esbuild ${esbuild.version}`, variant, imported, e.outputFiles[0].text);
    const bundle = await rollup({ input: entry, logLevel: 'silent' });
    const { output } = await bundle.generate({ format: 'es' });
    report(`rollup ${(await import('rollup')).VERSION}`, variant, imported, output[0].code);
  }
}

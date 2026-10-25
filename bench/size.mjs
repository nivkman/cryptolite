#!/usr/bin/env node
/**
 * Bundle size of typical imports, as a consumer's bundler would produce it: esbuild, bundle +
 * minify, ESM output, platform "browser", target es2020. `cryptolite` resolves by package
 * self-reference through package.json "exports" (so dist/ and "sideEffects": false apply exactly
 * as for an installed copy); `crypto-js` from node_modules.
 *
 *   npm run build && node bench/size.mjs [--json bench/raw/size.json]
 *
 * Reported per import:
 * - min: minified bytes with legal comments removed (webpack/terser extract them to a separate
 *   LICENSE file by default; this is the code that ships)
 * - gzip: zlib level 9 of `min`;  brotli: quality 11, text mode, of `min`
 * - +legal: extra bytes when legal comments are kept, which is esbuild's default for bundles
 *   (`legalComments: "eof"`)
 * - compat layer?: whether marker strings that only exist in src/compat are in the output
 * Every bundle is also executed with Node and its output checked, so a bundle that silently lost
 * code (the trap described in tsup.config.ts) cannot be reported as small.
 *
 * Rows under "Diagnosis" and "Hypothetical" are NOT shipped entry points:
 * - Diagnosis: a temp copy of dist/index.js with one statement removed, to attribute the cost.
 * - Hypothetical: entries built from src/ the way tsup.config.ts builds dist (esbuild, ESM,
 *   platform neutral, noble bundled, every src/ module marked side-effectful), then bundled by
 *   the consumer like the real rows. They estimate what a proposed entry point would weigh.
 * Temp files go to os.tmpdir() and are removed at exit.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import * as esbuild from 'esbuild';
import { ROOT, argValue, environment, requireBuild, writeJson } from './env.mjs';

const build = requireBuild();
const JSON_OUT = argValue('--json');
const SRC = path.join(ROOT, 'src') + path.sep;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptolite-size-'));
process.on('exit', () => fs.rmSync(TMP, { recursive: true, force: true }));

/** Strings that only exist in the compat layer (src/compat) or only in the modern API. */
const COMPAT_MARKERS = ['Malformed UTF-8 data', 'MDHasher._newCore', 'MIGRATION.md#unsupported-ciphers'];
const MODERN_MARKERS = ['ERR_LEGACY_NOT_ALLOWED'];
{
  // A marker that no longer exists in dist would silently report "no compat layer".
  const dist = fs.readFileSync(path.join(ROOT, 'dist', 'index.js'), 'utf8');
  const stale = [...COMPAT_MARKERS, ...MODERN_MARKERS].filter((m) => !dist.includes(m));
  if (stale.length) throw new Error(`marker strings not found in dist/index.js (update bench/size.mjs): ${stale.join(', ')}`);
}
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

// ---------------------------------------------------------------------------------------------
// Library-side builds for the diagnosis / hypothetical rows (written to TMP as tiny packages)
// ---------------------------------------------------------------------------------------------
function writePackage(name, js) {
  const dir = path.join(TMP, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "type": "module", "sideEffects": false }\n');
  fs.writeFileSync(path.join(dir, 'index.js'), js);
  return path.join(dir, 'index.js');
}

/** Same rule as tsup.config.ts: every module under src/ has side effects during the library build. */
const srcHasSideEffects = {
  name: 'src-has-side-effects',
  setup(b) {
    b.onResolve({ filter: /.*/ }, async (args) => {
      if (args.pluginData === 'src-has-side-effects' || args.kind === 'entry-point') return undefined;
      const r = await b.resolve(args.path, {
        kind: args.kind,
        importer: args.importer,
        resolveDir: args.resolveDir,
        pluginData: 'src-has-side-effects',
      });
      if (r.errors.length > 0 || !r.path.startsWith(SRC)) return undefined;
      return { path: r.path, sideEffects: true };
    });
  },
};

async function libraryBuild(name, entrySource) {
  const result = await esbuild.build({
    stdin: { contents: entrySource, resolveDir: ROOT, sourcefile: `${name}.ts`, loader: 'ts' },
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    mainFields: ['module', 'main'],
    target: 'es2020',
    minify: false,
    legalComments: 'eof',
    plugins: [srcHasSideEffects],
    write: false,
    logLevel: 'error',
  });
  return writePackage(name, result.outputFiles[0].text);
}

/** dist/index.js with each pattern (which must match exactly once) deleted. */
function distWithout(name, patterns) {
  let dist = fs.readFileSync(path.join(ROOT, 'dist', 'index.js'), 'utf8');
  for (const re of patterns) {
    const found = dist.match(new RegExp(re.source, 'g')) ?? [];
    if (found.length !== 1) throw new Error(`expected exactly one match of ${re} in dist/index.js, found ${found.length}`);
    dist = dist.replace(re, '');
  }
  return writePackage(name, dist);
}

const q = JSON.stringify;
const srcPath = (p) => q(path.join(SRC, p));
// What src/index.ts's `import * as modern` + `Object.assign(CryptoJS, modern)` compile to.
const OBJECT_ASSIGN = /Object\.assign\(compat_default, modern_exports\);/;
const MODERN_NAMESPACE = /__export\(modern_exports, \{[^}]*\}\);/;
const noAssign = distWithout('dist-without-object-assign', [OBJECT_ASSIGN, MODERN_NAMESPACE]);
const hypModern = await libraryBuild('hyp-modern', `export * from ${srcPath('modern/index.ts')};`);
const hypSha256 = await libraryBuild(
  'hyp-sha256',
  `import { C } from ${srcPath('compat/core.ts')};\nimport ${srcPath('compat/hashers.ts')};\nexport default C.SHA256;`,
);
const hypCompat = await libraryBuild('hyp-compat-only', `export { default } from ${srcPath('compat/index.ts')};`);

// ---------------------------------------------------------------------------------------------
// Consumer imports
// ---------------------------------------------------------------------------------------------
const useSha256 = (fn) => `console.log(${fn}('abc').toString());`;
const useAes = "console.log(AES.decrypt(AES.encrypt('a', 'b'), 'b').toString(Utf8));";
const useEncrypt = "encrypt('a', 'password').then((t) => decrypt(t, 'password')).then(console.log);";

const cases = [
  { group: 'Whole library', title: "import CryptoJS from 'crypto-js'", code: "import CryptoJS from 'crypto-js';\nconsole.log(typeof CryptoJS.AES, CryptoJS.SHA256('abc').toString());", expect: SHA256_ABC },
  { group: 'Whole library', title: "import CryptoJS from 'cryptolite'", code: "import CryptoJS from 'cryptolite';\nconsole.log(typeof CryptoJS.AES, CryptoJS.SHA256('abc').toString());", expect: SHA256_ABC },
  { group: 'One hash, crypto-js style', title: "import sha256 from 'crypto-js/sha256'", code: `import sha256 from 'crypto-js/sha256';\n${useSha256('sha256')}`, expect: SHA256_ABC },
  { group: 'One hash, crypto-js style', title: "import sha256 from 'cryptolite/sha256'", code: `import sha256 from 'cryptolite/sha256';\n${useSha256('sha256')}`, expect: SHA256_ABC },
  { group: 'One hash, crypto-js style', title: "import { SHA256 } from 'cryptolite'", code: `import { SHA256 } from 'cryptolite';\n${useSha256('SHA256')}`, expect: SHA256_ABC },
  { group: 'AES via subpaths (extra)', title: "import AES from 'crypto-js/aes' + Utf8 from 'crypto-js/enc-utf8'", code: `import AES from 'crypto-js/aes';\nimport Utf8 from 'crypto-js/enc-utf8';\n${useAes}`, expect: 'a' },
  { group: 'AES via subpaths (extra)', title: "import AES from 'cryptolite/aes' + Utf8 from 'cryptolite/enc-utf8'", code: `import AES from 'cryptolite/aes';\nimport Utf8 from 'cryptolite/enc-utf8';\n${useAes}`, expect: 'a' },
  { group: 'Modern API only', title: "import { sha256 } from 'cryptolite'", code: `import { sha256 } from 'cryptolite';\n${useSha256('sha256')}`, expect: SHA256_ABC },
  { group: 'Modern API only', title: "import { encrypt, decrypt } from 'cryptolite'", code: `import { encrypt, decrypt } from 'cryptolite';\n${useEncrypt}`, expect: 'a' },
  {
    group: 'Diagnosis: dist/index.js minus `Object.assign(compat_default, modern_exports)` and `__export(modern_exports, {...})`',
    title: '{ sha256 } from patched dist',
    code: `import { sha256 } from ${q(noAssign)};\n${useSha256('sha256')}`,
    expect: SHA256_ABC,
    synthetic: true,
  },
  {
    group: 'Diagnosis: dist/index.js minus `Object.assign(compat_default, modern_exports)` and `__export(modern_exports, {...})`',
    title: '{ encrypt, decrypt } from patched dist',
    code: `import { encrypt, decrypt } from ${q(noAssign)};\n${useEncrypt}`,
    expect: 'a',
    synthetic: true,
  },
  {
    group: 'Hypothetical entries (built from src/ like tsup.config.ts; not shipped)',
    title: '`cryptolite/modern` (= src/modern/index.ts): { sha256 }',
    code: `import { sha256 } from ${q(hypModern)};\n${useSha256('sha256')}`,
    expect: SHA256_ABC,
    synthetic: true,
  },
  {
    group: 'Hypothetical entries (built from src/ like tsup.config.ts; not shipped)',
    title: '`cryptolite/modern` (= src/modern/index.ts): { encrypt, decrypt }',
    code: `import { encrypt, decrypt } from ${q(hypModern)};\n${useEncrypt}`,
    expect: 'a',
    synthetic: true,
  },
  {
    group: 'Hypothetical entries (built from src/ like tsup.config.ts; not shipped)',
    title: 'split `cryptolite/sha256` (= src/compat core.ts + hashers.ts)',
    code: `import sha256 from ${q(hypSha256)};\n${useSha256('sha256')}`,
    expect: SHA256_ABC,
    synthetic: true,
  },
  {
    group: 'Hypothetical entries (built from src/ like tsup.config.ts; not shipped)',
    title: 'compat object without the modern API (= src/compat/index.ts)',
    code: `import CryptoJS from ${q(hypCompat)};\nconsole.log(typeof CryptoJS.AES, CryptoJS.SHA256('abc').toString());`,
    expect: SHA256_ABC,
    synthetic: true,
  },
];

async function bundle(code, legalComments) {
  const result = await esbuild.build({
    stdin: { contents: code, resolveDir: path.join(ROOT, 'bench'), sourcefile: 'entry.mjs', loader: 'js' },
    bundle: true,
    minify: true,
    format: 'esm',
    platform: 'browser',
    target: 'es2020',
    legalComments,
    write: false,
    logLevel: 'error',
  });
  return Buffer.from(result.outputFiles[0].contents);
}

/** Runs a bundle with Node and returns its trimmed stdout (throws if it fails). */
function execute(bytes, name) {
  const file = path.join(TMP, `${name}.mjs`);
  fs.writeFileSync(file, bytes);
  const r = spawnSync(process.execPath, [file], { encoding: 'utf8', timeout: 60000 });
  if (r.status !== 0) throw new Error(`bundle ${name} failed to run: ${r.stderr}`);
  return r.stdout.trim();
}

const gzip = (b) => zlib.gzipSync(b, { level: 9 }).length;
const brotli = (b) =>
  zlib.brotliCompressSync(b, {
    params: {
      [zlib.constants.BROTLI_PARAM_QUALITY]: 11,
      [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
      [zlib.constants.BROTLI_PARAM_SIZE_HINT]: b.length,
    },
  }).length;

const rows = [];
for (const [i, c] of cases.entries()) {
  const code = await bundle(c.code, 'none');
  const withLegal = await bundle(c.code, 'eof');
  const stdout = execute(code, `case-${i}`);
  if (!stdout.includes(c.expect)) throw new Error(`${c.title}: bundle printed ${q(stdout)}, expected ${q(c.expect)}`);
  const text = code.toString('utf8');
  rows.push({
    group: c.group,
    title: c.title,
    code: c.code.replaceAll(TMP, '<tmp>').replaceAll(ROOT, '<repo>'),
    synthetic: Boolean(c.synthetic),
    min: code.length,
    gzip: gzip(code),
    brotli: brotli(code),
    legalExtra: withLegal.length - code.length,
    compatMarkers: COMPAT_MARKERS.filter((m) => text.includes(m)),
    modernMarkers: MODERN_MARKERS.filter((m) => text.includes(m)),
    executed: stdout,
  });
}

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------
const kib = (n) => `${(n / 1024).toFixed(1)} KiB`;
const lines = [
  '| Import | min | min + gzip | min + brotli | + legal comments (esbuild default) | compat layer in output? |',
  '|---|--:|--:|--:|--:|---|',
];
let group;
for (const r of rows) {
  if (r.group !== group) {
    group = r.group;
    lines.push(`| **${group}** | | | | | |`);
  }
  const compat = r.title.includes('crypto-js')
    ? 'n/a'
    : r.compatMarkers.length
      ? `yes (${r.compatMarkers.length}/${COMPAT_MARKERS.length} markers)`
      : 'no';
  lines.push(
    `| ${r.title} | ${kib(r.min)} (${r.min.toLocaleString('en-US')} B) | ${kib(r.gzip)} | ${kib(r.brotli)} | +${r.legalExtra.toLocaleString('en-US')} B | ${compat} |`,
  );
}

const env = { ...environment(), build, esbuildApiVersion: esbuild.version };
process.stderr.write(`${q(env)}\n`);
process.stdout.write(`${lines.join('\n')}\n`);

const by = Object.fromEntries(rows.map((r) => [r.title, r]));
const delta = (a, b) =>
  ['min', 'gzip', 'brotli'].map((k) => `${(by[a][k] - by[b][k]).toLocaleString('en-US')} B ${k}`).join(' / ');
process.stdout.write(
  [
    '',
    'Extra bytes a modern-only import pays for importing from the package root (root minus hypothetical `cryptolite/modern`):',
    `- { sha256 }: ${delta("import { sha256 } from 'cryptolite'", '`cryptolite/modern` (= src/modern/index.ts): { sha256 }')}`,
    `- { encrypt, decrypt }: ${delta("import { encrypt, decrypt } from 'cryptolite'", '`cryptolite/modern` (= src/modern/index.ts): { encrypt, decrypt }')}`,
    'Removing those two statements from dist (diagnosis) saves:',
    `- { sha256 }: ${delta("import { sha256 } from 'cryptolite'", '{ sha256 } from patched dist')}`,
    `- { encrypt, decrypt }: ${delta("import { encrypt, decrypt } from 'cryptolite'", '{ encrypt, decrypt } from patched dist')}`,
    `cryptolite/sha256 minus crypto-js/sha256: ${delta("import sha256 from 'cryptolite/sha256'", "import sha256 from 'crypto-js/sha256'")}`,
    '',
  ].join('\n'),
);
if (JSON_OUT) writeJson(JSON_OUT, { env, rows });

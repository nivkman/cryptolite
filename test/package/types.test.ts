/*
 * TypeScript consumers of the packed package: test/package/types-corpus compiled in temp projects
 * under several compilers and module settings, with skipLibCheck off so the shipped declarations
 * are checked too. The same compat corpus rewritten to `crypto-js` is compiled against crypto-js +
 * @types/crypto-js, to prove it is genuine crypto-js-typed code (so "compiles against cryptolite"
 * means "existing crypto-js code compiles unchanged").
 *
 * TypeScript 7 removed moduleResolution node10 and esModuleInterop=false, so those configurations
 * run on TypeScript 6 (@typescript/typescript6), which also covers an older compiler generally.
 */
import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { CORPUS, TSC6, TSC7, extractTarballAs, linkDevPackage, output, runNode, tarball, tempDir } from './helpers';

// compat-subpaths.ts imports subpaths without extension, compat-subpaths-js.ts with `.js`.
const COMPAT_ESM = ['compat-default.ts', 'compat-namespace.ts', 'compat-named.ts', 'compat-subpaths.ts', 'compat-subpaths-js.ts'];
const COMPAT_CJS = ['compat-require.cts', 'compat-require.cjs'];
const MODERN_ESM = ['modern.ts'];
const MODERN_CJS = ['modern-require.cts'];

const strict = {
  strict: true,
  noEmit: true,
  skipLibCheck: false,
  allowJs: true,
  checkJs: true,
  target: 'ES2020',
  lib: ['ES2020'],
  types: [] as string[],
  forceConsistentCasingInFileNames: true,
};

interface Case {
  label: string;
  tsc: string;
  compilerOptions: Record<string, unknown>;
  files: string[];
  /** package.json "type" of the consumer project; undefined = CommonJS project. */
  type?: 'module';
  /** Compile the corpus against crypto-js + @types/crypto-js instead of cryptolite. */
  against?: 'crypto-js';
  /** Also install @types/crypto-js next to cryptolite (mid-migration). */
  withTypesCryptoJs?: boolean;
}

let installedCryptolite = '';

beforeAll(() => {
  // What `npm install cryptolite` puts on disk: the packed tarball, extracted once and linked
  // into every temp project.
  installedCryptolite = extractTarballAs(tarball(), tempDir('ts-install'), 'cryptolite');
});

function compile(c: Case) {
  const dir = tempDir(`ts-${c.label}`);
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: `consumer-${c.label}`, private: true, ...(c.type ? { type: c.type } : {}) }),
  );
  fs.writeFileSync(
    path.join(dir, 'tsconfig.json'),
    JSON.stringify({ compilerOptions: { ...strict, ...c.compilerOptions }, files: c.files }, null, 2),
  );
  for (const file of c.files) {
    let text = fs.readFileSync(path.join(CORPUS, file), 'utf8');
    if (c.against === 'crypto-js') text = text.replace(/(['"])cryptolite(\/[^'"]*)?\1/g, '$1crypto-js$2$1');
    fs.writeFileSync(path.join(dir, file), text);
  }
  const nodeModules = path.join(dir, 'node_modules');
  fs.mkdirSync(nodeModules);
  if (c.against === 'crypto-js') {
    linkDevPackage(dir, 'crypto-js');
    linkDevPackage(dir, '@types/crypto-js');
  } else {
    fs.symlinkSync(installedCryptolite, path.join(nodeModules, 'cryptolite'), 'dir');
    if (c.withTypesCryptoJs) linkDevPackage(dir, '@types/crypto-js');
  }
  const result = runNode([c.tsc, '-p', 'tsconfig.json', '--pretty', 'false'], { cwd: dir });
  expect(result.status, `${c.label}\n${output(result)}`).toBe(0);
}

const node16 = { module: 'node16', moduleResolution: 'node16' };
const nodenext = { module: 'nodenext', moduleResolution: 'nodenext' };
const preserve = { module: 'preserve', moduleResolution: 'bundler' };
const esnextBundler = { module: 'esnext', moduleResolution: 'bundler' };
const node10 = { module: 'commonjs', moduleResolution: 'node10', esModuleInterop: true, ignoreDeprecations: '6.0' };
const node10NoInterop = { module: 'commonjs', moduleResolution: 'node10', esModuleInterop: false, ignoreDeprecations: '6.0' };

const ALL = [...COMPAT_ESM, ...COMPAT_CJS, ...MODERN_ESM, ...MODERN_CJS];
const ESM_ONLY = [...COMPAT_ESM, ...MODERN_ESM];

const cases: Case[] = [
  { label: 'ts7-node16', tsc: TSC7, compilerOptions: node16, files: ALL, type: 'module' },
  { label: 'ts7-nodenext', tsc: TSC7, compilerOptions: nodenext, files: ALL, type: 'module' },
  { label: 'ts7-node16-cjs-project', tsc: TSC7, compilerOptions: node16, files: ALL },
  { label: 'ts7-bundler-preserve', tsc: TSC7, compilerOptions: preserve, files: ALL, type: 'module' },
  { label: 'ts7-bundler-esnext', tsc: TSC7, compilerOptions: esnextBundler, files: ESM_ONLY, type: 'module' },
  // (the .cts corpus files use `export const`, which verbatimModuleSyntax rejects in CJS files)
  { label: 'ts7-verbatim-node16', tsc: TSC7, compilerOptions: { ...node16, verbatimModuleSyntax: true }, files: [...ESM_ONLY, 'compat-require.cjs'], type: 'module' },
  { label: 'ts6-node16', tsc: TSC6, compilerOptions: node16, files: ALL, type: 'module' },
  { label: 'ts6-bundler', tsc: TSC6, compilerOptions: preserve, files: ALL, type: 'module' },
  // Resolvers that ignore "exports" find subpaths through the <name>/package.json stubs, which
  // cannot serve the `.js`-suffixed form (documented in scripts/subpaths.mjs and scripts/attw.mjs).
  { label: 'ts6-node10', tsc: TSC6, compilerOptions: node10, files: ALL.filter((f) => f !== 'compat-subpaths-js.ts') },
  {
    label: 'ts6-node10-no-esModuleInterop',
    tsc: TSC6,
    compilerOptions: node10NoInterop,
    files: ['compat-namespace.ts', 'compat-named.ts', 'compat-require.cts', 'compat-require.cjs', 'modern-require.cts'],
  },
  {
    label: 'ts7-node16-with-types-crypto-js',
    tsc: TSC7,
    compilerOptions: { ...node16, types: ['crypto-js'] },
    files: [...ALL, 'mid-migration.ts'],
    type: 'module',
    withTypesCryptoJs: true,
  },
];

// The corpus is real crypto-js code: it compiles against @types/crypto-js in the same settings.
// crypto-js has no "exports" map, so in Node ESM only the `.js` form resolves (cryptolite accepts
// both; the cryptolite cases above compile both files in ESM).
const COMPAT_ALL = [...COMPAT_ESM, ...COMPAT_CJS];
const referenceCases: Case[] = [
  {
    label: 'crypto-js-ts7-node16-esm-project',
    tsc: TSC7,
    compilerOptions: node16,
    files: COMPAT_ALL.filter((f) => f !== 'compat-subpaths.ts'),
    type: 'module',
    against: 'crypto-js',
  },
  { label: 'crypto-js-ts7-node16-cjs-project', tsc: TSC7, compilerOptions: node16, files: COMPAT_ALL, against: 'crypto-js' },
  { label: 'crypto-js-ts7-bundler', tsc: TSC7, compilerOptions: preserve, files: COMPAT_ALL, type: 'module', against: 'crypto-js' },
  { label: 'crypto-js-ts6-node10', tsc: TSC6, compilerOptions: node10, files: COMPAT_ALL, against: 'crypto-js' },
  {
    label: 'crypto-js-ts6-node10-no-esModuleInterop',
    tsc: TSC6,
    compilerOptions: node10NoInterop,
    files: ['compat-namespace.ts', 'compat-named.ts', 'compat-require.cts', 'compat-require.cjs'],
    against: 'crypto-js',
  },
];

describe('TypeScript consumers of the packed cryptolite', () => {
  it.each(cases.map((c) => [c.label, c] as const))('%s', (_label, c) => compile(c));
});

describe('reference: the compat corpus is valid crypto-js code (@types/crypto-js 4.2.2)', () => {
  it.each(referenceCases.map((c) => [c.label, c] as const))('%s', (_label, c) => compile(c));
});

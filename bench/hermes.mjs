#!/usr/bin/env node
/**
 * PBKDF2 / modern encrypt on the Hermes VM (React Native's engine), using the BUILT package.
 *
 * Hermes is not a dependency of this repo. Install the toolchain anywhere outside it:
 *
 *   mkdir -p "$DIR" && cd "$DIR" && npm init -y \
 *     && npm i --save-exact hermes-engine-cli@0.12.0 @babel/core@7.29.7 @react-native/babel-preset@0.88.0
 *   cd /path/to/cryptolite && npm run build && node bench/hermes.mjs --toolchain "$DIR" [--json bench/raw/hermes.json]
 *
 * Pipeline, mirroring what a React Native release build does to app code:
 *   1. esbuild bundles bench/hermes-entry.mjs (+ dist/index.js via "exports", + crypto-js) to an IIFE
 *      with Metro-like resolution (platform browser, "react-native" condition).
 *   2. Babel with @react-native/babel-preset, profile "default" (dev: false, helpers inlined).
 *      Hermes 0.12 cannot parse `class` or `async`; the preset's default "hermes-stable" profile
 *      targets Hermes V1 and keeps them, so the "default" profile (full lowering) is required.
 *   3. hermesc -O -emit-binary (release-build bytecode), then `hermes bundle.hbc`.
 * Every result is checked against Node's crypto (PBKDF2) or decrypted on Node (tokens).
 *
 * hermes-engine-cli 0.12.0 (2022) is the newest Hermes VM binary on npm; current React Native
 * ships Hermes V1, whose speed this does NOT measure. See bench/RESULTS.md.
 */
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import * as esbuild from 'esbuild';
import { decrypt } from 'cryptolite';
import { ROOT, argValue, environment, requireBuild, writeJson } from './env.mjs';
import { PASSWORD, SALT_HEX, SHORT } from './inputs.mjs';

const build = requireBuild();
const TOOLCHAIN = argValue('--toolchain');
const JSON_OUT = argValue('--json');
if (!TOOLCHAIN) {
  process.stderr.write('usage: node bench/hermes.mjs --toolchain <dir with hermes-engine-cli, @babel/core, @react-native/babel-preset>\n');
  process.exit(2);
}
const req = createRequire(path.join(path.resolve(TOOLCHAIN), 'package.json'));
const babel = req('@babel/core');
const preset = req.resolve('@react-native/babel-preset');
const binDir = path.join(path.dirname(req.resolve('hermes-engine-cli/package.json')), `${process.platform === 'darwin' ? 'osx' : 'linux64'}-bin`);
const HERMES = path.join(binDir, 'hermes');
const HERMESC = path.join(binDir, 'hermesc');
const version = (p) => JSON.parse(fs.readFileSync(req.resolve(`${p}/package.json`), 'utf8')).version;

const samples = { small: Number(argValue('--samples-small') ?? 3), large: Number(argValue('--samples-large') ?? 2) };
const salt = Buffer.from(SALT_HEX, 'hex');
const known = {
  pbkdf2_10k: crypto.pbkdf2Sync(PASSWORD, salt, 10000, 32, 'sha256').toString('hex'),
  pbkdf2_600k: crypto.pbkdf2Sync(PASSWORD, salt, 600000, 32, 'sha256').toString('hex'),
};

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptolite-hermes-'));
process.on('exit', () => fs.rmSync(TMP, { recursive: true, force: true }));

// 1. bundle
const bundled = await esbuild.build({
  entryPoints: [path.join(ROOT, 'bench', 'hermes-entry.mjs')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  conditions: ['react-native'],
  mainFields: ['react-native', 'browser', 'module', 'main'],
  target: 'es2020',
  define: { __BENCH__: JSON.stringify({ samples, known }) },
  write: false,
  logLevel: 'error',
});
// 2. Babel (React Native preset)
const transformed = babel.transformSync(bundled.outputFiles[0].text, {
  babelrc: false,
  configFile: false,
  sourceType: 'script',
  compact: false,
  presets: [[preset, { unstable_transformProfile: 'default', dev: false, enableBabelRuntime: false }]],
});
const js = path.join(TMP, 'bundle.js');
const hbc = path.join(TMP, 'bundle.hbc');
fs.writeFileSync(js, transformed.code);
// 3. compile + run
const compile = spawnSync(HERMESC, ['-O', '-emit-binary', '-out', hbc, js], { encoding: 'utf8' });
if (compile.status !== 0) throw new Error(`hermesc failed:\n${compile.stderr}`);
const hermesVersion = spawnSync(HERMES, ['-version'], { encoding: 'utf8' }).stdout.match(/Hermes release version: (\S+)/)?.[1];

const env = {
  ...environment(),
  build,
  hermes: hermesVersion,
  hermesEngineCli: version('hermes-engine-cli'),
  babelCore: version('@babel/core'),
  reactNativeBabelPreset: version('@react-native/babel-preset'),
  samples,
};
process.stderr.write(`${JSON.stringify(env)}\nrunning on Hermes (several minutes)...\n`);
const run = spawnSync(HERMES, [hbc], { encoding: 'utf8', timeout: 30 * 60 * 1000, maxBuffer: 16 * 1024 * 1024 });
if (run.status !== 0) throw new Error(`hermes exited with ${run.status}:\n${run.stdout}\n${run.stderr}`);
const records = run.stdout
  .trim()
  .split('\n')
  .map((l) => JSON.parse(l));
const failure = records.find((r) => r.error);
if (failure) throw new Error(`benchmark failed inside Hermes:\n${failure.error}`);
if (!records.some((r) => r.done)) throw new Error(`Hermes run did not finish:\n${run.stdout}`);

// Tokens made on Hermes must decrypt on Node with the same build.
for (const r of records.filter((x) => x.token)) {
  if ((await decrypt(r.token, PASSWORD)) !== SHORT) throw new Error(`token from "${r.name}" does not decrypt on Node`);
  r.tokenVerifiedOnNode = true;
}

const results = records.filter((r) => r.ms);
const fmt = (ms) => (ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms} ms`);
const lines = ['| Case | Library | samples (wall time each) | mean |', '|---|---|---|--:|'];
for (const r of results) {
  const mean = r.ms.reduce((a, b) => a + b, 0) / r.ms.length;
  r.meanMs = mean;
  lines.push(`| ${r.name} | ${r.label} | ${r.ms.map(fmt).join(', ')} | ${fmt(Math.round(mean))} |`);
}
process.stdout.write(`${lines.join('\n')}\n\n(engine probe: ${JSON.stringify(records[0])})\n`);
env.loadavg1mEnd = os.loadavg()[0];
if (JSON_OUT) writeJson(JSON_OUT, { env, records });

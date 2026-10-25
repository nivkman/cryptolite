// Shared by bench/run.mjs, bench/size.mjs and bench/hermes.mjs: a description of the machine and
// toolchain a result was produced on, so every published number can be traced to its conditions.
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function cpuModel() {
  try {
    const line = fs
      .readFileSync('/proc/cpuinfo', 'utf8')
      .split('\n')
      .find((l) => l.startsWith('model name'));
    if (line) return line.split(':')[1].trim();
  } catch {
    // not Linux: fall through to os.cpus()
  }
  return os.cpus()[0]?.model ?? 'unknown';
}

function pkgVersion(name) {
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, 'node_modules', name, 'package.json'), 'utf8')).version;
  } catch {
    return 'not installed';
  }
}

export function environment() {
  return {
    date: new Date().toISOString(),
    cpu: cpuModel(),
    logicalCpus: typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length,
    ramGiB: Math.round((os.totalmem() / 2 ** 30) * 10) / 10,
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    node: process.version,
    v8: process.versions.v8,
    loadavg1m: os.loadavg()[0],
    cryptolite: JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version,
    'crypto-js': pkgVersion('crypto-js'),
    tinybench: pkgVersion('tinybench'),
    esbuild: pkgVersion('esbuild'),
  };
}

function git(args) {
  const r = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8' });
  return r.status === 0 ? r.stdout.replace(/\s+$/, '') : undefined;
}

/**
 * Fails fast if dist/ is missing. Returns what identifies the measured build: the content hash of
 * dist/index.js, its mtime, the git commit and any uncommitted src/ files it may include.
 */
export function requireBuild() {
  const entry = path.join(ROOT, 'dist', 'index.js');
  if (!fs.existsSync(entry)) {
    process.stderr.write('dist/index.js not found. Run `npm run build` first.\n');
    process.exit(1);
  }
  const status = git(['status', '--porcelain', '--', 'src', 'scripts', 'tsup.config.ts']);
  return {
    entry: path.relative(ROOT, entry),
    sha256: crypto.createHash('sha256').update(fs.readFileSync(entry)).digest('hex'),
    builtAt: fs.statSync(entry).mtime.toISOString(),
    gitHead: git(['rev-parse', '--short', 'HEAD']),
    uncommittedBuildInputs: status ? status.split('\n') : [],
  };
}

export function writeJson(file, data) {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);
}

/** `--name value` from argv, or undefined. */
export function argValue(name) {
  const i = process.argv.indexOf(name);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

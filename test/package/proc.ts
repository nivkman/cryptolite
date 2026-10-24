/*
 * Process and path helpers for the package tests. No `vitest` import, so global-setup.ts can use
 * them too. Owned by the packaging lane.
 */
import { spawnSync, type SpawnSyncOptions } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

declare module 'vitest' {
  export interface ProvidedContext {
    /** Absolute path of the tarball `npm pack` produced in global-setup.ts. */
    tarball: string;
    /** Per-run temp directory (removed after the run unless KEEP_TMP=1). */
    tmpRoot: string;
  }
}

export interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Run a command without a shell; never throws, so assertions can show the output. */
export function run(command: string, args: readonly string[], options: SpawnSyncOptions = {}): RunResult {
  const result = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...options });
  if (result.error) throw result.error;
  return { status: result.status, stdout: String(result.stdout ?? ''), stderr: String(result.stderr ?? '') };
}

export const runNode = (args: readonly string[], options: SpawnSyncOptions = {}) => run(process.execPath, args, options);

/** `npm` from PATH (npm.cmd on Windows needs a shell). */
export function runNpm(args: readonly string[], options: SpawnSyncOptions = {}): RunResult {
  const env = { ...process.env, ...options.env };
  // Do not inherit the outer `npm run`'s lifecycle/config variables into nested installs.
  for (const key of Object.keys(env)) if (/^npm_(config|lifecycle|package)_/i.test(key)) delete env[key];
  return run('npm', ['--no-audit', '--no-fund', '--loglevel=error', ...args], {
    ...options,
    env,
    shell: process.platform === 'win32',
  });
}

export function npmMajor(): number {
  const { stdout } = runNpm(['--version']);
  return Number.parseInt(stdout.trim().split('.')[0] ?? '0', 10);
}

/** Readable failure text for a RunResult. */
export function output(result: RunResult): string {
  return `exit ${result.status}\n--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`;
}

/** The JSON array `npm pack --json` prints, ignoring any lifecycle-script output around it. */
export function parsePackJson(stdout: string): { filename: string }[] {
  const start = stdout.search(/^\[\s*(\{|\])/m);
  if (start === -1) throw new Error(`no JSON in npm pack output:\n${stdout}`);
  return JSON.parse(stdout.slice(start)) as { filename: string }[];
}

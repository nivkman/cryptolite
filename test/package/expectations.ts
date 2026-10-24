/*
 * What a correctly built and installed cryptolite must look like at runtime, shared by
 * runtime.test.ts (the build, via package self-reference) and alias-install.test.ts (the packed
 * tarball installed as `crypto-js`). Facts are collected in a plain Node child process by
 * fixtures/runtime-facts.{cjs,mjs}; expected values come from the real crypto-js 4.2.0.
 * Owned by the packaging lane.
 */
import path from 'node:path';
import { expect } from 'vitest';
import { readExportNames } from '../../scripts/build.mjs';
import { SUBPATHS } from '../../scripts/subpaths.mjs';
import { FIXTURES, output, requireFromRoot, runNode } from './helpers';

export interface Vectors {
  password: string;
  plaintext: string;
  aesCiphertext: string;
  sha256: string;
  hmacSha256: string;
  hmacSha256Base64: string;
  pbkdf2: string;
  base64: string;
}

/** Expected outputs, computed with the real crypto-js devDependency. */
export function cryptoJsVectors(): Vectors {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const C: any = requireFromRoot('crypto-js');
  const password = 'correct horse battery staple';
  const plaintext = 'hello from crypto-js 4.2.0';
  return {
    password,
    plaintext,
    aesCiphertext: C.AES.encrypt(plaintext, password).toString(),
    sha256: C.SHA256('abc').toString(),
    hmacSha256: C.HmacSHA256('message', 'key').toString(),
    hmacSha256Base64: C.HmacSHA256('message', 'key').toString(C.enc.Base64),
    pbkdf2: C.PBKDF2('password', 'salt', { keySize: 8, iterations: 1000 }).toString(),
    base64: C.enc.Base64.stringify(C.enc.Utf8.parse('hello')),
  };
}

/** Names the CryptoJS object and the ESM named exports must have, read from dist/*.d.ts. */
export function expectedNames(): { compat: string[]; modernValues: string[]; all: string[] } {
  const { compat, modern } = readExportNames() as {
    compat: string[];
    modern: { name: string; typeOnly: boolean }[];
  };
  const modernValues = modern.filter((m) => !m.typeOnly).map((m) => m.name);
  return { compat, modernValues, all: [...compat, ...modernValues] };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Facts = any;

export function collectFacts(kind: 'cjs' | 'mjs', spec: string, cwd: string, script = path.join(FIXTURES, `runtime-facts.${kind}`)): Facts {
  const result = runNode([script, spec], {
    cwd,
    env: {
      ...process.env,
      SUBPATHS_JSON: JSON.stringify(SUBPATHS),
      VECTORS_JSON: JSON.stringify(cryptoJsVectors()),
    },
  });
  if (result.status !== 0) throw new Error(`runtime-facts.${kind} failed\n${output(result)}`);
  return JSON.parse(result.stdout);
}

const sorted = (values: readonly string[]) => [...values].sort();

export function expectCjsFacts(facts: Facts, spec: string): void {
  const names = expectedNames();
  const v = cryptoJsVectors();
  expect(facts.type).toBe('object');
  // module.exports is the CryptoJS object itself, like crypto-js: no interop wrapper.
  expect(facts.ownEsModule).toBe(false);
  expect(facts.hasDefault).toBe(false);
  expect(sorted(facts.keys)).toEqual(sorted(names.all));
  expect(facts.undefinedMembers).toEqual([]);

  const expectedSubpaths = Object.fromEntries(
    SUBPATHS.flatMap(({ name }) => [`${spec}/${name}`, `${spec}/${name}.js`]).map((s) => [s, 'same']),
  );
  expect(facts.subpaths).toEqual(expectedSubpaths);

  expect(facts.behaviour).toEqual({
    sha256: v.sha256,
    sha256Subpath: v.sha256,
    hmacSha256: v.hmacSha256,
    hmacSubpath: v.hmacSha256Base64,
    pbkdf2: v.pbkdf2,
    base64: v.base64,
    randomSigBytes: 16,
    decryptCryptoJsCiphertext: v.plaintext,
    decryptViaSubpaths: v.plaintext,
    aesRoundTrip: 'round trip',
    modernAttached: true,
  });
}

export function expectEsmFacts(facts: Facts, spec: string): void {
  const names = expectedNames();
  const v = cryptoJsVectors();
  expect(facts.defaultType).toBe('object');
  expect(sorted(facts.named)).toEqual(sorted(names.all));
  expect(facts.namedNotOnDefault).toEqual([]);
  expect(facts.undefinedNamed).toEqual([]);
  expect(sorted(facts.defaultKeys)).toEqual(sorted(names.all));

  const expectedSubpaths = Object.fromEntries(
    SUBPATHS.flatMap(({ name }) => [`${spec}/${name}`, `${spec}/${name}.js`]).map((s) => [s, 'same']),
  );
  expect(facts.subpaths).toEqual(expectedSubpaths);
  const wholeObject = Object.fromEntries(
    SUBPATHS.filter((s) => s.path === '')
      .flatMap(({ name }) => [`${spec}/${name}`, `${spec}/${name}.js`])
      .map((s) => [s, []]),
  );
  expect(facts.wholeObjectNamedExports).toEqual(wholeObject);

  expect(facts.behaviour).toEqual({
    sha256: v.sha256,
    sha256Subpath: v.sha256,
    decryptCryptoJsCiphertext: v.plaintext,
    decryptViaSubpaths: v.plaintext,
    namespaceImportSha256: v.sha256,
    modernNamed: true,
  });
}

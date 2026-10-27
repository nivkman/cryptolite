/*
 * The built package at runtime, resolved the way Node resolves it for users (exports map,
 * import/require conditions) via package self-reference from inside the repo: ESM default, named
 * and namespace imports; CJS require and destructuring; every crypto-js subpath in both module
 * systems, with and without the `.js` suffix, equal to the expected member of the CryptoJS object.
 * Behaviour spot checks compare against the real crypto-js (deep differential tests live in
 * test/compat).
 */
import { describe, it } from 'vitest';
import { collectFacts, expectCjsFacts, expectEsmFacts } from './expectations';
import { FIXTURES } from './helpers';

describe('built package, resolved as `cryptolite`', () => {
  it('CommonJS: module.exports is the CryptoJS object; destructuring and every subpath work', () => {
    expectCjsFacts(collectFacts('cjs', '@nivkman/cryptolite', FIXTURES), '@nivkman/cryptolite');
  });

  it('ESM: default, named and namespace imports; every subpath default-exports its member', () => {
    expectEsmFacts(collectFacts('mjs', '@nivkman/cryptolite', FIXTURES), '@nivkman/cryptolite');
  });
});

// CommonJS build entry (bundled by tsup into dist/index.cjs).
//
// `export =` compiles to `module.exports = CryptoJS`: the CryptoJS object itself, exactly like
// crypto-js, with no `__esModule` flag and no `.default`. So `require('cryptolite').SHA256(...)`,
// `const CryptoJS = require('cryptolite')` and `const { AES, enc } = require('cryptolite')` all
// behave as they do with crypto-js. The modern API is attached to the same object by src/index.ts.
//
// The ESM import + `export =` mix is deliberate: esbuild bundles it scope-hoisted with a single
// `module.exports = CryptoJS` and no interop helpers, whereas `import x = require()` or tsup's
// cjsInterop footer produce wrapper/interop code. tsc rejects the mix (TS1293), so this file is
// excluded from tsconfig.test.json; the build and test/package/runtime.test.ts verify its output.
import CryptoJS from '../src/index';

export = CryptoJS;

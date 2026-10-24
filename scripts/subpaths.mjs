// The single list of crypto-js 4.2.0 module paths that cryptolite mirrors.
//
// Each entry maps a crypto-js module (`require('crypto-js/<name>')`) to the property path on the
// CryptoJS object that the module's value is. An empty path means the whole CryptoJS object.
// scripts/build.mjs generates from this list: the dist shims (ESM .js + CJS .cjs + .d.ts/.d.cts),
// the legacy directory stubs for resolvers that ignore "exports", and package.json "exports"/"files".
// test/package/subpaths.test.ts asserts this list equals the .js modules shipped by crypto-js.
//
// Resolution coverage:
// - "exports"-aware resolvers (Node, TypeScript node16/nodenext/bundler, webpack 5, Vite, esbuild,
//   Metro with package exports, Jest 28+): both `cryptolite/<name>` and `cryptolite/<name>.js`.
// - Resolvers that ignore "exports" (TypeScript node10, webpack 4, Metro without package exports,
//   Browserify, old Jest): `cryptolite/<name>` through the <name>/package.json stub (main = CJS
//   shim, types = .d.cts). The `.js`-suffixed form is NOT served there; that would need a root
//   file or a `<name>.js/` directory per module.
//
// Deliberate differences from crypto-js 4.2.0 (asserted in test/package/subpaths.test.ts):
// - cipher-core, hmac: crypto-js's modules evaluate to `undefined` (their factories return
//   nothing); cryptolite returns the whole CryptoJS object, so side-effect imports keep working
//   and value imports become useful.
// - pad-ansix923: crypto-js returns `CryptoJS.pad.Ansix923` (a typo, so `undefined`);
//   cryptolite returns `pad.AnsiX923`, which is what @types/crypto-js already declares.
// - crypto-js (the all-in-one UMD file): crypto-js evaluates a second, separate copy of the
//   library; cryptolite returns the same single object as the package root.

/** @typedef {{ name: string, path: string }} Subpath */

/** @type {readonly Subpath[]} */
export const SUBPATHS = Object.freeze([
  // whole object
  { name: 'core', path: '' },
  { name: 'index', path: '' },
  { name: 'crypto-js', path: '' },
  { name: 'x64-core', path: '' },
  { name: 'cipher-core', path: '' },
  { name: 'hmac', path: '' },
  // lib
  { name: 'lib-typedarrays', path: 'lib.WordArray' },
  // encoders
  { name: 'enc-base64', path: 'enc.Base64' },
  { name: 'enc-base64url', path: 'enc.Base64url' },
  { name: 'enc-hex', path: 'enc.Hex' },
  { name: 'enc-latin1', path: 'enc.Latin1' },
  { name: 'enc-utf16', path: 'enc.Utf16' },
  { name: 'enc-utf8', path: 'enc.Utf8' },
  // hashers
  { name: 'md5', path: 'MD5' },
  { name: 'sha1', path: 'SHA1' },
  { name: 'sha224', path: 'SHA224' },
  { name: 'sha256', path: 'SHA256' },
  { name: 'sha384', path: 'SHA384' },
  { name: 'sha512', path: 'SHA512' },
  { name: 'sha3', path: 'SHA3' },
  { name: 'ripemd160', path: 'RIPEMD160' },
  // HMAC helpers
  { name: 'hmac-md5', path: 'HmacMD5' },
  { name: 'hmac-sha1', path: 'HmacSHA1' },
  { name: 'hmac-sha224', path: 'HmacSHA224' },
  { name: 'hmac-sha256', path: 'HmacSHA256' },
  { name: 'hmac-sha384', path: 'HmacSHA384' },
  { name: 'hmac-sha512', path: 'HmacSHA512' },
  { name: 'hmac-sha3', path: 'HmacSHA3' },
  { name: 'hmac-ripemd160', path: 'HmacRIPEMD160' },
  // key derivation
  { name: 'pbkdf2', path: 'PBKDF2' },
  { name: 'evpkdf', path: 'EvpKDF' },
  // formats
  { name: 'format-openssl', path: 'format.OpenSSL' },
  { name: 'format-hex', path: 'format.Hex' },
  // block modes
  { name: 'mode-cfb', path: 'mode.CFB' },
  { name: 'mode-ctr', path: 'mode.CTR' },
  { name: 'mode-ctr-gladman', path: 'mode.CTRGladman' },
  { name: 'mode-ofb', path: 'mode.OFB' },
  { name: 'mode-ecb', path: 'mode.ECB' },
  // paddings
  { name: 'pad-pkcs7', path: 'pad.Pkcs7' },
  { name: 'pad-ansix923', path: 'pad.AnsiX923' },
  { name: 'pad-iso10126', path: 'pad.Iso10126' },
  { name: 'pad-iso97971', path: 'pad.Iso97971' },
  { name: 'pad-zeropadding', path: 'pad.ZeroPadding' },
  { name: 'pad-nopadding', path: 'pad.NoPadding' },
  // ciphers
  { name: 'aes', path: 'AES' },
  { name: 'tripledes', path: 'TripleDES' },
  { name: 'rc4', path: 'RC4' },
  { name: 'rabbit', path: 'Rabbit' },
  { name: 'rabbit-legacy', path: 'RabbitLegacy' },
  { name: 'blowfish', path: 'Blowfish' },
].map((entry) => Object.freeze(entry)));

/**
 * crypto-js modules whose real 4.2.0 value differs from cryptolite's on purpose (see header).
 * `undefined` = crypto-js evaluates to undefined; `copy` = crypto-js returns a separate copy.
 * @type {Readonly<Record<string, 'undefined' | 'copy'>>}
 */
export const CRYPTO_JS_DIFFERENCES = Object.freeze({
  'cipher-core': 'undefined',
  hmac: 'undefined',
  'pad-ansix923': 'undefined',
  'crypto-js': 'copy',
});

/** The subpath that is the root entry itself: it maps to dist/index.* and gets no shim. */
export const ROOT_ALIAS = 'index';

/** Resolve an entry's property path against a CryptoJS object. */
export function resolvePath(root, path) {
  if (path === '') return root;
  return path.split('.').reduce((value, key) => (value == null ? undefined : value[key]), root);
}

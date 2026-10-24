// @ts-check
// Plain JavaScript CommonJS, type-checked with checkJs: require and destructuring.
const CryptoJS = require('cryptolite');
const { AES, enc, SHA256 } = require('cryptolite');
const sha256 = require('cryptolite/sha256');

/** @type {string} */
const a = SHA256('x').toString(enc.Hex);
/** @type {string} */
const b = sha256('x').toString();
/** @type {string} */
const c = AES.decrypt(CryptoJS.AES.encrypt('m', 'k').toString(), 'k').toString(enc.Utf8);

/** @param {import('cryptolite').lib.WordArray} w @returns {string} */
function hex(w) {
  return w.toString(CryptoJS.enc.Hex);
}

module.exports = { a, b, c, hex };

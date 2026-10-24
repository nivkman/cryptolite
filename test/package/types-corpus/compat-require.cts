// TypeScript CommonJS: `import x = require(...)`.
import CryptoJS = require('cryptolite');
import sha256 = require('cryptolite/sha256');
import Utf8 = require('cryptolite/enc-utf8');
import WordArray = require('cryptolite/lib-typedarrays');

const { AES, enc } = CryptoJS;
export const hash: string = sha256('abc').toString(enc.Hex);
export const plain: string = AES.decrypt(AES.encrypt('a', 'b').toString(), 'b').toString(Utf8);
export const words: CryptoJS.lib.WordArray = WordArray.create([1, 2, 3]);
// lib-typedarrays is CryptoJS.lib.WordArray: a value and, as in @types/crypto-js, a type.
export const random: WordArray = WordArray.random(8);

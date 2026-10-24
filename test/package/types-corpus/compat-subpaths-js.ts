// Per-module imports with the `.js` suffix: how Node ESM code imports crypto-js (it has no
// "exports" map, so Node ESM needs the file name).
import AES from 'cryptolite/aes.js';
import Utf8 from 'cryptolite/enc-utf8.js';
import md5 from 'cryptolite/md5.js';
import sha256 from 'cryptolite/sha256.js';
import WordArray from 'cryptolite/lib-typedarrays.js';
import core from 'cryptolite/core.js';

export const digest: string = sha256('abc').toString();
export const md5Hex: string = md5('x').toString();
export const plain: string = AES.decrypt(AES.encrypt('text', 'pass').toString(), 'pass').toString(Utf8);
export const random = WordArray.random(16);
export const fromCore: core.lib.WordArray = core.SHA256('x');

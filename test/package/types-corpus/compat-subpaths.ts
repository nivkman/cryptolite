// Per-module imports without extension (bundlers, CommonJS, TypeScript node10), as many apps and
// libraries do to keep bundles small.
import AES from 'cryptolite/aes';
import core from 'cryptolite/core';
import Base64 from 'cryptolite/enc-base64';
import Hex from 'cryptolite/enc-hex';
import Utf8 from 'cryptolite/enc-utf8';
import OpenSSL from 'cryptolite/format-openssl';
import hmacSHA512 from 'cryptolite/hmac-sha512';
import WordArray from 'cryptolite/lib-typedarrays';
import ECB from 'cryptolite/mode-ecb';
import NoPadding from 'cryptolite/pad-nopadding';
import pbkdf2 from 'cryptolite/pbkdf2';
import sha256 from 'cryptolite/sha256';

export const mac: string = Base64.stringify(hmacSHA512('message', 'key'));
export const digest: string = sha256('abc').toString(Hex);
const token: string = AES.encrypt('text', 'pass').toString();
export const plain: string = AES.decrypt(token, 'pass').toString(Utf8);
const key = pbkdf2('pw', WordArray.random(16), { keySize: 8, iterations: 10 });
export const raw = AES.encrypt('0123456789abcdef', key, { mode: ECB, padding: NoPadding, format: OpenSSL });
export const fromCore: core.lib.WordArray = core.SHA1('x');

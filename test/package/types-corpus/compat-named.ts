// `import { AES, enc } from 'crypto-js'` style.
import { AES, HmacSHA512, PBKDF2, SHA256, algo, enc, format, lib, mode, pad } from 'cryptolite';

const key: lib.WordArray = PBKDF2('passphrase', lib.WordArray.random(16), { keySize: 8, iterations: 1000, hasher: algo.SHA256 });
const iv: lib.WordArray = lib.WordArray.random(16);
const sealed: lib.CipherParams = AES.encrypt('data', key, { iv, mode: mode.CFB, padding: pad.AnsiX923, format: format.OpenSSL });
export const opened: string = AES.decrypt(sealed, key, { iv, mode: mode.CFB, padding: pad.AnsiX923 }).toString(enc.Utf8);
export const signature: string = HmacSHA512('payload', 'secret').toString(enc.Base64);
export const hash: string = SHA256('abc').toString(enc.Hex);
export const hasher = algo.SHA512.create();

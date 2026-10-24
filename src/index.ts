/**
 * cryptolite — a maintained, drop-in successor to crypto-js.
 *
 * Default export and the named exports below mirror crypto-js 4.2.0 (compat API).
 * The lowercase named exports at the bottom are the modern API (see docs/SPEC-modern.md).
 */
import CryptoJS from './compat/index';
import * as modern from './modern/index';

// CommonJS consumers get a single object (`module.exports = CryptoJS`), so the modern
// API is attached to it as well. None of these names exist on crypto-js, so nothing collides.
Object.assign(CryptoJS, modern);

export default CryptoJS;

// ---- compat named exports (same names as crypto-js top-level members) ----
export const lib = CryptoJS.lib;
export const enc = CryptoJS.enc;
export const algo = CryptoJS.algo;
export const mode = CryptoJS.mode;
export const pad = CryptoJS.pad;
export const format = CryptoJS.format;
export const kdf = CryptoJS.kdf;
export const x64 = CryptoJS.x64;

export const MD5 = CryptoJS.MD5;
export const SHA1 = CryptoJS.SHA1;
export const SHA224 = CryptoJS.SHA224;
export const SHA256 = CryptoJS.SHA256;
export const SHA384 = CryptoJS.SHA384;
export const SHA512 = CryptoJS.SHA512;
export const SHA3 = CryptoJS.SHA3;
export const RIPEMD160 = CryptoJS.RIPEMD160;

export const HmacMD5 = CryptoJS.HmacMD5;
export const HmacSHA1 = CryptoJS.HmacSHA1;
export const HmacSHA224 = CryptoJS.HmacSHA224;
export const HmacSHA256 = CryptoJS.HmacSHA256;
export const HmacSHA384 = CryptoJS.HmacSHA384;
export const HmacSHA512 = CryptoJS.HmacSHA512;
export const HmacSHA3 = CryptoJS.HmacSHA3;
export const HmacRIPEMD160 = CryptoJS.HmacRIPEMD160;

export const PBKDF2 = CryptoJS.PBKDF2;
export const EvpKDF = CryptoJS.EvpKDF;

export const AES = CryptoJS.AES;
export const DES = CryptoJS.DES;
export const TripleDES = CryptoJS.TripleDES;
export const RC4 = CryptoJS.RC4;
export const RC4Drop = CryptoJS.RC4Drop;
export const Rabbit = CryptoJS.Rabbit;
export const RabbitLegacy = CryptoJS.RabbitLegacy;
export const Blowfish = CryptoJS.Blowfish;

// ---- modern API ----
export * from './modern/index';

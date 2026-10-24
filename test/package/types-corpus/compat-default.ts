// `import CryptoJS from 'crypto-js'` style (esModuleInterop / allowSyntheticDefaultImports).
import CryptoJS from 'cryptolite';

// Hashing and encoders
const digest: string = CryptoJS.SHA256('message').toString();
const digestHex: string = CryptoJS.SHA256('message').toString(CryptoJS.enc.Hex);
const md5: string = CryptoJS.MD5('message').toString();
const sha3: string = CryptoJS.SHA3('message', { outputLength: 256 }).toString();
const hmac: string = CryptoJS.HmacSHA256('message', 'secret').toString(CryptoJS.enc.Base64);
const ripemd: CryptoJS.lib.WordArray = CryptoJS.RIPEMD160(CryptoJS.enc.Latin1.parse('abc'));

// Progressive hashing and HMAC objects
const hasher = CryptoJS.algo.SHA256.create();
hasher.update('part 1');
hasher.update(CryptoJS.enc.Utf8.parse('part 2'));
const incremental: CryptoJS.lib.WordArray = hasher.finalize();
const mac: CryptoJS.algo.HMAC = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA512, 'key');
const macHex: string = mac.update('data').finalize().toString();

// Passphrase AES (OpenSSL-compatible "Salted__" output)
const ciphertext: string = CryptoJS.AES.encrypt('my message', 'secret key 123').toString();
const original: string = CryptoJS.AES.decrypt(ciphertext, 'secret key 123').toString(CryptoJS.enc.Utf8);

// Key + IV AES with explicit mode and padding
const key: CryptoJS.lib.WordArray = CryptoJS.enc.Hex.parse('000102030405060708090a0b0c0d0e0f');
const iv = CryptoJS.enc.Hex.parse('101112131415161718191a1b1c1d1e1f');
const encrypted: CryptoJS.lib.CipherParams = CryptoJS.AES.encrypt('data', key, {
  iv,
  mode: CryptoJS.mode.CBC,
  padding: CryptoJS.pad.Pkcs7,
});
const ecb = CryptoJS.AES.encrypt('data', key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.ZeroPadding });
const ctr = CryptoJS.AES.encrypt('data', key, { iv, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding });
const ctBase64: string = encrypted.ciphertext.toString(CryptoJS.enc.Base64);
const decrypted: string = CryptoJS.AES.decrypt(encrypted, key, { iv }).toString(CryptoJS.enc.Utf8);
const params = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse(ctBase64) });
const fromParams: CryptoJS.lib.WordArray = CryptoJS.AES.decrypt(params, key, { iv });
const openssl: string = CryptoJS.format.OpenSSL.stringify(encrypted);
const parsed: CryptoJS.lib.CipherParams = CryptoJS.format.OpenSSL.parse(openssl);
const viaFormatter: string = encrypted.toString(CryptoJS.format.Hex);

// Key derivation
const salt = CryptoJS.lib.WordArray.random(128 / 8);
const pbkdf2 = CryptoJS.PBKDF2('password', salt, { keySize: 256 / 32, iterations: 1000, hasher: CryptoJS.algo.SHA256 });
const evp = CryptoJS.EvpKDF('password', 'salt', { keySize: 8, iterations: 1 });
const derivedParams: CryptoJS.lib.CipherParams = CryptoJS.kdf.OpenSSL.execute('password', 8, 4);

// WordArray
const words = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 8);
const fromBytes = CryptoJS.lib.WordArray.create(new Uint8Array([1, 2, 3]));
const joined: CryptoJS.lib.WordArray = words.clone().concat(fromBytes);
joined.clamp();
const b64url: string = CryptoJS.enc.Base64url.stringify(joined);
const utf16: string = CryptoJS.enc.Utf16LE.stringify(CryptoJS.enc.Utf16.parse('x'));
const sigBytes: number = joined.sigBytes + joined.words.length;

// Code typed against crypto-js's types
function toHex(value: CryptoJS.lib.WordArray): string {
  return value.toString(CryptoJS.enc.Hex);
}
function encryptWith(cipher: typeof CryptoJS.AES, text: string): string {
  return cipher.encrypt(text, 'passphrase').toString();
}
const x64: CryptoJS.x64.Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
const legacyCiphers = [CryptoJS.TripleDES, CryptoJS.DES, CryptoJS.RC4, CryptoJS.Rabbit, CryptoJS.Blowfish];

export const results = [
  digest, digestHex, md5, sha3, hmac, ripemd, incremental, macHex, ciphertext, original, ecb, ctr,
  decrypted, fromParams, parsed, viaFormatter, pbkdf2, evp, derivedParams, b64url, utf16, sigBytes,
  toHex(joined), encryptWith(CryptoJS.AES, 'x'), x64, legacyCiphers,
];

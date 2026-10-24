// `import * as CryptoJS from 'crypto-js'` style (common in Angular code; no esModuleInterop needed).
import * as CryptoJS from 'cryptolite';

export function encryptPayload(payload: object, secret: string): string {
  return CryptoJS.AES.encrypt(JSON.stringify(payload), secret).toString();
}

export function decryptPayload<T>(token: string, secret: string): T {
  const bytes: CryptoJS.lib.WordArray = CryptoJS.AES.decrypt(token, secret);
  return JSON.parse(bytes.toString(CryptoJS.enc.Utf8)) as T;
}

export function sign(message: string, secret: string): string {
  return CryptoJS.enc.Base64.stringify(CryptoJS.HmacSHA256(message, secret));
}

export const fingerprint: string = CryptoJS.SHA1('id').toString(CryptoJS.enc.Hex);
export const params: CryptoJS.lib.CipherParams = CryptoJS.TripleDES.encrypt('x', 'y');
export const hmacObject: CryptoJS.algo.HMAC = CryptoJS.algo.HMAC.create(CryptoJS.algo.MD5, 'k');

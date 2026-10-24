// cryptolite-only: the modern API from CommonJS (attached to module.exports).
import CryptoJS = require('cryptolite');

const { sha256, encrypt, CryptoliteError } = CryptoJS;
export const hex: string = sha256('abc');
export const token: Promise<string> = encrypt('a', 'b');
export const isError = (value: unknown): value is CryptoJS.CryptoliteError => value instanceof CryptoliteError;

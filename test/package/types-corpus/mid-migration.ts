// cryptolite installed next to @types/crypto-js (typical mid-migration): no conflicts, and the
// two typings are interchangeable. `CryptoJS` below is @types/crypto-js's global namespace.
import CL from 'cryptolite';

type Global = typeof CryptoJS;
type Lite = typeof CL;
type LiteCompat = Omit<Lite, Exclude<keyof Lite, keyof Global>>;
type Equals<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;

// Same member names as @types/crypto-js, and mutually assignable (deep, structural).
export const sameNames: Equals<keyof Global, keyof LiteCompat> = true;
export const toGlobal = (value: LiteCompat): Global => value;
export const toLite = (value: Global): LiteCompat => value;

// Values flow between code typed against either.
export const words: CryptoJS.lib.WordArray = CL.SHA256('x');
export const params: CryptoJS.lib.CipherParams = CL.AES.encrypt('a', 'b');
export const back: ReturnType<typeof CL.SHA256> = words;
export const hmac: CryptoJS.algo.HMAC = CL.algo.HMAC.create(CL.algo.SHA256, 'k');

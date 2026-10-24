// cryptolite-only: the modern API (named exports, also attached to the default object).
import CryptoJS, {
  CryptoliteError,
  type Encoding,
  type EncryptOptions,
  decrypt,
  decryptBytes,
  encrypt,
  hmac,
  isLegacy,
  randomBytes,
  sha256,
  upgrade,
} from 'cryptolite';

export async function demo(): Promise<void> {
  const options: EncryptOptions = { iterations: 100_000 };
  const token: string = await encrypt('secret', 'password', options);
  const plain: string = await decrypt(token, 'password');
  const bytes: Uint8Array = await decryptBytes(token, 'password');
  const legacy = CryptoJS.AES.encrypt('old', 'password').toString();
  const upgraded: string = isLegacy(legacy) ? await upgrade(legacy, 'password') : token;
  const hex: string = sha256('abc');
  const raw: Uint8Array = sha256('abc', 'bytes');
  const mac: string = hmac('sha256', 'key', 'data', 'base64');
  const random: Uint8Array = randomBytes(16);
  const encoding: Encoding = 'base64url';
  const viaDefault: Promise<string> = CryptoJS.encrypt('a', 'b');
  try {
    await decrypt('not a token', 'password');
  } catch (error) {
    if (error instanceof CryptoliteError) {
      const code: string = error.code;
      void code;
    }
  }
  let typedViaNamespace: CryptoJS.CryptoliteError | undefined;
  void [plain, bytes, upgraded, hex, raw, mac, random, encoding, viaDefault, typedViaNamespace];
}

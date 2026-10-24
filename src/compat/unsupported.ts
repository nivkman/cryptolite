/*
 * Ciphers crypto-js shipped that cryptolite deliberately does not implement (see
 * docs/DECISIONS.md D6). They exist so imports keep working; using one throws a clear error.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { C, type Any } from './core';

const MIGRATION_URL = 'https://github.com/nivkman/cryptolite/blob/main/MIGRATION.md#unsupported-ciphers';

function unsupported(name: string): never {
  throw new Error(
    `cryptolite does not implement ${name}: it is a broken legacy cipher and cryptolite only ` +
      `ships audited primitives. Keep crypto-js for ${name} data, or migrate it — see ${MIGRATION_URL}`,
  );
}

function stub(name: string): Any {
  const helper = {
    encrypt: (): never => unsupported(name),
    decrypt: (): never => unsupported(name),
  };
  C.algo[name] = {
    create: (): never => unsupported(name),
    createEncryptor: (): never => unsupported(name),
    createDecryptor: (): never => unsupported(name),
  };
  C[name] = helper;
  return helper;
}

export const DES: Any = stub('DES');
export const TripleDES: Any = stub('TripleDES');
export const RC4: Any = stub('RC4');
export const RC4Drop: Any = stub('RC4Drop');
export const Rabbit: Any = stub('Rabbit');
export const RabbitLegacy: Any = stub('RabbitLegacy');
export const Blowfish: Any = stub('Blowfish');

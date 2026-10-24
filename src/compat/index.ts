/*
 * Assembles the crypto-js-compatible CryptoJS object. Every module below attaches its members
 * to the shared namespace (like crypto-js's own modules); importing a binding from each one
 * keeps bundlers from dropping it.
 */
import { C } from './core';
import { X64Word } from './x64';
import { Base64 } from './enc';
import { SHA256 } from './hashers';
import { HMAC } from './hmac';
import { PBKDF2 } from './kdf';
import { BlockCipher } from './cipher-core';
import { ECB } from './modes';
import { NoPadding } from './pads';
import { AESAlgo } from './aes';
import { TripleDES } from './unsupported';
import type { CryptoJSStatic } from './types';

// Referenced so every module is retained (see header).
void [X64Word, Base64, SHA256, HMAC, PBKDF2, BlockCipher, ECB, NoPadding, AESAlgo, TripleDES];

const CryptoJS = C as CryptoJSStatic;
export default CryptoJS;

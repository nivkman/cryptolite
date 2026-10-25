| Import | min | min + gzip | min + brotli | + legal comments (esbuild default) | compat layer in output? |
|---|--:|--:|--:|--:|---|
| **Whole library** | | | | | |
| import CryptoJS from 'crypto-js' | 69.5 KiB (71,219 B) | 25.5 KiB | 20.8 KiB | +1,589 B | n/a |
| import CryptoJS from 'cryptolite' | 76.0 KiB (77,827 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| **One hash, crypto-js style** | | | | | |
| import sha256 from 'crypto-js/sha256' | 6.3 KiB (6,418 B) | 2.6 KiB | 2.4 KiB | +0 B | n/a |
| import sha256 from 'cryptolite/sha256' | 76.0 KiB (77,823 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| import { SHA256 } from 'cryptolite' | 76.0 KiB (77,801 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| **AES via subpaths (extra)** | | | | | |
| import AES from 'crypto-js/aes' + Utf8 from 'crypto-js/enc-utf8' | 18.4 KiB (18,836 B) | 6.6 KiB | 5.7 KiB | +0 B | n/a |
| import AES from 'cryptolite/aes' + Utf8 from 'cryptolite/enc-utf8' | 76.0 KiB (77,867 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| **Modern API only** | | | | | |
| import { sha256 } from 'cryptolite' | 76.0 KiB (77,801 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| import { encrypt, decrypt } from 'cryptolite' | 76.0 KiB (77,830 B) | 27.4 KiB | 23.4 KiB | +4,049 B | yes (3/3 markers) |
| **Diagnosis: dist/index.js minus `Object.assign(compat_default, modern_exports)` and `__export(modern_exports, {...})`** | | | | | |
| { sha256 } from patched dist | 62.1 KiB (63,610 B) | 22.4 KiB | 19.1 KiB | +4,049 B | yes (3/3 markers) |
| { encrypt, decrypt } from patched dist | 73.9 KiB (75,625 B) | 26.7 KiB | 22.7 KiB | +4,049 B | yes (3/3 markers) |
| **Hypothetical entries (built from src/ like tsup.config.ts; not shipped)** | | | | | |
| `cryptolite/modern` (= src/modern/index.ts): { sha256 } | 9.6 KiB (9,795 B) | 4.2 KiB | 3.8 KiB | +136 B | no |
| `cryptolite/modern` (= src/modern/index.ts): { encrypt, decrypt } | 33.1 KiB (33,939 B) | 12.5 KiB | 11.1 KiB | +136 B | no |
| split `cryptolite/sha256` (= src/compat core.ts + hashers.ts) | 30.3 KiB (31,012 B) | 11.5 KiB | 10.0 KiB | +0 B | yes (2/3 markers) |
| compat object without the modern API (= src/compat/index.ts) | 58.4 KiB (59,790 B) | 21.0 KiB | 17.9 KiB | +136 B | yes (3/3 markers) |

Extra bytes a modern-only import pays for importing from the package root (root minus hypothetical `cryptolite/modern`):
- { sha256 }: 68,006 B min / 23,713 B gzip / 20,092 B brotli
- { encrypt, decrypt }: 43,891 B min / 15,287 B gzip / 12,613 B brotli
Removing those two statements from dist (diagnosis) saves:
- { sha256 }: 14,191 B min / 5,133 B gzip / 4,405 B brotli
- { encrypt, decrypt }: 2,205 B min / 709 B gzip / 668 B brotli
cryptolite/sha256 minus crypto-js/sha256: 71,405 B min / 25,351 B gzip / 21,488 B brotli

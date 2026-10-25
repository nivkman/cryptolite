| Case | Library | samples (wall time each) | mean |
|---|---|---|--:|
| PBKDF2 SHA256 10k, keySize 8 (compat call) | crypto-js | 1.37 s, 1.35 s, 1.35 s | 1.36 s |
| PBKDF2 SHA256 10k, keySize 8 (compat call) | cryptolite | 1.18 s, 1.18 s, 1.18 s | 1.18 s |
| encrypt() short, 100k iterations (lowest allowed), noble path | cryptolite | 12.24 s, 12.29 s, 12.27 s | 12.27 s |
| PBKDF2 SHA256 600k, keySize 8 (compat call, sync noble) | cryptolite | 72.94 s, 73.28 s | 73.11 s |
| encrypt() short, default 600k iterations, noble path | cryptolite | 73.95 s, 74.36 s | 74.15 s |
| decrypt() short, 600k iterations, noble path | cryptolite | 73.35 s, 72.77 s | 73.06 s |

(engine probe: {"engine":"hermes","textEncoder":"undefined","subtle":"undefined"})


### Compat API (same call on both libraries)

| Case | crypto-js ops/s | cryptolite ops/s | crypto-js time/op | cryptolite time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|
| MD5 short (43 B string) | 135,999 (±0.6%, runs ±14%) | 187,273 (±1.3%, runs ±21%) | 7.35 µs | 5.34 µs | 1.38× (1.21–1.79) |
| SHA1 short (43 B string) | 137,943 (±0.8%, runs ±16%) | 181,972 (±1.3%, runs ±1%) | 7.25 µs | 5.50 µs | 1.32× (1.23–1.73) |
| SHA256 short (43 B string) | 130,940 (±0.7%, runs ±1%) | 159,607 (±1.5%, runs ±15%) | 7.64 µs | 6.27 µs | 1.23× (1.15–1.49) |
| SHA512 short (43 B string) | 27,944 (±1.2%, runs ±2%) | 97,158 (±1.6%, runs ±8%) | 35.8 µs | 10.3 µs | 3.51× (3.47–3.92) |
| SHA3 short (43 B string) | 14,398 (±0.7%, runs ±7%) | 55,724 (±0.8%, runs ±7%) | 69.5 µs | 17.9 µs | 4.06× (3.42–4.33) |
| MD5 1 MiB (WordArray) | 27.6 (±1.7%, runs ±4%) | 53.7 (±0.8%, runs ±3%) | 36.2 ms | 18.6 ms | 1.95× (1.88–2.05) |
| SHA1 1 MiB (WordArray) | 43.9 (±1.9%, runs ±5%) | 54.5 (±1.2%, runs ±4%) | 22.8 ms | 18.4 ms | 1.25× (1.21–1.29) |
| SHA256 1 MiB (WordArray) | 38.9 (±3.8%, runs ±4%) | 54 (±1.7%, runs ±2%) | 25.7 ms | 18.5 ms | 1.38× (1.30–1.43) |
| SHA512 1 MiB (WordArray) | 5.7 (±1.2%, runs ±3%) | 31.2 (±1.1%, runs ±4%) | 176 ms | 32.0 ms | 5.47× (5.46–5.64) |
| SHA3 1 MiB (WordArray) | 1.31 (±0.6%, runs ±3%) | 5.88 (±0.6%, runs ±2%) | 763 ms | 170 ms | 4.44× (4.22–4.65) |
| SHA256 progressive: create() + 16 × 64 KiB update() + finalize() | 45.9 (±2.4%, runs ±2%) | 25 (±2.1%, runs ±3%) | 21.8 ms | 40.0 ms | 0.540× (0.525–0.560) |
| HmacSHA256 short | 23,259 (±1.6%, runs ±2%) | 57,770 (±1.5%, runs ±16%) | 43.0 µs | 17.3 µs | 2.46× (2.32–3.05) |
| PBKDF2 SHA256, 10k iterations, keySize 8 | 7.47 (±3.8%, runs ±4%) | 33.1 (±0.9%, runs ±4%) | 134 ms | 30.3 ms | 4.50× (4.27–4.65) |
| PBKDF2 crypto-js 4.2 defaults (SHA256, 250k, keySize 4) | 0.296 (±7.6% (!), runs ±5%) | 1.3 (±7.9% (!), runs ±3%) | 3.38 s | 771 ms | 4.39× (4.35–4.98) |
| AES passphrase encrypt + toString (short) | 4,275 (±2.4%, runs ±6%) | 5,404 (±2.2%, runs ±5%) | 234 µs | 185 µs | 1.22× (1.17–1.36) |
| AES passphrase decrypt + toString(Utf8) (short) | 5,619 (±2.0%, runs ±2%) | 6,786 (±2.0%, runs ±1%) | 178 µs | 147 µs | 1.20× (1.20–1.23) |
| AES-256-CBC key+iv encrypt 1 MiB | 22.8 (±1.9%, runs ±4%) | 29.1 (±2.3%, runs ±4%) | 43.8 ms | 34.3 ms | 1.29× (1.24–1.35) |
| AES-256-CBC key+iv decrypt 1 MiB | 22.8 (±1.5%, runs ±4%) | 25.7 (±1.1%, runs ±7%) | 43.9 ms | 39.0 ms | 1.13× (1.00–1.18) |
| Base64 stringify 1 MiB | 10.4 (±2.7%, runs ±9%) | 12.4 (±5.0%, runs ±1%) | 96.0 ms | 80.8 ms | 1.19× (1.03–1.25) |
| Base64 parse 1 MiB | 51.5 (±2.8%, runs ±5%) | 50.5 (±2.7%, runs ±4%) | 19.4 ms | 19.8 ms | 0.965× (0.955–1.05) |
| Utf8 parse 1 MiB | 21 (±2.1%, runs ±4%) | 188 (±2.4%, runs ±7%) | 47.6 ms | 5.33 ms | 9.14× (7.88–9.31) |
| Utf8 stringify 1 MiB | 11.8 (±1.6%, runs ±4%) | 147 (±2.2%, runs ±4%) | 84.5 ms | 6.81 ms | 12.4× (11.8–13.4) |

### Modern API

| Case | crypto-js ops/s | cryptolite ops/s | crypto-js time/op | cryptolite time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|
| encrypt() short, Web Crypto path, 600k iterations | – | 7.94 (±1.8%, runs ±1%) | – | 126 ms | – |
| decrypt() short, Web Crypto path, 600k iterations | – | 7.88 (±1.4%, runs ±2%) | – | 127 ms | – |
| sha256() short (43 B string) | 132,842 (±0.7%, runs ±3%) | 156,683 (±1.1%, runs ±14%) | 7.53 µs | 6.38 µs | 1.20× (1.15–1.47) |
| sha256() 1 MiB (Uint8Array; crypto-js: WordArray) | 40.7 (±2.2%, runs ±4%) | 59.3 (±1.5%, runs ±4%) | 24.6 ms | 16.9 ms | 1.46× (1.36–1.57) |

### Supplementary

| Case | crypto-js ops/s | cryptolite ops/s | cryptolite modern ops/s | crypto-js time/op | cryptolite time/op | cryptolite modern time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|--:|--:|
| encrypt() short, noble path (crypto.subtle hidden), 600k | – | 0.474 (±1.9%, runs ±4%) | – | – | 2.11 s | – | – |
| decrypt() short, noble path (crypto.subtle hidden), 600k | – | 0.47 (±1.3%, runs ±3%) | – | – | 2.13 s | – | – |
| compat PBKDF2 SHA256, 600k, keySize 8 (sync noble) | – | 0.547 (±1.9%, runs ±2%) | – | – | 1.83 s | – | – |
| SHA256 of the 1 MiB UTF-8 text as a string | 13.3 (±1.9%, runs ±3%) | 51.5 (±1.1%, runs ±2%) | 41.2 (±1.4%, runs ±21%) | 75.4 ms | 19.4 ms | 24.3 ms | cryptolite: 3.88× (3.77–3.92); cryptolite modern: 3.11× (2.04–3.22) |

(isolated, 5 run(s) per case; dist/index.js sha256 6e74d9b7f415; load average 1m: 0.46 at start, 1.18 at end)

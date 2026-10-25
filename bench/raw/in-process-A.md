
### Compat API (same call on both libraries)

| Case | crypto-js ops/s ±RME | crypto-js time/op | cryptolite ops/s ±RME | cryptolite time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|
| MD5 short (43 B string) | 133,994 ±0.8% | 7.46 µs | 158,261 ±1.9% | 6.32 µs | 1.18× (±0.024) |
| SHA1 short (43 B string) | 132,539 ±0.8% | 7.54 µs | 168,113 ±1.8% | 5.95 µs | 1.27× (±0.025) |
| SHA256 short (43 B string) | 91,473 ±2.7% | 10.9 µs | 167,068 ±1.6% | 5.99 µs | 1.83× (±0.058) |
| SHA512 short (43 B string) | 27,463 ±1.4% | 36.4 µs | 79,165 ±2.5% | 12.6 µs | 2.88× (±0.083) |
| SHA3 short (43 B string) | 13,791 ±1.6% | 72.5 µs | 53,456 ±2.5% | 18.7 µs | 3.88× (±0.12) |
| MD5 1 MiB (WordArray) | 26.2 ±2.1% | 38.1 ms | 52.9 ±1.1% | 18.9 ms | 2.02× (±0.048) |
| SHA1 1 MiB (WordArray) | 35 ±1.8% | 28.5 ms | 52.5 ±1.6% | 19.0 ms | 1.50× (±0.036) |
| SHA256 1 MiB (WordArray) | 37.9 ±2.5% | 26.4 ms | 53.8 ±1.4% | 18.6 ms | 1.42× (±0.041) |
| SHA512 1 MiB (WordArray) | 5.74 ±2.3% | 174 ms | 32.4 ±1.1% | 30.9 ms | 5.63× (±0.14) |
| SHA3 1 MiB (WordArray) | 1.27 ±3.3% | 787 ms | 5.82 ±0.8% | 172 ms | 4.58× (±0.16) |
| SHA256 progressive: create() + 16 × 64 KiB update() + finalize() | 39.9 ±2.5% | 25.1 ms | 36.8 ±3.7% | 27.2 ms | 0.924× (±0.042) |
| HmacSHA256 short | 19,905 ±4.3% | 50.2 µs | 45,674 ±4.7% | 21.9 µs | 2.29× (±0.15) |
| PBKDF2 SHA256, 10k iterations, keySize 8 | 5.88 ±5.3% (!) | 170 ms | 31.2 ±2.3% | 32.1 ms | 5.31× (±0.31) |
| PBKDF2 crypto-js 4.2 defaults (SHA256, 250k, keySize 4) | 0.282 ±6.9% (!) | 3.54 s | 1.32 ±8.7% (!) | 758 ms | 4.67× (±0.52) |
| AES passphrase encrypt + toString (short) | 4,045 ±2.1% | 247 µs | 5,165 ±2.4% | 194 µs | 1.28× (±0.041) |
| AES passphrase decrypt + toString(Utf8) (short) | 4,834 ±3.5% | 207 µs | 5,568 ±4.4% | 180 µs | 1.15× (±0.065) |
| AES-256-CBC key+iv encrypt 1 MiB | 23.3 ±1.7% | 43.0 ms | 29.9 ±1.3% | 33.5 ms | 1.28× (±0.028) |
| AES-256-CBC key+iv decrypt 1 MiB | 24.9 ±1.8% | 40.1 ms | 26.2 ±2.9% | 38.2 ms | 1.05× (±0.036) |
| Base64 stringify 1 MiB | 10.7 ±4.9% | 93.8 ms | 11.7 ±3.6% | 85.2 ms | 1.10× (±0.067) |
| Base64 parse 1 MiB | 51.5 ±2.8% | 19.4 ms | 59.5 ±2.3% | 16.8 ms | 1.16× (±0.041) |
| Utf8 parse 1 MiB | 21 ±1.6% | 47.6 ms | 198 ±2.2% | 5.04 ms | 9.44× (±0.25) |
| Utf8 stringify 1 MiB | 11.2 ±3.3% | 89.1 ms | 150 ±1.6% | 6.68 ms | 13.4× (±0.49) |

### Modern API

| Case | crypto-js ops/s ±RME | crypto-js time/op | cryptolite ops/s ±RME | cryptolite time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|
| encrypt() short, Web Crypto path, 600k iterations | – | – | 7.99 ±1.1% | 125 ms | – |
| decrypt() short, Web Crypto path, 600k iterations | – | – | 7.53 ±2.8% | 133 ms | – |
| sha256() short (43 B string) | 120,392 ±0.8% | 8.31 µs | 193,368 ±0.8% | 5.17 µs | 1.61× (±0.018) |
| sha256() 1 MiB (Uint8Array; crypto-js: WordArray) | 36.7 ±2.0% | 27.2 ms | 61.3 ±1.1% | 16.3 ms | 1.67× (±0.038) |

### Supplementary

| Case | crypto-js ops/s ±RME | crypto-js time/op | cryptolite ops/s ±RME | cryptolite time/op | cryptolite modern ops/s ±RME | cryptolite modern time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|--:|--:|
| encrypt() short, noble path (crypto.subtle hidden), 600k | – | – | 0.468 ±2.7% | 2.14 s | – | – | – |
| decrypt() short, noble path (crypto.subtle hidden), 600k | – | – | 0.481 ±5.9% (!) | 2.08 s | – | – | – |
| compat PBKDF2 SHA256, 600k, keySize 8 (sync noble) | – | – | 0.542 ±3.7% | 1.85 s | – | – | – |
| SHA256 of the 1 MiB UTF-8 text as a string | 12.7 ±1.6% | 78.4 ms | 50.1 ±0.7% | 20.0 ms | 41.1 ±1.0% | 24.3 ms | cryptolite: 3.93× (±0.068); cryptolite modern: 3.22× (±0.060) |

(load average 1m: 0.73 at start, 1.66 at end)

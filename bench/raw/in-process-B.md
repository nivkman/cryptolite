
### Compat API (same call on both libraries)

| Case | crypto-js ops/s ±RME | crypto-js time/op | cryptolite ops/s ±RME | cryptolite time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|
| MD5 short (43 B string) | 133,878 ±0.8% | 7.47 µs | 239,371 ±0.9% | 4.18 µs | 1.79× (±0.022) |
| SHA1 short (43 B string) | 143,041 ±0.9% | 6.99 µs | 147,335 ±1.6% | 6.79 µs | 1.03× (±0.019) |
| SHA256 short (43 B string) | 120,601 ±1.0% | 8.29 µs | 158,741 ±1.5% | 6.30 µs | 1.32× (±0.023) |
| SHA512 short (43 B string) | 27,064 ±1.4% | 36.9 µs | 97,148 ±1.6% | 10.3 µs | 3.59× (±0.075) |
| SHA3 short (43 B string) | 14,638 ±0.6% | 68.3 µs | 55,354 ±0.9% | 18.1 µs | 3.78× (±0.041) |
| MD5 1 MiB (WordArray) | 25.5 ±1.6% | 39.2 ms | 55.3 ±0.8% | 18.1 ms | 2.17× (±0.040) |
| SHA1 1 MiB (WordArray) | 35.3 ±1.8% | 28.3 ms | 54.7 ±1.1% | 18.3 ms | 1.55× (±0.033) |
| SHA256 1 MiB (WordArray) | 34.4 ±3.4% | 29.1 ms | 51.7 ±1.7% | 19.4 ms | 1.50× (±0.056) |
| SHA512 1 MiB (WordArray) | 5.14 ±2.2% | 194 ms | 30 ±1.2% | 33.3 ms | 5.84× (±0.14) |
| SHA3 1 MiB (WordArray) | 1.33 ±2.0% | 754 ms | 5.79 ±1.5% | 173 ms | 4.36× (±0.11) |
| SHA256 progressive: create() + 16 × 64 KiB update() + finalize() | 41.1 ±2.0% | 24.3 ms | 37.8 ±3.2% | 26.5 ms | 0.919× (±0.035) |
| HmacSHA256 short | 21,344 ±1.9% | 46.9 µs | 52,861 ±1.2% | 18.9 µs | 2.48× (±0.055) |
| PBKDF2 SHA256, 10k iterations, keySize 8 | 6.76 ±2.9% | 148 ms | 31.6 ±1.4% | 31.7 ms | 4.68× (±0.15) |
| PBKDF2 crypto-js 4.2 defaults (SHA256, 250k, keySize 4) | 0.274 ±3.1% | 3.65 s | 1.28 ±6.7% (!) | 780 ms | 4.68× (±0.35) |
| AES passphrase encrypt + toString (short) | 4,247 ±2.4% | 235 µs | 5,318 ±2.6% | 188 µs | 1.25× (±0.045) |
| AES passphrase decrypt + toString(Utf8) (short) | 5,275 ±2.2% | 190 µs | 5,951 ±2.5% | 168 µs | 1.13× (±0.038) |
| AES-256-CBC key+iv encrypt 1 MiB | 22.3 ±2.3% | 44.9 ms | 28.1 ±1.1% | 35.6 ms | 1.26× (±0.032) |
| AES-256-CBC key+iv decrypt 1 MiB | 22.7 ±4.0% | 44.1 ms | 25 ±2.0% | 40.0 ms | 1.10× (±0.050) |
| Base64 stringify 1 MiB | 11.9 ±1.7% | 83.7 ms | 11.8 ±3.3% | 85.0 ms | 0.985× (±0.036) |
| Base64 parse 1 MiB | 48.8 ±2.9% | 20.5 ms | 54.2 ±2.9% | 18.4 ms | 1.11× (±0.046) |
| Utf8 parse 1 MiB | 21.1 ±2.1% | 47.4 ms | 201 ±2.0% | 4.97 ms | 9.54× (±0.28) |
| Utf8 stringify 1 MiB | 11.9 ±2.5% | 83.9 ms | 149 ±1.8% | 6.70 ms | 12.5× (±0.39) |

### Modern API

| Case | crypto-js ops/s ±RME | crypto-js time/op | cryptolite ops/s ±RME | cryptolite time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|
| encrypt() short, Web Crypto path, 600k iterations | – | – | 7.71 ±2.3% | 130 ms | – |
| decrypt() short, Web Crypto path, 600k iterations | – | – | 7.97 ±1.9% | 126 ms | – |
| sha256() short (43 B string) | 119,399 ±1.0% | 8.38 µs | 151,696 ±1.0% | 6.59 µs | 1.27× (±0.018) |
| sha256() 1 MiB (Uint8Array; crypto-js: WordArray) | 40.6 ±2.4% | 24.6 ms | 55.7 ±1.9% | 18.0 ms | 1.37× (±0.042) |

### Supplementary

| Case | crypto-js ops/s ±RME | crypto-js time/op | cryptolite ops/s ±RME | cryptolite time/op | cryptolite modern ops/s ±RME | cryptolite modern time/op | Speedup vs crypto-js |
|---|--:|--:|--:|--:|--:|--:|--:|
| encrypt() short, noble path (crypto.subtle hidden), 600k | – | – | 0.463 ±2.6% | 2.16 s | – | – | – |
| decrypt() short, noble path (crypto.subtle hidden), 600k | – | – | 0.488 ±2.2% | 2.05 s | – | – | – |
| compat PBKDF2 SHA256, 600k, keySize 8 (sync noble) | – | – | 0.566 ±12.6% (!) | 1.77 s | – | – | – |
| SHA256 of the 1 MiB UTF-8 text as a string | 12.5 ±3.2% | 80.0 ms | 51.1 ±0.8% | 19.6 ms | 41.2 ±0.9% | 24.2 ms | cryptolite: 4.09× (±0.13); cryptolite modern: 3.30× (±0.11) |

(load average 1m: 0.57 at start, 1.03 at end)

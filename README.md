# cryptolite

> **Work in progress — not yet published to npm.**

A maintained, drop-in replacement for [`crypto-js`](https://www.npmjs.com/package/crypto-js), which its
maintainers have discontinued. Same API and byte-identical output, built on the audited
[`@noble/hashes`](https://github.com/paulmillr/noble-hashes) and [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers),
plus a modern authenticated-encryption API with a migration path for existing crypto-js ciphertexts.

Design decisions: [docs/DECISIONS.md](docs/DECISIONS.md).

<p align="center">
  <img src="https://pith-digest.n24q02m.com/logo.svg" alt="pith-digest" width="120">
</p>

<h1 align="center">pith-digest</h1>

<p align="center">
  <strong>pith foundation: digest (zero-dep Rust)</strong>
</p>

<p align="center">
  <a href="https://github.com/pith-hash/pith-digest/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/pith-hash/pith-digest/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-digest/actions/workflows/cd.yml"><img alt="CD" src="https://github.com/pith-hash/pith-digest/actions/workflows/cd.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-digest/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/pith-hash/pith-digest?display_name=tag&sort=semver"></a>
  <a href="https://github.com/n24q02m/better-semantic-release"><img alt="semantic-release" src="https://img.shields.io/badge/semantic--release-e10079?logo=semantic-release&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/pith-hash/pith-digest"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#the-pith-suite-contract">Suite contract</a>
</p>

<!-- BEGIN: AUTO-GENERATED-CROSS-PROMO -->
<!-- END: AUTO-GENERATED-CROSS-PROMO -->

## The pith suite contract

pith-digest is part of the **pith** suite (pith-hash). Every suite repository
follows the same rules; CI enforces them mechanically:

- **Naming**: a library is always `pith-<domain>` (`pith-image`, `pith-audio`,
  `pith-zip`, ...). The curator/repository of repositories is the bare
  `pith-hash`. Never invent a second naming scheme inside the suite.
- **Version pinning**: cross-library dependencies pin `~0.1` (e.g.
  `pith-image = { version = "~0.1", path = "../pith-image" }`). The whole suite
  moves together inside 0.1.x; breaking changes require a suite-wide version
  bump, never a silent minor drift.
- **Zero third-party dependencies**: every crate depends only on other
  `pith-*` crates plus `std`. `scripts/check-zero-deps.py` (run in CI) fails
  the build on any other crate, for normal, build and dev dependencies alike.
- **No unsafe**: every crate root carries `#![forbid(unsafe_code)]`.
- **Hex-exact vectors**: `reference.json` at the repo root is the
  cross-language source of truth. The `gen-reference` binary regenerates it;
  CI verifies the committed copy is current (`gen-reference verify`), and CD
  ships the regenerated file with every SDK artifact. Python, Node and Go SDKs
  MUST test against the same bytes.

## Repository layout

```
crates/            one published crate per suite lib (pith-<domain>)
tools/gen-reference  the vector generator binary (bin name: gen-reference)
sdk/python         ctypes wheel; build backend reads PITH_CDYLIB_DIR
sdk/node           koffi-based package; prebuilds/<os-arch>/ carry the cdylib
sdk/go             cgo binding; go.mod carries the module's cgo flags
fuzz/corpus        fuzz inputs, replayed by tests/fuzz_corpus.rs (parser crates)
reference.json     hex-exact cross-SDK test vectors
```

## Install

Rust (the core library):

```bash
cargo add pith-digest
```

Python / Node / Go SDKs are published from the same cdylib on every release;
see the release assets or the package registries for the matching version.

## Quick start

Rust:

```rust
use pith_digest::{Digest, crc32, sha256};

// SHA-256 (FIPS 180-2): fixed-width `Digest<32>`, hex output without
// allocation — written into a caller-owned buffer.
let digest = sha256(b"pith").unwrap();
let mut hex = [0u8; Digest::<32>::HEX_LEN];
digest.to_hex_into(&mut hex).unwrap();
assert_eq!(&hex[..], b"158b993c2b8d4c22e5640dc7b2910dd9b4a70cee21eebd82b2eeecc06f7266e6");
assert_eq!(digest.to_string(), "158b993c2b8d4c22e5640dc7b2910dd9b4a70cee21eebd82b2eeecc06f7266e6");

// Checksums: CRC-32 (PNG/zlib), Adler-32 (RFC 1950), FNV-1a 64.
assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
assert_eq!(pith_digest::adler32(b"Wikipedia"), 0x11E6_0398);
assert_eq!(pith_digest::fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);

// Bit-level fields, MSB-first (the ISO media convention), never panicking.
let mut reader = pith_digest::BitReader::new(&[0b1010_0110]);
assert_eq!(reader.bits(3).unwrap(), 0b101);
assert_eq!(reader.bits(5).unwrap(), 0b0_0110);
```

The crate is `core`-only (`#![no_std]`): no allocator, no filesystem, no
environment — every result depends on its arguments alone. The committed
[`reference.json`](reference.json) carries the hex-exact test vectors;
regenerate with `cargo run --bin gen-reference -- gen` and verify with
`cargo run --bin gen-reference -- verify`.

Python / Node / Go SDKs are published from the same cdylib on every release;
see the release assets or the package registries for the matching version.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © pith-hash

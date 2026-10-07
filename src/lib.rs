//! The shared vocabulary of the `pith` suite: the one error type, the
//! fixed-width digest value, the Hamming distance between digests, and
//! the closed sets of names that appear in on-disk records. Also the
//! computational primitives every modality crate shares: SHA-256, the
//! checksums (CRC-32, Adler-32, FNV-1a 64), splitmix64 and the bit
//! reader.
//!
//! The foundation crate of the zero-dependency `pith` suite. Every other
//! crate builds on these types and nothing builds beneath them: this
//! crate has an empty `[dependencies]` table, enforced by
//! `scripts/check-zero-deps.py`.
//!
//! The crate is `core`-only in its library shape: no filesystem,
//! network, clock or environment, and no code path allocates. The
//! `std` feature (on by default) links `std` so the `cdylib` the
//! language SDKs bind through carries a panic handler; the library
//! surface itself stays `core`-only either way.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(missing_docs)]

mod bitreader;
mod checksums;
mod digest;
mod distance;
mod error;
mod names;
mod sha256;
mod splitmix64;

pub mod ffi;

pub use crate::bitreader::BitReader;
pub use crate::checksums::{adler32, crc32, fnv1a64};
pub use crate::digest::{Digest, Read};
pub use crate::distance::hamming;
pub use crate::error::{Error, Result};
pub use crate::names::{Algorithm, Format};
pub use crate::sha256::sha256;
pub use crate::splitmix64::SplitMix64;

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
//! Conformance: every published reference vector, replayed through the
//! library AND its C ABI surface.

use pith_digest::{SplitMix64, adler32, crc32, ffi, fnv1a64, sha256};

/// The FFI surface reproduces the library's own results byte-for-byte
/// (one representative vector per operation; the full vector corpus is
/// the lib unit tests' job).
#[test]
fn ffi_surface_matches_the_library() {
    // sha256: FIPS 180-2 "abc".
    let mut out = [0u8; 32];
    let status = unsafe { ffi::pith_digest_sha256(b"abc".as_ptr(), 3, out.as_mut_ptr()) };
    assert_eq!(status, ffi::PITH_OK);
    assert_eq!(out, *sha256(b"abc").expect("within size limit").as_bytes());

    // crc32 of "123456789".
    let mut c = 0u32;
    let status = unsafe { ffi::pith_digest_crc32(b"123456789".as_ptr(), 9, &mut c) };
    assert_eq!(status, ffi::PITH_OK);
    assert_eq!(c, crc32(b"123456789"));
    assert_eq!(c, 0xcbf4_3926);

    // adler32 of "Wikipedia".
    let mut a = 0u32;
    let status = unsafe { ffi::pith_digest_adler32(b"Wikipedia".as_ptr(), 9, &mut a) };
    assert_eq!(status, ffi::PITH_OK);
    assert_eq!(a, adler32(b"Wikipedia"));
    assert_eq!(a, 0x11e6_0398);

    // fnv1a64 of "foobar".
    let mut f = 0u64;
    let status = unsafe { ffi::pith_digest_fnv1a64(b"foobar".as_ptr(), 6, &mut f) };
    assert_eq!(status, ffi::PITH_OK);
    assert_eq!(f, fnv1a64(b"foobar"));
    assert_eq!(f, 0x8594_4171_f739_67e8);

    // splitmix64: the paper's seed-0 sequence.
    let mut seq = [0u64; 2];
    let status = unsafe { ffi::pith_digest_splitmix64_fill(0, seq.as_mut_ptr(), 2) };
    assert_eq!(status, ffi::PITH_OK);
    let mut rng = SplitMix64::new(0);
    assert_eq!(seq, [rng.next_u64(), rng.next_u64()]);

    // Refusals: null out-slots are invalid arguments, never a write
    // through null; null data with length is refused.
    unsafe {
        assert_eq!(
            ffi::pith_digest_sha256(core::ptr::null(), 1, out.as_mut_ptr()),
            ffi::PITH_E_INVALID
        );
        assert_eq!(
            ffi::pith_digest_crc32(b"x".as_ptr(), 1, core::ptr::null_mut()),
            ffi::PITH_E_INVALID
        );
        assert_eq!(
            ffi::pith_digest_adler32(b"x".as_ptr(), 1, core::ptr::null_mut()),
            ffi::PITH_E_INVALID
        );
        assert_eq!(
            ffi::pith_digest_fnv1a64(b"x".as_ptr(), 1, core::ptr::null_mut()),
            ffi::PITH_E_INVALID
        );
        assert_eq!(
            ffi::pith_digest_splitmix64_fill(0, core::ptr::null_mut(), 1),
            ffi::PITH_E_INVALID
        );
        // null data with zero length is the valid empty preimage.
        let status = unsafe { ffi::pith_digest_sha256(core::ptr::null(), 0, out.as_mut_ptr()) };
        assert_eq!(status, ffi::PITH_OK);
        assert_eq!(out, *sha256(b"").expect("within size limit").as_bytes());
    }
}

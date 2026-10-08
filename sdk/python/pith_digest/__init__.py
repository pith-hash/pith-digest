# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""pith-digest SDK: the suite's digest primitives through ctypes.

The single Rust core (the ``pith-digest`` cdylib built by
``cargo build --release``) is loaded at runtime; this package carries
no third-party dependency — ``ctypes`` is the standard library.

Discovery order (the suite's cdylib convention):

1. ``PITH_CDYLIB`` — an explicit cdylib *file* path;
2. ``PITH_CDYLIB_DIR`` — a *directory* scanned for the cdylib names
   (the CD pipeline points this at ``target/release``);
3. the package directory itself (the built wheel ships the cdylib as
   package data);
4. ``<repo root>/target/release`` — the repository working-tree layout,
   so a source checkout runs against a local cargo build with no
   configuration.

The FFI surface is five digest primitives, every one writing into a
caller-provided out-parameter (nothing is allocated, so there is no
``_free``): ``pith_digest_sha256`` (32 raw bytes), ``pith_digest_crc32``
/ ``pith_digest_adler32`` (``u32``), ``pith_digest_fnv1a64`` (``u64``)
and ``pith_digest_splitmix64_fill`` (a seeded output sequence).
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

__all__ = [
    "FfiError",
    "LibraryNotFoundError",
    "find_cdylib",
    "sha256",
    "sha1",
    "sha512",
    "hmac_sha1",
    "hmac_sha256",
    "hmac_sha512",
    "xxh64",
    "murmur3_x64_128",
    "crc32c",
    "base64_encode",
    "base64_decode",
    "xoshiro256_fill",
    "crc32",
    "adler32",
    "fnv1a64",
    "splitmix64_fill",
    "STATUS_OK",
    "STATUS_INVALID",
    "STATUS_REJECTED",
]

#: Status: success.
STATUS_OK = 0
#: Status: a caller argument is invalid (a null pointer or a null
#: output slot).
STATUS_INVALID = -1
#: Status: the core primitive refused the input (only reachable for a
#: SHA-256 input beyond the padding format's length ceiling).
STATUS_REJECTED = -2

#: Every cdylib file name cargo may drop into the build directory, per
#: platform (windows / linux / macOS).
CDYLIB_NAMES = ("pith_digest.dll", "libpith_digest.so", "libpith_digest.dylib")


class LibraryNotFoundError(OSError):
    """No cdylib was found through the discovery chain."""


class FfiError(Exception):
    """A non-zero status code came back from the cdylib."""

    def __init__(self, op: str, status: int) -> None:
        kind = {
            STATUS_INVALID: "invalid argument",
            STATUS_REJECTED: "input rejected",
        }.get(status, "unknown failure")
        super().__init__(f"{op} failed: {kind} (status {status})")
        #: The raw status code the FFI returned.
        self.status = status


def find_cdylib() -> Path:
    """Locates the cdylib through the suite's discovery chain."""
    explicit = os.environ.get("PITH_CDYLIB")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
    env_dir = os.environ.get("PITH_CDYLIB_DIR")
    candidates: list[Path] = []
    if env_dir:
        env_dir_path = Path(env_dir)
        candidates.append(env_dir_path)
        if not env_dir_path.is_absolute():
            # CD and local runs invoke tools from the repository root or
            # from sdk/<lang>; resolve the env value against both.
            candidates.append(Path.cwd() / env_dir_path)
            candidates.append(Path(__file__).resolve().parents[3] / env_dir_path)
    candidates.append(Path(__file__).resolve().parent)  # packaged wheel
    candidates.append(Path(__file__).resolve().parents[3] / "target" / "release")
    for directory in candidates:
        for name in CDYLIB_NAMES:
            p = directory / name
            if p.is_file():
                return p
    raise LibraryNotFoundError(
        "no pith-digest cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, "
        "the package directory and <repo>/target/release); "
        "run `cargo build --release` first"
    )


_lib: ctypes.CDLL | None = None


def _load() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        lib = ctypes.CDLL(str(find_cdylib()))
        for name in ("pith_digest_crc32", "pith_digest_adler32"):
            fn = getattr(lib, name)
            fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint32)]
            fn.restype = ctypes.c_int32
        lib.pith_digest_fnv1a64.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        lib.pith_digest_fnv1a64.restype = ctypes.c_int32
        lib.pith_digest_sha256.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_char_p,  # 32-byte out slot
        ]
        lib.pith_digest_sha256.restype = ctypes.c_int32
        lib.pith_digest_splitmix64_fill.argtypes = [
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
        ]
        lib.pith_digest_splitmix64_fill.restype = ctypes.c_int32
        for name, out_len in (
            ("pith_digest_sha1", 20),
            ("pith_digest_sha512", 64),
        ):
            fn = getattr(lib, name)
            fn.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_char_p,  # out_len-byte out slot
            ]
            fn.restype = ctypes.c_int32
        for name, out_len in (
            ("pith_digest_hmac_sha1", 20),
            ("pith_digest_hmac_sha256", 32),
            ("pith_digest_hmac_sha512", 64),
        ):
            fn = getattr(lib, name)
            fn.argtypes = [
                ctypes.c_void_p,  # key
                ctypes.c_size_t,
                ctypes.c_void_p,  # data
                ctypes.c_size_t,
                ctypes.c_char_p,  # out_len-byte out slot
            ]
            fn.restype = ctypes.c_int32
        lib.pith_digest_xxh64.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        lib.pith_digest_xxh64.restype = ctypes.c_int32
        lib.pith_digest_murmur3_x64_128.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.c_char_p,  # 16-byte out slot
        ]
        lib.pith_digest_murmur3_x64_128.restype = ctypes.c_int32
        lib.pith_digest_crc32c.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.pith_digest_crc32c.restype = ctypes.c_int32
        for name in ("pith_digest_base64_encode", "pith_digest_base64_decode"):
            fn = getattr(lib, name)
            fn.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_char_p,  # caller-provided out buffer
                ctypes.c_size_t,  # capacity
                ctypes.POINTER(ctypes.c_size_t),  # written length
            ]
            fn.restype = ctypes.c_int32
        lib.pith_digest_xoshiro256_fill.argtypes = [
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
        ]
        lib.pith_digest_xoshiro256_fill.restype = ctypes.c_int32
        _lib = lib
    return _lib


def _bytes_op(fn: ctypes._FuncType, data: bytes, out: ctypes._CData, op: str) -> int:
    status = fn(data, len(data), ctypes.byref(out))
    if status != STATUS_OK:
        raise FfiError(op, status)
    return out.value


def sha256(data: bytes) -> bytes:
    """The 32-byte SHA-256 digest of ``data``."""
    out = (ctypes.c_char * 32)()
    status = _load().pith_digest_sha256(data, len(data), out)
    if status != STATUS_OK:
        raise FfiError("pith_digest_sha256", status)
    return bytes(out)


def crc32(data: bytes) -> int:
    """The CRC-32 (IEEE 802.3, reflected) of ``data``."""
    return _bytes_op(_load().pith_digest_crc32, data, ctypes.c_uint32(), "pith_digest_crc32")


def adler32(data: bytes) -> int:
    """The Adler-32 (RFC 1950) of ``data``."""
    return _bytes_op(_load().pith_digest_adler32, data, ctypes.c_uint32(), "pith_digest_adler32")


def fnv1a64(data: bytes) -> int:
    """The FNV-1a 64 of ``data``."""
    return _bytes_op(_load().pith_digest_fnv1a64, data, ctypes.c_uint64(), "pith_digest_fnv1a64")


def splitmix64_fill(seed: int, count: int) -> list[int]:
    """The first ``count`` sequential splitmix64 outputs of the
    generator seeded with ``seed``."""
    if count < 0:
        raise ValueError("count must not be negative")
    out = (ctypes.c_uint64 * count)()
    status = _load().pith_digest_splitmix64_fill(seed, out, count)
    if status != STATUS_OK:
        raise FfiError("pith_digest_splitmix64_fill", status)
    return list(out)


def _digest_op(fn: ctypes._FuncType, data: bytes, size: int, op: str) -> bytes:
    out = (ctypes.c_char * size)()
    status = fn(data, len(data), out)
    if status != STATUS_OK:
        raise FfiError(op, status)
    return bytes(out)


def sha1(data: bytes) -> bytes:
    """The 20-byte SHA-1 digest of ``data``."""
    return _digest_op(_load().pith_digest_sha1, data, 20, "pith_digest_sha1")


def sha512(data: bytes) -> bytes:
    """The 64-byte SHA-512 digest of ``data``."""
    return _digest_op(_load().pith_digest_sha512, data, 64, "pith_digest_sha512")


def _hmac_op(fn: ctypes._FuncType, key: bytes, data: bytes, size: int, op: str) -> bytes:
    out = (ctypes.c_char * size)()
    status = fn(key, len(key), data, len(data), out)
    if status != STATUS_OK:
        raise FfiError(op, status)
    return bytes(out)


def hmac_sha1(key: bytes, data: bytes) -> bytes:
    """The 20-byte HMAC-SHA-1 of ``data`` under ``key``."""
    return _hmac_op(_load().pith_digest_hmac_sha1, key, data, 20, "pith_digest_hmac_sha1")


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """The 32-byte HMAC-SHA-256 of ``data`` under ``key``."""
    return _hmac_op(_load().pith_digest_hmac_sha256, key, data, 32, "pith_digest_hmac_sha256")


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    """The 64-byte HMAC-SHA-512 of ``data`` under ``key``."""
    return _hmac_op(_load().pith_digest_hmac_sha512, key, data, 64, "pith_digest_hmac_sha512")


def xxh64(data: bytes, seed: int = 0) -> int:
    """The XXH-64 of ``data`` under ``seed``."""
    out = ctypes.c_uint64()
    status = _load().pith_digest_xxh64(data, len(data), seed, ctypes.byref(out))
    if status != STATUS_OK:
        raise FfiError("pith_digest_xxh64", status)
    return out.value


def murmur3_x64_128(data: bytes, seed: int = 0) -> bytes:
    """The 16-byte MurmurHash3 x64 128 of ``data``."""
    out = (ctypes.c_char * 16)()
    status = _load().pith_digest_murmur3_x64_128(data, len(data), seed, out)
    if status != STATUS_OK:
        raise FfiError("pith_digest_murmur3_x64_128", status)
    return bytes(out)


def crc32c(data: bytes) -> int:
    """The CRC-32C (Castagnoli, reflected) of ``data``."""
    return _bytes_op(_load().pith_digest_crc32c, data, ctypes.c_uint32(), "pith_digest_crc32c")


def _base64_op(
    fn: ctypes._FuncType, data: bytes, capacity: int, op: str
) -> tuple[bytes, int]:
    out = (ctypes.c_char * capacity)()
    out_len = ctypes.c_size_t(0)
    status = fn(data, len(data), out, capacity, ctypes.byref(out_len))
    if status != STATUS_OK:
        raise FfiError(op, status)
    return out.raw[: out_len.value], out_len.value


def base64_encode(data: bytes) -> bytes:
    """The canonical standard-alphabet Base64 encoding of ``data``."""
    capacity = 4 * ((len(data) + 2) // 3) + 1  # payload + NUL terminator
    return _base64_op(_load().pith_digest_base64_encode, data, capacity, "pith_digest_base64_encode")[0]


def base64_decode(data: bytes) -> bytes:
    """The canonical standard-alphabet Base64 decoding of ``data``.

    Non-canonical input (wrong padding, stray characters) raises
    :class:`FfiError` with :data:`STATUS_REJECTED`.
    """
    capacity = 3 * ((len(data) + 3) // 4) + 1
    return _base64_op(_load().pith_digest_base64_decode, data, capacity, "pith_digest_base64_decode")[0]


def xoshiro256_fill(seed: int, count: int) -> list[int]:
    """The first ``count`` sequential xoshiro256** outputs of the
    generator seeded with ``seed``."""
    if count < 0:
        raise ValueError("count must not be negative")
    out = (ctypes.c_uint64 * count)()
    status = _load().pith_digest_xoshiro256_fill(seed, out, count)
    if status != STATUS_OK:
        raise FfiError("pith_digest_xoshiro256_fill", status)
    return list(out)

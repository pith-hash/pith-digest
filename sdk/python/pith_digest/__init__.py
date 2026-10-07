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

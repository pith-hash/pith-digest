# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""Hex-exact conformance: the committed reference vectors through ctypes.

Every vector in the repository-root ``reference.json`` is replayed
through the cdylib — SHA-256 digests, CRC-32 / Adler-32 / FNV-1a 64
checksums and the splitmix64 seed sequences — and compared hex-exact
against the recorded values, the same vectors the Rust
``gen-reference verify`` gate and the Node/Go SDKs check.
"""

from __future__ import annotations

import json
from pathlib import Path

import ctypes

import pytest

from pith_digest import (
    FfiError,
    STATUS_INVALID,
    STATUS_REJECTED,
    adler32,
    base64_decode,
    base64_encode,
    crc32,
    crc32c,
    find_cdylib,
    fnv1a64,
    hmac_sha1,
    hmac_sha256,
    hmac_sha512,
    murmur3_x64_128,
    sha1,
    sha256,
    sha512,
    splitmix64_fill,
    xoshiro256_fill,
    xxh64,
    _load,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

REFERENCE = json.loads((REPO_ROOT / "reference.json").read_text(encoding="utf-8"))


def test_cdylib_is_discoverable() -> None:
    path = find_cdylib()
    assert path.is_file(), path


@pytest.mark.parametrize("vector", REFERENCE["sha256"], ids=lambda v: v["input_hex"][:16])
def test_sha256_vector_is_reproduced_hex_exact(vector: dict) -> None:
    digest = sha256(bytes.fromhex(vector["input_hex"])).hex()
    assert digest == vector["digest"]


@pytest.mark.parametrize("vector", REFERENCE["crc32"], ids=lambda v: v["input_hex"][:16])
def test_crc32_vector_is_reproduced_hex_exact(vector: dict) -> None:
    assert f"{crc32(bytes.fromhex(vector['input_hex'])):08x}" == vector["crc32"]


@pytest.mark.parametrize("vector", REFERENCE["adler32"], ids=lambda v: v["input_hex"][:16])
def test_adler32_vector_is_reproduced_hex_exact(vector: dict) -> None:
    assert f"{adler32(bytes.fromhex(vector['input_hex'])):08x}" == vector["adler32"]


@pytest.mark.parametrize("vector", REFERENCE["fnv1a64"], ids=lambda v: v["input_hex"][:16])
def test_fnv1a64_vector_is_reproduced_hex_exact(vector: dict) -> None:
    assert f"{fnv1a64(bytes.fromhex(vector['input_hex'])):016x}" == vector["fnv1a64"]


@pytest.mark.parametrize(
    "vector", REFERENCE["splitmix64"], ids=lambda v: "seed-" + v["seed_hex"]
)
def test_splitmix64_vector_is_reproduced_hex_exact(vector: dict) -> None:
    outputs = splitmix64_fill(int(vector["seed_hex"], 16), len(vector["outputs"]))
    assert [f"{value:016x}" for value in outputs] == vector["outputs"]


def test_non_bytes_input_is_refused_by_the_wrapper() -> None:
    # The raw-pointer refusals (null out-slots, null data with length)
    # are covered by the Rust unit tests; this wrapper never hands the
    # cdylib anything but bytes.
    with pytest.raises(TypeError):
        crc32(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        sha256(None)  # type: ignore[arg-type]


def test_empty_input_is_the_valid_empty_preimage() -> None:
    assert sha256(b"").hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert crc32(b"") == 0
    assert adler32(b"") == 1
    assert fnv1a64(b"") == 0xCBF29CE484222325


def test_splitmix64_zero_count_is_a_noop() -> None:
    assert splitmix64_fill(0, 0) == []


def test_sha256_matches_a_rust_pinned_value() -> None:
    # The FIPS 180-2 "abc" vector, pinned in the committed
    # reference.json and re-derived by the Rust unit tests; this test
    # fails loudly even if reference.json were regenerated wrongly.
    assert sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    # splitmix64 seed 0's first output, the paper's own example.
    assert splitmix64_fill(0, 1) == [0xE220A8397B1DCDAF]


@pytest.mark.parametrize("vector", REFERENCE["sha1"], ids=lambda v: v["input_hex"][:16])
def test_sha1_vector_is_reproduced_hex_exact(vector: dict) -> None:
    digest = sha1(bytes.fromhex(vector["input_hex"])).hex()
    assert digest == vector["digest"]


@pytest.mark.parametrize("vector", REFERENCE["sha512"], ids=lambda v: v["input_hex"][:16])
def test_sha512_vector_is_reproduced_hex_exact(vector: dict) -> None:
    digest = sha512(bytes.fromhex(vector["input_hex"])).hex()
    assert digest == vector["digest"]


@pytest.mark.parametrize(
    "vector",
    REFERENCE["hmac_sha1"],
    ids=lambda v: (v["key_hex"] + v["data_hex"])[:16],
)
def test_hmac_sha1_vector_is_reproduced_hex_exact(vector: dict) -> None:
    mac = hmac_sha1(bytes.fromhex(vector["key_hex"]), bytes.fromhex(vector["data_hex"])).hex()
    assert mac == vector["mac"]


@pytest.mark.parametrize(
    "vector",
    REFERENCE["hmac_sha256"],
    ids=lambda v: (v["key_hex"] + v["data_hex"])[:16],
)
def test_hmac_sha256_vector_is_reproduced_hex_exact(vector: dict) -> None:
    mac = hmac_sha256(bytes.fromhex(vector["key_hex"]), bytes.fromhex(vector["data_hex"])).hex()
    assert mac == vector["mac"]


@pytest.mark.parametrize(
    "vector",
    REFERENCE["hmac_sha512"],
    ids=lambda v: (v["key_hex"] + v["data_hex"])[:16],
)
def test_hmac_sha512_vector_is_reproduced_hex_exact(vector: dict) -> None:
    mac = hmac_sha512(bytes.fromhex(vector["key_hex"]), bytes.fromhex(vector["data_hex"])).hex()
    assert mac == vector["mac"]


@pytest.mark.parametrize(
    "vector", REFERENCE["xxh64"], ids=lambda v: (v["input_hex"] + v["seed_hex"])[:16]
)
def test_xxh64_vector_is_reproduced_hex_exact(vector: dict) -> None:
    value = xxh64(bytes.fromhex(vector["input_hex"]), int(vector["seed_hex"], 16))
    assert f"{value:016x}" == vector["hash"]


@pytest.mark.parametrize(
    "vector", REFERENCE["murmur3_x64_128"], ids=lambda v: (v["input_hex"] + v["seed_hex"])[:16]
)
def test_murmur3_x64_128_vector_is_reproduced_hex_exact(vector: dict) -> None:
    digest = murmur3_x64_128(bytes.fromhex(vector["input_hex"]), int(vector["seed_hex"], 16)).hex()
    assert digest == vector["digest"]


@pytest.mark.parametrize("vector", REFERENCE["crc32c"], ids=lambda v: v["input_hex"][:16])
def test_crc32c_vector_is_reproduced_hex_exact(vector: dict) -> None:
    assert f"{crc32c(bytes.fromhex(vector['input_hex'])):08x}" == vector["crc32c"]


@pytest.mark.parametrize("vector", REFERENCE["base64"], ids=lambda v: v["input_hex"][:16] or "empty")
def test_base64_vector_is_reproduced_hex_exact(vector: dict) -> None:
    data = bytes.fromhex(vector["input_hex"])
    encoded = base64_encode(data)
    assert encoded.hex() == vector["encoded_hex"]
    # The recorded encoding decodes back to the same preimage.
    assert base64_decode(encoded) == data


@pytest.mark.parametrize(
    "vector", REFERENCE["xoshiro256ss"], ids=lambda v: "seed-" + v["seed_hex"]
)
def test_xoshiro256ss_vector_is_reproduced_hex_exact(vector: dict) -> None:
    outputs = xoshiro256_fill(int(vector["seed_hex"], 16), len(vector["outputs"]))
    assert [f"{value:016x}" for value in outputs] == vector["outputs"]


def test_null_out_slot_is_refused_with_status_invalid() -> None:
    # A null out-slot must surface the -1 path, not a crash; the wrapper
    # never builds this call itself, so it goes through the raw symbols.
    lib = _load()
    for call in (
        lambda: lib.pith_digest_sha1(b"x", 1, None),
        lambda: lib.pith_digest_sha512(b"x", 1, None),
        lambda: lib.pith_digest_hmac_sha1(b"k", 1, b"d", 1, None),
        lambda: lib.pith_digest_hmac_sha256(b"k", 1, b"d", 1, None),
        lambda: lib.pith_digest_hmac_sha512(b"k", 1, b"d", 1, None),
        lambda: lib.pith_digest_murmur3_x64_128(b"x", 1, 0, None),
    ):
        assert call() == STATUS_INVALID


def test_base64_buffer_too_small_is_refused_with_status_rejected() -> None:
    lib = _load()
    out_len = ctypes.c_size_t(0)
    # Four input bytes need four output bytes (+ NUL); a 1-byte slot is too small.
    out = (ctypes.c_char * 1)()
    status = lib.pith_digest_base64_encode(b"\xff\xff\xff\xff", 4, out, 1, ctypes.byref(out_len))
    assert status == STATUS_REJECTED
    # Decoding needs 3 output bytes for a 4-char input; 1 is too small.
    out = (ctypes.c_char * 1)()
    status = lib.pith_digest_base64_decode(b"////", 4, out, 1, ctypes.byref(out_len))
    assert status == STATUS_REJECTED


def test_base64_non_canonical_input_is_refused_with_status_rejected() -> None:
    with pytest.raises(FfiError) as exc:
        base64_decode(b"Zy==")
    assert exc.value.status == STATUS_REJECTED

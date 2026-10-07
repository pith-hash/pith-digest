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

import pytest

from pith_digest import FfiError, adler32, crc32, find_cdylib, fnv1a64, sha256, splitmix64_fill

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

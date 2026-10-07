// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

// Hex-exact conformance: the committed reference vectors through koffi.
// Every vector in the repository-root reference.json is replayed through
// the cdylib — SHA-256 digests, CRC-32 / Adler-32 / FNV-1a 64 checksums
// and the splitmix64 seed sequences — and compared hex-exact against the
// recorded values, the same vectors the Rust gen-reference verify gate
// and the Python/Go SDKs check.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  FfiError,
  adler32,
  crc32,
  findCdylib,
  fnv1a64,
  hex64,
  sha256,
  splitmix64Fill,
} = require("../index.js");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

const REFERENCE = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "reference.json"), "utf8"));

test("cdylib is discoverable", () => {
  assert.ok(fs.statSync(findCdylib()).isFile());
});

for (const vector of REFERENCE.sha256) {
  test(`sha256 vector ${vector.input_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(sha256(Buffer.from(vector.input_hex, "hex")).toString("hex"), vector.digest);
  });
}

for (const vector of REFERENCE.crc32) {
  test(`crc32 vector ${vector.input_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(crc32(Buffer.from(vector.input_hex, "hex")).toString(16).padStart(8, "0"), vector.crc32);
  });
}

for (const vector of REFERENCE.adler32) {
  test(`adler32 vector ${vector.input_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(adler32(Buffer.from(vector.input_hex, "hex")).toString(16).padStart(8, "0"), vector.adler32);
  });
}

for (const vector of REFERENCE.fnv1a64) {
  test(`fnv1a64 vector ${vector.input_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(hex64(fnv1a64(Buffer.from(vector.input_hex, "hex"))), vector.fnv1a64);
  });
}

for (const vector of REFERENCE.splitmix64) {
  test(`splitmix64 seed ${vector.seed_hex} is reproduced hex-exact`, () => {
    const outputs = splitmix64Fill(BigInt(`0x${vector.seed_hex}`), vector.outputs.length);
    assert.deepEqual(outputs.map(hex64), vector.outputs);
  });
}

test("non-Buffer input is refused by the wrapper", () => {
  // The raw-pointer refusals (null out-slots, null data with length)
  // are covered by the Rust unit tests; this wrapper never hands the
  // cdylib anything but a Buffer.
  assert.throws(() => crc32(null), TypeError);
  assert.throws(() => sha256("abc"), TypeError);
});

test("empty input is the valid empty preimage", () => {
  assert.equal(sha256(Buffer.alloc(0)).toString("hex"),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(crc32(Buffer.alloc(0)), 0);
  assert.equal(adler32(Buffer.alloc(0)), 1);
  assert.equal(hex64(fnv1a64(Buffer.alloc(0))), "cbf29ce484222325");
});

test("splitmix64 zero count is a no-op", () => {
  assert.deepEqual(splitmix64Fill(0, 0), []);
});

test("matches rust-pinned values", () => {
  // The FIPS 180-2 "abc" vector and splitmix64 seed 0's first output,
  // both pinned in the committed reference.json and re-derived by the
  // Rust unit tests; this test fails loudly even if reference.json were
  // regenerated wrongly.
  assert.equal(
    sha256(Buffer.from("abc")).toString("hex"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  assert.equal(hex64(splitmix64Fill(0, 1)[0]), "e220a8397b1dcdaf");
});

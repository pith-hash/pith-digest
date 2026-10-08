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

// ---------------------------------------------------------------------------
// New tier-1 ops: sha1 / sha512 / hmac-* / xxh64 / murmur3_x64_128 /
// crc32c / base64 / xoshiro256ss, replayed hex-exact like the sections
// above, plus the PITH_E_INVALID / PITH_E_REJECTED refusals.
// ---------------------------------------------------------------------------

const {
  STATUS_INVALID,
  STATUS_REJECTED,
  base64Decode,
  base64Encode,
  crc32c,
  hmacSha1,
  hmacSha256,
  hmacSha512,
  loadLibrary,
  murmur3X64128,
  sha1,
  sha512,
  xxh64,
  xoshiro256Fill,
} = require("../index.js");

for (const vector of REFERENCE.sha1) {
  test(`sha1 vector ${vector.input_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(sha1(Buffer.from(vector.input_hex, "hex")).toString("hex"), vector.digest);
  });
}

for (const vector of REFERENCE.sha512) {
  test(`sha512 vector ${vector.input_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(sha512(Buffer.from(vector.input_hex, "hex")).toString("hex"), vector.digest);
  });
}

for (const vector of REFERENCE.hmac_sha1) {
  test(`hmac_sha1 vector ${vector.data_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(
      hmacSha1(Buffer.from(vector.key_hex, "hex"), Buffer.from(vector.data_hex, "hex")).toString("hex"),
      vector.mac,
    );
  });
}

for (const vector of REFERENCE.hmac_sha256) {
  test(`hmac_sha256 vector ${vector.data_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(
      hmacSha256(Buffer.from(vector.key_hex, "hex"), Buffer.from(vector.data_hex, "hex")).toString("hex"),
      vector.mac,
    );
  });
}

for (const vector of REFERENCE.hmac_sha512) {
  test(`hmac_sha512 vector ${vector.data_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(
      hmacSha512(Buffer.from(vector.key_hex, "hex"), Buffer.from(vector.data_hex, "hex")).toString("hex"),
      vector.mac,
    );
  });
}

for (const vector of REFERENCE.xxh64) {
  test(`xxh64 vector ${vector.input_hex.slice(0, 16)} seed ${vector.seed_hex} is reproduced hex-exact`, () => {
    assert.equal(
      hex64(xxh64(Buffer.from(vector.input_hex, "hex"), BigInt(`0x${vector.seed_hex}`))),
      vector.hash,
    );
  });
}

for (const vector of REFERENCE.murmur3_x64_128) {
  test(`murmur3_x64_128 vector ${vector.input_hex.slice(0, 16)} seed ${vector.seed_hex} is reproduced hex-exact`, () => {
    assert.equal(
      murmur3X64128(Buffer.from(vector.input_hex, "hex"), parseInt(vector.seed_hex, 16)).toString("hex"),
      vector.digest,
    );
  });
}

for (const vector of REFERENCE.crc32c) {
  test(`crc32c vector ${vector.input_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    assert.equal(crc32c(Buffer.from(vector.input_hex, "hex")).toString(16).padStart(8, "0"), vector.crc32c);
  });
}

for (const vector of REFERENCE.base64) {
  test(`base64 vector ${vector.input_hex.slice(0, 16)} is reproduced hex-exact`, () => {
    const data = Buffer.from(vector.input_hex, "hex");
    const encoded = Buffer.from(vector.encoded_hex, "hex").toString("ascii");
    assert.equal(base64Encode(data), encoded);
    assert.deepEqual([...base64Decode(Buffer.from(encoded, "ascii"))], [...data]);
  });
}

for (const vector of REFERENCE.xoshiro256ss) {
  test(`xoshiro256ss seed ${vector.seed_hex} is reproduced hex-exact`, () => {
    const outputs = xoshiro256Fill(BigInt(`0x${vector.seed_hex}`), vector.outputs.length);
    assert.deepEqual(outputs.map(hex64), vector.outputs);
  });
}

test("null out-slot is refused with PITH_E_INVALID (-1)", () => {
  // koffi surfaces the int32_t return as a value; the wrappers turn
  // non-zero statuses into FfiError. At the raw binding level a null
  // out-slot comes back as the -1 status itself.
  const { sha1: raw } = loadLibrary();
  const data = Buffer.from("abc");
  assert.equal(raw(data, data.length, null), STATUS_INVALID);
});

test("too-small base64 encode buffer is refused with PITH_E_REJECTED (-2)", () => {
  const data = Buffer.from("hello");
  const tiny = Buffer.alloc(4); // canonical size for 5 bytes is 8
  assert.throws(() => base64Encode(data, tiny), (err) =>
    err instanceof FfiError && err.status === STATUS_REJECTED);
});

test("too-small base64 decode buffer is refused with PITH_E_REJECTED (-2)", () => {
  const encoded = Buffer.from("aGVsbG8=", "ascii");
  const tiny = Buffer.alloc(2); // decoded size is 5
  assert.throws(() => base64Decode(encoded, tiny), (err) =>
    err instanceof FfiError && err.status === STATUS_REJECTED);
});

test("non-canonical base64 decode is refused with PITH_E_REJECTED (-2)", () => {
  assert.throws(() => base64Decode(Buffer.from("Zy==", "ascii")), (err) =>
    err instanceof FfiError && err.status === STATUS_REJECTED);
});

test("base64 round-trip with explicit buffers of exact capacity succeeds", () => {
  const data = Buffer.from("hello");
  const enc = Buffer.alloc(8);
  assert.equal(base64Encode(data, enc), "aGVsbG8=");
  assert.deepEqual([...base64Decode(Buffer.from("aGVsbG8=", "ascii"), Buffer.alloc(6))], [...data]);
});

test("empty-input edge cases for the new ops", () => {
  assert.equal(sha1(Buffer.alloc(0)).toString("hex"), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  assert.equal(
    sha512(Buffer.alloc(0)).toString("hex"),
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  );
  assert.equal(hex64(xxh64(Buffer.alloc(0), 0n)), "ef46db3751d8e999");
  assert.equal(crc32c(Buffer.alloc(0)), 0);
  assert.deepEqual(xoshiro256Fill(0, 0), []);
});

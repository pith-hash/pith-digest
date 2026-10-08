// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

/**
 * pith-digest SDK: the suite's digest primitives through koffi.
 *
 * The single Rust core (the `pith-digest` cdylib built by
 * `cargo build --release`) is loaded at runtime; koffi is the only
 * runtime dependency.
 *
 * Discovery order (the suite's cdylib convention):
 *
 *  1. `PITH_CDYLIB` — an explicit cdylib *file* path;
 *  2. `PITH_CDYLIB_DIR` — a *directory* scanned for the cdylib names
 *     (the CD pipeline points this at `target/release`);
 *  3. `prebuilds/` — the packaged npm layout the CD publish job
 *     assembles, flat and per `<os-arch>` (e.g. `linux-x64`);
 *  4. `<repo root>/target/release` — the repository working-tree
 *     layout, so a source checkout runs against a local cargo build
 *     with no configuration.
 *
 * The FFI surface is five digest primitives, every one writing into a
 * caller-provided out-parameter (nothing is allocated, so there is no
 * `_free`): `pith_digest_sha256` (32 raw bytes), `pith_digest_crc32` /
 * `pith_digest_adler32` (u32), `pith_digest_fnv1a64` (u64) and
 * `pith_digest_splitmix64_fill` (a seeded output sequence).
 */

const koffi = require("koffi");
const fs = require("node:fs");
const path = require("node:path");

const STATUS_OK = 0;
const STATUS_INVALID = -1;
const STATUS_REJECTED = -2;

/** Every cdylib file name cargo may drop into the build directory, per platform. */
const CDYLIB_NAMES = ["pith_digest.dll", "libpith_digest.so", "libpith_digest.dylib"];

const PKG_ROOT = path.join(__dirname);
const REPO_ROOT = path.resolve(__dirname, "..", "..");

/** FfiError: a non-zero status code came back from the cdylib. */
class FfiError extends Error {
  /**
   * @param {string} op the FFI operation name
   * @param {number} status the raw status code
   */
  constructor(op, status) {
    const kind = { [STATUS_INVALID]: "invalid argument", [STATUS_REJECTED]: "input rejected" }[status] ?? "unknown failure";
    super(`${op} failed: ${kind} (status ${status})`);
    this.name = "FfiError";
    /** The raw status code the FFI returned. */
    this.status = status;
  }
}

/**
 * Locates the cdylib through the suite's discovery chain.
 * @returns {string} an absolute path to the cdylib file
 * @throws {Error} when nothing is found
 */
function findCdylib() {
  const explicit = process.env.PITH_CDYLIB;
  if (explicit && fs.statSync(explicit, { throwIfNoEntry: false })?.isFile()) {
    return path.resolve(explicit);
  }
  /** @type {string[]} */
  const dirs = [];
  const envDir = process.env.PITH_CDYLIB_DIR;
  if (envDir) {
    dirs.push(envDir);
    if (!path.isAbsolute(envDir)) {
      dirs.push(path.join(REPO_ROOT, envDir));
    }
  }
  const osArch = `${process.platform}-${process.arch}`;
  dirs.push(path.join(PKG_ROOT, "prebuilds", osArch));
  dirs.push(path.join(PKG_ROOT, "prebuilds"));
  dirs.push(path.join(REPO_ROOT, "target", "release"));
  for (const dir of dirs) {
    for (const name of CDYLIB_NAMES) {
      const p = path.join(dir, name);
      if (fs.statSync(p, { throwIfNoEntry: false })?.isFile()) return p;
    }
  }
  throw new Error(
    "no pith-digest cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, prebuilds/ and <repo>/target/release); " +
      "run `cargo build --release` first",
  );
}

let cached = undefined;

/**
 * Loads the cdylib and binds the exported symbols (lazily, once).
 * @returns {{sha256: Function, crc32: Function, adler32: Function, fnv1a64: Function, splitmix64Fill: Function}}
 */
function loadLibrary() {
  if (cached) return cached;
  const lib = koffi.load(findCdylib());
  // JS-allocated Buffers are passed by reference (zero-copy), so C-side
  // writes into the sha256 digest slot and the splitmix64 output array
  // land in the caller's Buffer directly; scalar out-params use the
  // koffi.out + array-holder pattern.
  const sha256 = lib.func("pith_digest_sha256", "int32_t", [
    "const uint8_t *",
    "size_t",
    "uint8_t *",
  ]);
  const crc32 = lib.func("pith_digest_crc32", "int32_t", [
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("uint32_t")),
  ]);
  const adler32 = lib.func("pith_digest_adler32", "int32_t", [
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("uint32_t")),
  ]);
  const fnv1a64 = lib.func("pith_digest_fnv1a64", "int32_t", [
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("uint64_t")),
  ]);
  const splitmix64Fill = lib.func("pith_digest_splitmix64_fill", "int32_t", [
    "uint64_t",
    "uint64_t *",
    "size_t",
  ]);
  const sha1 = lib.func("pith_digest_sha1", "int32_t", [
    "const uint8_t *",
    "size_t",
    "uint8_t *",
  ]);
  const sha512 = lib.func("pith_digest_sha512", "int32_t", [
    "const uint8_t *",
    "size_t",
    "uint8_t *",
  ]);
  const hmacSha1 = lib.func("pith_digest_hmac_sha1", "int32_t", [
    "const uint8_t *",
    "size_t",
    "const uint8_t *",
    "size_t",
    "uint8_t *",
  ]);
  const hmacSha256 = lib.func("pith_digest_hmac_sha256", "int32_t", [
    "const uint8_t *",
    "size_t",
    "const uint8_t *",
    "size_t",
    "uint8_t *",
  ]);
  const hmacSha512 = lib.func("pith_digest_hmac_sha512", "int32_t", [
    "const uint8_t *",
    "size_t",
    "const uint8_t *",
    "size_t",
    "uint8_t *",
  ]);
  const xxh64 = lib.func("pith_digest_xxh64", "int32_t", [
    "const uint8_t *",
    "size_t",
    "uint64_t",
    koffi.out(koffi.pointer("uint64_t")),
  ]);
  const murmur3X64128 = lib.func("pith_digest_murmur3_x64_128", "int32_t", [
    "const uint8_t *",
    "size_t",
    "uint32_t",
    "uint8_t *",
  ]);
  const crc32c = lib.func("pith_digest_crc32c", "int32_t", [
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("uint32_t")),
  ]);
  const base64Encode = lib.func("pith_digest_base64_encode", "int32_t", [
    "const uint8_t *",
    "size_t",
    "uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("size_t")),
  ]);
  const base64Decode = lib.func("pith_digest_base64_decode", "int32_t", [
    "const uint8_t *",
    "size_t",
    "uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("size_t")),
  ]);
  const xoshiro256Fill = lib.func("pith_digest_xoshiro256_fill", "int32_t", [
    "uint64_t",
    "uint64_t *",
    "size_t",
  ]);
  cached = {
    sha256, crc32, adler32, fnv1a64, splitmix64Fill,
    sha1, sha512, hmacSha1, hmacSha256, hmacSha512,
    xxh64, murmur3X64128, crc32c, base64Encode, base64Decode,
    xoshiro256Fill,
  };
  return cached;
}

/** Asserts `data` is a Buffer (empty input is a valid preimage). */
function assertData(data, op) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError(`${op}: data must be a Buffer`);
  }
}

/**
 * Computes the 32-byte SHA-256 digest of `data`.
 *
 * @param {Buffer} data the input bytes
 * @returns {Buffer} the 32-byte digest
 * @throws {FfiError} on a non-zero status (a null `data` is -1)
 */
function sha256(data) {
  assertData(data, "sha256");
  const { sha256: op } = loadLibrary();
  const out = Buffer.alloc(32);
  const status = op(data, data.length, out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_sha256", status);
  }
  return out;
}

/** The hex formatting helper every 64-bit checksum goes through. */
function hex64(value) {
  return value.toString(16).padStart(16, "0");
}

/**
 * Computes the CRC-32 (IEEE 802.3, reflected) of `data`.
 *
 * @param {Buffer} data the input bytes
 * @returns {number} the checksum
 * @throws {FfiError} on a non-zero status
 */
function crc32(data) {
  assertData(data, "crc32");
  const { crc32: op } = loadLibrary();
  const out = [0];
  const status = op(data, data.length, out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_crc32", status);
  }
  return out[0] >>> 0;
}

/**
 * Computes the Adler-32 (RFC 1950) of `data`.
 *
 * @param {Buffer} data the input bytes
 * @returns {number} the checksum
 * @throws {FfiError} on a non-zero status
 */
function adler32(data) {
  assertData(data, "adler32");
  const { adler32: op } = loadLibrary();
  const out = [0];
  const status = op(data, data.length, out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_adler32", status);
  }
  return out[0] >>> 0;
}

/**
 * Computes the FNV-1a 64 of `data`.
 *
 * @param {Buffer} data the input bytes
 * @returns {bigint} the checksum (format with `hex64`)
 * @throws {FfiError} on a non-zero status
 */
function fnv1a64(data) {
  assertData(data, "fnv1a64");
  const { fnv1a64: op } = loadLibrary();
  const out = [0n];
  const status = op(data, data.length, out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_fnv1a64", status);
  }
  return out[0];
}

/**
 * Produces the first `count` sequential splitmix64 outputs of the
 * generator seeded with `seed`.
 *
 * @param {number|bigint} seed the generator seed
 * @param {number} count how many outputs to produce
 * @returns {bigint[]} the outputs (format each with `hex64`)
 * @throws {FfiError} on a non-zero status
 */
function splitmix64Fill(seed, count) {
  if (!Number.isInteger(count) || count < 0) {
    throw new TypeError("count must be a non-negative integer");
  }
  const { splitmix64Fill: op } = loadLibrary();
  // The Buffer is passed by reference; the cdylib writes count
  // little-endian u64s into it.
  const out = Buffer.alloc(8 * count);
  const status = op(BigInt(seed), out, count);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_splitmix64_fill", status);
  }
  const values = [];
  for (let i = 0; i < count; i++) {
    values.push(out.readBigUInt64LE(8 * i));
  }
  return values;
}

/**
 * Computes the 20-byte SHA-1 digest of `data`.
 *
 * @param {Buffer} data the input bytes
 * @returns {Buffer} the 20-byte digest
 * @throws {FfiError} on a non-zero status (a null `data` is -1)
 */
function sha1(data) {
  assertData(data, "sha1");
  const { sha1: op } = loadLibrary();
  const out = Buffer.alloc(20);
  const status = op(data, data.length, out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_sha1", status);
  }
  return out;
}

/**
 * Computes the 64-byte SHA-512 digest of `data`.
 *
 * @param {Buffer} data the input bytes
 * @returns {Buffer} the 64-byte digest
 * @throws {FfiError} on a non-zero status (a null `data` is -1)
 */
function sha512(data) {
  assertData(data, "sha512");
  const { sha512: op } = loadLibrary();
  const out = Buffer.alloc(64);
  const status = op(data, data.length, out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_sha512", status);
  }
  return out;
}

/** Shared HMAC wrapper: key and data are both Buffers, out is digest-sized. */
function hmac(opName, op, key, data, digestLen) {
  if (!Buffer.isBuffer(key)) {
    throw new TypeError(`${opName}: key must be a Buffer`);
  }
  assertData(data, opName);
  const out = Buffer.alloc(digestLen);
  const status = op(key, key.length, data, data.length, out);
  if (status !== STATUS_OK) {
    throw new FfiError(opName, status);
  }
  return out;
}

/**
 * Computes HMAC-SHA-1 of `data` under `key`.
 *
 * @param {Buffer} key the HMAC key
 * @param {Buffer} data the input bytes
 * @returns {Buffer} the 20-byte MAC
 * @throws {FfiError} on a non-zero status
 */
function hmacSha1(key, data) {
  return hmac("pith_digest_hmac_sha1", loadLibrary().hmacSha1, key, data, 20);
}

/**
 * Computes HMAC-SHA-256 of `data` under `key`.
 *
 * @param {Buffer} key the HMAC key
 * @param {Buffer} data the input bytes
 * @returns {Buffer} the 32-byte MAC
 * @throws {FfiError} on a non-zero status
 */
function hmacSha256(key, data) {
  return hmac("pith_digest_hmac_sha256", loadLibrary().hmacSha256, key, data, 32);
}

/**
 * Computes HMAC-SHA-512 of `data` under `key`.
 *
 * @param {Buffer} key the HMAC key
 * @param {Buffer} data the input bytes
 * @returns {Buffer} the 64-byte MAC
 * @throws {FfiError} on a non-zero status
 */
function hmacSha512(key, data) {
  return hmac("pith_digest_hmac_sha512", loadLibrary().hmacSha512, key, data, 64);
}

/**
 * Computes the XXH64 of `data` under `seed`.
 *
 * @param {Buffer} data the input bytes
 * @param {number|bigint} seed the 64-bit seed
 * @returns {bigint} the hash (format with `hex64`)
 * @throws {FfiError} on a non-zero status
 */
function xxh64(data, seed) {
  assertData(data, "xxh64");
  const { xxh64: op } = loadLibrary();
  const out = [0n];
  const status = op(data, data.length, BigInt(seed), out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_xxh64", status);
  }
  return out[0];
}

/**
 * Computes the MurmurHash3 x64 128-bit digest of `data` under `seed`.
 *
 * @param {Buffer} data the input bytes
 * @param {number} seed the 32-bit seed
 * @returns {Buffer} the 16-byte digest (big-endian hex matches reference.json)
 * @throws {FfiError} on a non-zero status
 */
function murmur3X64128(data, seed) {
  assertData(data, "murmur3_x64_128");
  const { murmur3X64128: op } = loadLibrary();
  const out = Buffer.alloc(16);
  const status = op(data, data.length, seed >>> 0, out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_murmur3_x64_128", status);
  }
  return out;
}

/**
 * Computes the CRC-32C (Castagnoli, reflected) of `data`.
 *
 * @param {Buffer} data the input bytes
 * @returns {number} the checksum
 * @throws {FfiError} on a non-zero status
 */
function crc32c(data) {
  assertData(data, "crc32c");
  const { crc32c: op } = loadLibrary();
  const out = [0];
  const status = op(data, data.length, out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_crc32c", status);
  }
  return out[0] >>> 0;
}

/**
 * Base64-encodes `data`. With no `out` buffer, allocates the exact
 * canonical size; with one, its length is the capacity handed to the
 * cdylib (so a too-small buffer surfaces as PITH_E_REJECTED).
 *
 * @param {Buffer} data the input bytes
 * @param {Buffer} [out] optional destination buffer
 * @returns {string} the base64 text
 * @throws {FfiError} on a non-zero status (-2 when `out` is too small)
 */
function base64Encode(data, out) {
  assertData(data, "base64_encode");
  const { base64Encode: op } = loadLibrary();
  const dest = out ?? Buffer.alloc(Math.max(1, Math.ceil(data.length / 3) * 4));
  const outLen = [0];
  const status = op(data, data.length, dest, dest.length, outLen);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_base64_encode", status);
  }
  return dest.toString("ascii", 0, outLen[0]);
}

/**
 * Decodes canonical base64 `data`. With no `out` buffer, allocates the
 * maximum decoded size; with one, its length is the capacity handed to
 * the cdylib (so a too-small buffer surfaces as PITH_E_REJECTED).
 *
 * @param {Buffer} data the base64 text bytes
 * @param {Buffer} [out] optional destination buffer
 * @returns {Buffer} the decoded bytes
 * @throws {FfiError} on a non-zero status (-2 for non-canonical input
 *   or a too-small `out`)
 */
function base64Decode(data, out) {
  assertData(data, "base64_decode");
  const { base64Decode: op } = loadLibrary();
  const dest = out ?? Buffer.alloc(Math.max(1, Math.floor(data.length / 4) * 3));
  const outLen = [0];
  const status = op(data, data.length, dest, dest.length, outLen);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_base64_decode", status);
  }
  return dest.subarray(0, outLen[0]);
}

/**
 * Produces the first `count` sequential xoshiro256** outputs of the
 * generator seeded with `seed`.
 *
 * @param {number|bigint} seed the generator seed
 * @param {number} count how many outputs to produce
 * @returns {bigint[]} the outputs (format each with `hex64`)
 * @throws {FfiError} on a non-zero status
 */
function xoshiro256Fill(seed, count) {
  if (!Number.isInteger(count) || count < 0) {
    throw new TypeError("count must be a non-negative integer");
  }
  const { xoshiro256Fill: op } = loadLibrary();
  // The Buffer is passed by reference; the cdylib writes count
  // little-endian u64s into it.
  const out = Buffer.alloc(8 * count);
  const status = op(BigInt(seed), out, count);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_digest_xoshiro256_fill", status);
  }
  const values = [];
  for (let i = 0; i < count; i++) {
    values.push(out.readBigUInt64LE(8 * i));
  }
  return values;
}

module.exports = {
  STATUS_OK,
  STATUS_INVALID,
  STATUS_REJECTED,
  CDYLIB_NAMES,
  FfiError,
  findCdylib,
  loadLibrary,
  sha256,
  sha1,
  sha512,
  hmacSha1,
  hmacSha256,
  hmacSha512,
  crc32,
  crc32c,
  adler32,
  fnv1a64,
  xxh64,
  murmur3X64128,
  base64Encode,
  base64Decode,
  splitmix64Fill,
  xoshiro256Fill,
  hex64,
};

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
  cached = { sha256, crc32, adler32, fnv1a64, splitmix64Fill };
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

module.exports = {
  STATUS_OK,
  STATUS_INVALID,
  STATUS_REJECTED,
  CDYLIB_NAMES,
  FfiError,
  findCdylib,
  sha256,
  crc32,
  adler32,
  fnv1a64,
  splitmix64Fill,
  hex64,
};

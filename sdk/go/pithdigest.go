// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

// Package pithdigest provides Go bindings for the pith-digest Rust
// cdylib: the suite's digest primitives (SHA-256, CRC-32, Adler-32,
// FNV-1a 64, splitmix64).
//
// The single Rust core (built by `cargo build --release`) is loaded at
// runtime; the package carries zero module dependencies. On unix the
// cdylib is opened with dlopen through cgo, on Windows with
// LoadLibrary through the standard syscall package — both resolve the
// library through the same discovery chain, so `go build ./... &&
// go test ./...` works unchanged on every OS the CD matrix builds.
//
// Discovery order (the suite's cdylib convention):
//
//  1. PITH_CDYLIB — an explicit cdylib file path;
//  2. PITH_CDYLIB_DIR — a directory scanned for the cdylib names (the
//     CD pipeline points this at target/release);
//  3. <repo root>/target/release — the repository working-tree layout,
//     anchored at this package's source directory, so a source
//     checkout runs against a local cargo build unconfigured.
//
// The FFI surface is five digest primitives, every one writing into a
// caller-provided out-parameter (nothing is allocated, so there is no
// free function).
package pithdigest

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Status codes returned by the cdylib's C ABI.
const (
	// StatusOK: success.
	StatusOK int32 = 0
	// StatusInvalid: a caller argument is invalid (a null pointer or a
	// null output slot).
	StatusInvalid int32 = -1
	// StatusRejected: the core primitive refused the input (only
	// reachable for a SHA-256 input beyond the padding format's length
	// ceiling).
	StatusRejected int32 = -2
)

// cdylibNames are the file names cargo may drop into the build
// directory, per platform (windows / linux / macOS).
var cdylibNames = []string{"pith_digest.dll", "libpith_digest.so", "libpith_digest.dylib"}

// FfiError reports a non-zero status code from the cdylib.
type FfiError struct {
	// Op is the FFI operation name.
	Op string
	// Status is the raw status code the FFI returned.
	Status int32
}

func (e *FfiError) Error() string {
	kind := "unknown failure"
	switch e.Status {
	case StatusInvalid:
		kind = "invalid argument"
	case StatusRejected:
		kind = "input rejected"
	}
	return fmt.Sprintf("%s failed: %s (status %d)", e.Op, kind, e.Status)
}

// FindCdylib locates the cdylib through the suite's discovery chain.
func FindCdylib() (string, error) {
	if p := os.Getenv("PITH_CDYLIB"); p != "" {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return filepath.Abs(p)
		}
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("pithdigest: cannot locate the package source directory")
	}
	pkgDir := filepath.Dir(thisFile)
	repoRoot := filepath.Dir(filepath.Dir(pkgDir)) // sdk/go -> sdk -> repo root

	var dirs []string
	if env := os.Getenv("PITH_CDYLIB_DIR"); env != "" {
		dirs = append(dirs, env)
		if !filepath.IsAbs(env) {
			dirs = append(dirs, filepath.Join(repoRoot, env))
		}
	}
	dirs = append(dirs, filepath.Join(repoRoot, "target", "release"))
	for _, dir := range dirs {
		for _, name := range cdylibNames {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf(
		"pithdigest: no cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR and <repo>/target/release); run `cargo build --release` first",
	)
}

// locate resolves the cdylib path once per process.
var locate = sync.OnceValues(FindCdylib)

// dataPtr returns a pointer to data's first byte, or nil for empty
// input (the cdylib refuses null pointers with StatusInvalid).
func dataPtr(data []byte) *byte {
	if len(data) == 0 {
		return nil
	}
	return &data[0]
}

// Sha256 computes the 32-byte SHA-256 digest of data.
func Sha256(data []byte) ([32]byte, error) {
	var digest [32]byte
	libPath, err := locate()
	if err != nil {
		return digest, err
	}
	status, err := ffiSha256(libPath, dataPtr(data), len(data), &digest)
	if err != nil {
		return digest, err
	}
	if status != StatusOK {
		return digest, &FfiError{Op: "pith_digest_sha256", Status: status}
	}
	return digest, nil
}

// Crc32 computes the CRC-32 (IEEE 802.3, reflected) of data.
func Crc32(data []byte) (uint32, error) {
	libPath, err := locate()
	if err != nil {
		return 0, err
	}
	var out uint32
	status, err := ffiChecksum32(libPath, "pith_digest_crc32", dataPtr(data), len(data), &out)
	if err != nil {
		return 0, err
	}
	if status != StatusOK {
		return 0, &FfiError{Op: "pith_digest_crc32", Status: status}
	}
	return out, nil
}

// Adler32 computes the Adler-32 (RFC 1950) of data.
func Adler32(data []byte) (uint32, error) {
	libPath, err := locate()
	if err != nil {
		return 0, err
	}
	var out uint32
	status, err := ffiChecksum32(libPath, "pith_digest_adler32", dataPtr(data), len(data), &out)
	if err != nil {
		return 0, err
	}
	if status != StatusOK {
		return 0, &FfiError{Op: "pith_digest_adler32", Status: status}
	}
	return out, nil
}

// Fnv1a64 computes the FNV-1a 64 of data.
func Fnv1a64(data []byte) (uint64, error) {
	libPath, err := locate()
	if err != nil {
		return 0, err
	}
	var out uint64
	status, err := ffiChecksum64(libPath, "pith_digest_fnv1a64", dataPtr(data), len(data), &out)
	if err != nil {
		return 0, err
	}
	if status != StatusOK {
		return 0, &FfiError{Op: "pith_digest_fnv1a64", Status: status}
	}
	return out, nil
}

// SplitMix64Fill produces the first count sequential splitmix64
// outputs of the generator seeded with seed.
func SplitMix64Fill(seed uint64, count int) ([]uint64, error) {
	libPath, err := locate()
	if err != nil {
		return nil, err
	}
	out := make([]uint64, count)
	var outPtr *uint64
	if count > 0 {
		outPtr = &out[0]
	}
	status, err := ffiSplitMix64Fill(libPath, seed, outPtr, count)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_digest_splitmix64_fill", Status: status}
	}
	return out, nil
}

// Sha1 computes the 20-byte SHA-1 digest of data.
func Sha1(data []byte) ([20]byte, error) {
	var digest [20]byte
	libPath, err := locate()
	if err != nil {
		return digest, err
	}
	status, err := ffiDigest(libPath, "pith_digest_sha1", dataPtr(data), len(data), digest[:])
	if err != nil {
		return digest, err
	}
	if status != StatusOK {
		return digest, &FfiError{Op: "pith_digest_sha1", Status: status}
	}
	return digest, nil
}

// Sha512 computes the 64-byte SHA-512 digest of data.
func Sha512(data []byte) ([64]byte, error) {
	var digest [64]byte
	libPath, err := locate()
	if err != nil {
		return digest, err
	}
	status, err := ffiDigest(libPath, "pith_digest_sha512", dataPtr(data), len(data), digest[:])
	if err != nil {
		return digest, err
	}
	if status != StatusOK {
		return digest, &FfiError{Op: "pith_digest_sha512", Status: status}
	}
	return digest, nil
}

// HmacSha1 computes the 20-byte HMAC-SHA-1 of data under key.
func HmacSha1(key, data []byte) ([20]byte, error) {
	var mac [20]byte
	libPath, err := locate()
	if err != nil {
		return mac, err
	}
	status, err := ffiHmac(libPath, "pith_digest_hmac_sha1", dataPtr(key), len(key), dataPtr(data), len(data), mac[:])
	if err != nil {
		return mac, err
	}
	if status != StatusOK {
		return mac, &FfiError{Op: "pith_digest_hmac_sha1", Status: status}
	}
	return mac, nil
}

// HmacSha256 computes the 32-byte HMAC-SHA-256 of data under key.
func HmacSha256(key, data []byte) ([32]byte, error) {
	var mac [32]byte
	libPath, err := locate()
	if err != nil {
		return mac, err
	}
	status, err := ffiHmac(libPath, "pith_digest_hmac_sha256", dataPtr(key), len(key), dataPtr(data), len(data), mac[:])
	if err != nil {
		return mac, err
	}
	if status != StatusOK {
		return mac, &FfiError{Op: "pith_digest_hmac_sha256", Status: status}
	}
	return mac, nil
}

// HmacSha512 computes the 64-byte HMAC-SHA-512 of data under key.
func HmacSha512(key, data []byte) ([64]byte, error) {
	var mac [64]byte
	libPath, err := locate()
	if err != nil {
		return mac, err
	}
	status, err := ffiHmac(libPath, "pith_digest_hmac_sha512", dataPtr(key), len(key), dataPtr(data), len(data), mac[:])
	if err != nil {
		return mac, err
	}
	if status != StatusOK {
		return mac, &FfiError{Op: "pith_digest_hmac_sha512", Status: status}
	}
	return mac, nil
}

// Xxh64 computes the XXH-64 hash of data with seed.
func Xxh64(data []byte, seed uint64) (uint64, error) {
	libPath, err := locate()
	if err != nil {
		return 0, err
	}
	var out uint64
	status, err := ffiSum64Seed(libPath, "pith_digest_xxh64", dataPtr(data), len(data), seed, &out)
	if err != nil {
		return 0, err
	}
	if status != StatusOK {
		return 0, &FfiError{Op: "pith_digest_xxh64", Status: status}
	}
	return out, nil
}

// Murmur3X64_128 computes the 16-byte MurmurHash3 x64 128 digest of
// data with seed.
func Murmur3X64_128(data []byte, seed uint32) ([16]byte, error) {
	var digest [16]byte
	libPath, err := locate()
	if err != nil {
		return digest, err
	}
	status, err := ffiSum128(libPath, "pith_digest_murmur3_x64_128", dataPtr(data), len(data), seed, &digest)
	if err != nil {
		return digest, err
	}
	if status != StatusOK {
		return digest, &FfiError{Op: "pith_digest_murmur3_x64_128", Status: status}
	}
	return digest, nil
}

// Crc32c computes the CRC-32C (Castagnoli, reflected) of data.
func Crc32c(data []byte) (uint32, error) {
	libPath, err := locate()
	if err != nil {
		return 0, err
	}
	var out uint32
	status, err := ffiChecksum32(libPath, "pith_digest_crc32c", dataPtr(data), len(data), &out)
	if err != nil {
		return 0, err
	}
	if status != StatusOK {
		return 0, &FfiError{Op: "pith_digest_crc32c", Status: status}
	}
	return out, nil
}

// Base64Encode encodes data as standard base64 with padding.
func Base64Encode(data []byte) ([]byte, error) {
	libPath, err := locate()
	if err != nil {
		return nil, err
	}
	out := make([]byte, (len(data)+2)/3*4)
	var outLen int
	status, err := ffiBase64(libPath, "pith_digest_base64_encode", dataPtr(data), len(data), out, &outLen)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_digest_base64_encode", Status: status}
	}
	return out[:outLen], nil
}

// Base64Decode decodes a standard base64 string. A non-canonical
// input is refused with StatusRejected.
func Base64Decode(data []byte) ([]byte, error) {
	libPath, err := locate()
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	var outLen int
	status, err := ffiBase64(libPath, "pith_digest_base64_decode", dataPtr(data), len(data), out, &outLen)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_digest_base64_decode", Status: status}
	}
	return out[:outLen], nil
}

// Xoshiro256Fill produces the first count sequential xoshiro256**
// outputs of the generator seeded with seed.
func Xoshiro256Fill(seed uint64, count int) ([]uint64, error) {
	libPath, err := locate()
	if err != nil {
		return nil, err
	}
	out := make([]uint64, count)
	var outPtr *uint64
	if count > 0 {
		outPtr = &out[0]
	}
	status, err := ffiFill(libPath, "pith_digest_xoshiro256_fill", seed, outPtr, count)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_digest_xoshiro256_fill", Status: status}
	}
	return out, nil
}

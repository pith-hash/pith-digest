// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build !windows && cgo

package pithdigest

/*
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>

typedef int32_t (*pith_sha256_fn)(const uint8_t *, size_t, uint8_t *);
typedef int32_t (*pith_sum32_fn)(const uint8_t *, size_t, uint32_t *);
typedef int32_t (*pith_sum64_fn)(const uint8_t *, size_t, uint64_t *);
typedef int32_t (*pith_sm64_fn)(uint64_t, uint64_t *, size_t);
typedef int32_t (*pith_digest_fn)(const uint8_t *, size_t, uint8_t *);
typedef int32_t (*pith_hmac_fn)(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *);
typedef int32_t (*pith_sum64_seed_fn)(const uint8_t *, size_t, uint64_t, uint64_t *);
typedef int32_t (*pith_sum128_fn)(const uint8_t *, size_t, uint32_t, uint8_t *);
typedef int32_t (*pith_base64_fn)(const uint8_t *, size_t, uint8_t *, size_t, size_t *);

static int32_t pith_call_sha256(void *fn, const uint8_t *data, size_t len, uint8_t *out) {
    return ((pith_sha256_fn)fn)(data, len, out);
}

static int32_t pith_call_sum32(void *fn, const uint8_t *data, size_t len, uint32_t *out) {
    return ((pith_sum32_fn)fn)(data, len, out);
}

static int32_t pith_call_sum64(void *fn, const uint8_t *data, size_t len, uint64_t *out) {
    return ((pith_sum64_fn)fn)(data, len, out);
}

static int32_t pith_call_sm64(void *fn, uint64_t seed, uint64_t *out, size_t count) {
    return ((pith_sm64_fn)fn)(seed, out, count);
}

static int32_t pith_call_digest(void *fn, const uint8_t *data, size_t len, uint8_t *out) {
    return ((pith_digest_fn)fn)(data, len, out);
}

static int32_t pith_call_hmac(void *fn, const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t *out) {
    return ((pith_hmac_fn)fn)(key, key_len, data, len, out);
}

static int32_t pith_call_sum64_seed(void *fn, const uint8_t *data, size_t len, uint64_t seed, uint64_t *out) {
    return ((pith_sum64_seed_fn)fn)(data, len, seed, out);
}

static int32_t pith_call_sum128(void *fn, const uint8_t *data, size_t len, uint32_t seed, uint8_t *out) {
    return ((pith_sum128_fn)fn)(data, len, seed, out);
}

static int32_t pith_call_base64(void *fn, const uint8_t *data, size_t len, uint8_t *out, size_t cap, size_t *out_len) {
    return ((pith_base64_fn)fn)(data, len, out, cap, out_len);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// openCdylib dlopens libPath with error text surfaced verbatim.
func openCdylib(libPath string) (unsafe.Pointer, error) {
	cPath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cPath))
	handle := C.dlopen(cPath, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		msg := "unknown dlopen failure"
		if e := C.dlerror(); e != nil {
			msg = C.GoString(e)
		}
		return nil, fmt.Errorf("pithdigest: dlopen(%s): %s", libPath, msg)
	}
	return handle, nil
}

// resolve dlsyms name out of an open handle.
func resolve(handle unsafe.Pointer, libPath, name string) (unsafe.Pointer, error) {
	cName := C.CString(name)
	sym := C.dlsym(handle, cName)
	C.free(unsafe.Pointer(cName))
	if sym == nil {
		return nil, fmt.Errorf("pithdigest: symbol %s missing from %s", name, libPath)
	}
	return sym, nil
}

// ffiSha256 opens the cdylib, resolves pith_digest_sha256 and calls it.
func ffiSha256(libPath string, data *byte, n int, out *[32]byte) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, "pith_digest_sha256")
	if err != nil {
		return 0, err
	}
	var dataPtr *C.uint8_t
	if data != nil {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(data))
	}
	rc := C.pith_call_sha256(sym, dataPtr, C.size_t(n), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return int32(rc), nil
}

// ffiChecksum32 resolves a (data, len, *mut u32) checksum symbol and calls it.
func ffiChecksum32(libPath, name string, data *byte, n int, out *uint32) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, name)
	if err != nil {
		return 0, err
	}
	var dataPtr *C.uint8_t
	if data != nil {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(data))
	}
	rc := C.pith_call_sum32(sym, dataPtr, C.size_t(n), (*C.uint32_t)(unsafe.Pointer(out)))
	return int32(rc), nil
}

// ffiChecksum64 resolves a (data, len, *mut u64) checksum symbol and calls it.
func ffiChecksum64(libPath, name string, data *byte, n int, out *uint64) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, name)
	if err != nil {
		return 0, err
	}
	var dataPtr *C.uint8_t
	if data != nil {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(data))
	}
	rc := C.pith_call_sum64(sym, dataPtr, C.size_t(n), (*C.uint64_t)(unsafe.Pointer(out)))
	return int32(rc), nil
}

// ffiSplitMix64Fill resolves pith_digest_splitmix64_fill and calls it.
func ffiSplitMix64Fill(libPath string, seed uint64, out *uint64, count int) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, "pith_digest_splitmix64_fill")
	if err != nil {
		return 0, err
	}
	var outPtr *C.uint64_t
	if out != nil {
		outPtr = (*C.uint64_t)(unsafe.Pointer(out))
	}
	rc := C.pith_call_sm64(sym, C.uint64_t(seed), outPtr, C.size_t(count))
	return int32(rc), nil
}

// ffiDigest resolves a (data, len, *mut u8) digest symbol and calls it.
func ffiDigest(libPath, name string, data *byte, n int, out []byte) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, name)
	if err != nil {
		return 0, err
	}
	var dataPtr *C.uint8_t
	if data != nil {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(data))
	}
	rc := C.pith_call_digest(sym, dataPtr, C.size_t(n), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return int32(rc), nil
}

// ffiHmac resolves a (key, key_len, data, len, *mut u8) HMAC symbol
// and calls it.
func ffiHmac(libPath, name string, key *byte, keyLen int, data *byte, n int, out []byte) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, name)
	if err != nil {
		return 0, err
	}
	var keyPtr, dataPtr *C.uint8_t
	if key != nil {
		keyPtr = (*C.uint8_t)(unsafe.Pointer(key))
	}
	if data != nil {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(data))
	}
	rc := C.pith_call_hmac(sym, keyPtr, C.size_t(keyLen), dataPtr, C.size_t(n), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return int32(rc), nil
}

// ffiSum64Seed resolves a (data, len, seed u64, *mut u64) symbol and
// calls it.
func ffiSum64Seed(libPath, name string, data *byte, n int, seed uint64, out *uint64) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, name)
	if err != nil {
		return 0, err
	}
	var dataPtr *C.uint8_t
	if data != nil {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(data))
	}
	rc := C.pith_call_sum64_seed(sym, dataPtr, C.size_t(n), C.uint64_t(seed), (*C.uint64_t)(unsafe.Pointer(out)))
	return int32(rc), nil
}

// ffiSum128 resolves a (data, len, seed u32, *mut u8) 128-bit digest
// symbol and calls it.
func ffiSum128(libPath, name string, data *byte, n int, seed uint32, out *[16]byte) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, name)
	if err != nil {
		return 0, err
	}
	var dataPtr *C.uint8_t
	if data != nil {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(data))
	}
	rc := C.pith_call_sum128(sym, dataPtr, C.size_t(n), C.uint32_t(seed), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return int32(rc), nil
}

// ffiBase64 resolves a (data, len, out, cap, *mut usize) base64
// symbol and calls it.
func ffiBase64(libPath, name string, data *byte, n int, out []byte, outLen *int) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, name)
	if err != nil {
		return 0, err
	}
	var dataPtr *C.uint8_t
	if data != nil {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(data))
	}
	if len(out) == 0 {
		out = make([]byte, 1) // cap 0: pass a real slot for the out-length probe
	}
	var cOutLen C.size_t
	rc := C.pith_call_base64(sym, dataPtr, C.size_t(n), (*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &cOutLen)
	*outLen = int(cOutLen)
	return int32(rc), nil
}

// ffiFill resolves a (seed u64, *mut u64, count) fill symbol and
// calls it.
func ffiFill(libPath, name string, seed uint64, out *uint64, count int) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := resolve(handle, libPath, name)
	if err != nil {
		return 0, err
	}
	var outPtr *C.uint64_t
	if out != nil {
		outPtr = (*C.uint64_t)(unsafe.Pointer(out))
	}
	rc := C.pith_call_sm64(sym, C.uint64_t(seed), outPtr, C.size_t(count))
	return int32(rc), nil
}

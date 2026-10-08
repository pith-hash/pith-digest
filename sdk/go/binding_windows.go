// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build windows

package pithdigest

import (
	"fmt"
	"syscall"
	"unsafe"
)

// openProc loads libPath and resolves name. The library is released
// before returning: on Windows FreeLibrary unmaps the cdylib, so every
// out-parameter must be written inside the call this wraps.
func openProc(libPath, name string) (proc uintptr, release func(), err error) {
	lib, err := syscall.LoadLibrary(libPath)
	if err != nil {
		return 0, nil, fmt.Errorf("pithdigest: LoadLibrary(%s): %w", libPath, err)
	}
	release = func() { syscall.FreeLibrary(lib) }
	proc, err = syscall.GetProcAddress(lib, name)
	if err != nil {
		release()
		return 0, nil, fmt.Errorf("pithdigest: symbol %s missing from %s: %w", name, libPath, err)
	}
	return proc, release, nil
}

// ffiSha256 resolves pith_digest_sha256 and calls it, writing the
// 32-byte digest into out.
func ffiSha256(libPath string, data *byte, n int, out *[32]byte) (int32, error) {
	proc, release, err := openProc(libPath, "pith_digest_sha256")
	if err != nil {
		return 0, err
	}
	defer release()
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(&out[0])),
	)
	return int32(rc), nil
}

// ffiChecksum32 resolves a (data, len, *mut u32) checksum symbol and
// calls it.
func ffiChecksum32(libPath, name string, data *byte, n int, out *uint32) (int32, error) {
	proc, release, err := openProc(libPath, name)
	if err != nil {
		return 0, err
	}
	defer release()
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(out)),
	)
	return int32(rc), nil
}

// ffiChecksum64 resolves a (data, len, *mut u64) checksum symbol and
// calls it.
func ffiChecksum64(libPath, name string, data *byte, n int, out *uint64) (int32, error) {
	proc, release, err := openProc(libPath, name)
	if err != nil {
		return 0, err
	}
	defer release()
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(out)),
	)
	return int32(rc), nil
}

// ffiDigest resolves a (data, len, *mut u8) digest symbol and calls
// it, writing exactly len(out) bytes into out.
func ffiDigest(libPath, name string, data *byte, n int, out []byte) (int32, error) {
	proc, release, err := openProc(libPath, name)
	if err != nil {
		return 0, err
	}
	defer release()
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(&out[0])),
	)
	return int32(rc), nil
}

// ffiHmac resolves a (key, key_len, data, len, *mut u8) HMAC symbol
// and calls it.
func ffiHmac(libPath, name string, key *byte, keyLen int, data *byte, n int, out []byte) (int32, error) {
	proc, release, err := openProc(libPath, name)
	if err != nil {
		return 0, err
	}
	defer release()
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(key)),
		uintptr(keyLen),
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(&out[0])),
	)
	return int32(rc), nil
}

// ffiSum64Seed resolves a (data, len, seed u64, *mut u64) symbol and
// calls it.
func ffiSum64Seed(libPath, name string, data *byte, n int, seed uint64, out *uint64) (int32, error) {
	proc, release, err := openProc(libPath, name)
	if err != nil {
		return 0, err
	}
	defer release()
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(seed),
		uintptr(unsafe.Pointer(out)),
	)
	return int32(rc), nil
}

// ffiSum128 resolves a (data, len, seed u32, *mut u8) 128-bit digest
// symbol and calls it.
func ffiSum128(libPath, name string, data *byte, n int, seed uint32, out *[16]byte) (int32, error) {
	proc, release, err := openProc(libPath, name)
	if err != nil {
		return 0, err
	}
	defer release()
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(seed),
		uintptr(unsafe.Pointer(&out[0])),
	)
	return int32(rc), nil
}

// ffiBase64 resolves a (data, len, out, cap, *mut usize) base64
// symbol and calls it.
func ffiBase64(libPath, name string, data *byte, n int, out []byte, outLen *int) (int32, error) {
	proc, release, err := openProc(libPath, name)
	if err != nil {
		return 0, err
	}
	defer release()
	if len(out) == 0 {
		out = make([]byte, 1) // cap 0: pass a real slot for the out-length probe
	}
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(len(out)),
		uintptr(unsafe.Pointer(outLen)),
	)
	return int32(rc), nil
}

// ffiFill resolves a (seed u64, *mut u64, count) fill symbol and
// calls it, writing count outputs into out.
func ffiFill(libPath, name string, seed uint64, out *uint64, count int) (int32, error) {
	proc, release, err := openProc(libPath, name)
	if err != nil {
		return 0, err
	}
	defer release()
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(seed),
		uintptr(unsafe.Pointer(out)),
		uintptr(count),
	)
	return int32(rc), nil
}

// ffiSplitMix64Fill resolves pith_digest_splitmix64_fill and calls it,
// writing count outputs into out.
func ffiSplitMix64Fill(libPath string, seed uint64, out *uint64, count int) (int32, error) {
	proc, release, err := openProc(libPath, "pith_digest_splitmix64_fill")
	if err != nil {
		return 0, err
	}
	defer release()
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(seed),
		uintptr(unsafe.Pointer(out)),
		uintptr(count),
	)
	return int32(rc), nil
}

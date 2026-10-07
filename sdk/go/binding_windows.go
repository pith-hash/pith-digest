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

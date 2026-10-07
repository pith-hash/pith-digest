// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build !windows && !cgo

package pithdigest

import "fmt"

// The ffi helpers are unavailable without cgo on unix: there is no
// pure-Go dlopen in the standard library. Build with CGO_ENABLED=1
// (the CD pipeline always does).
func ffiSha256(string, *byte, int, *[32]byte) (int32, error) {
	return 0, fmt.Errorf("pithdigest: cgo is required to load the cdylib on this platform (build with CGO_ENABLED=1)")
}

func ffiChecksum32(string, string, *byte, int, *uint32) (int32, error) {
	return 0, fmt.Errorf("pithdigest: cgo is required to load the cdylib on this platform (build with CGO_ENABLED=1)")
}

func ffiChecksum64(string, string, *byte, int, *uint64) (int32, error) {
	return 0, fmt.Errorf("pithdigest: cgo is required to load the cdylib on this platform (build with CGO_ENABLED=1)")
}

func ffiSplitMix64Fill(string, uint64, *uint64, int) (int32, error) {
	return 0, fmt.Errorf("pithdigest: cgo is required to load the cdylib on this platform (build with CGO_ENABLED=1)")
}

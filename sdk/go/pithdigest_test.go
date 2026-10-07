// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

package pithdigest

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// reference parses the committed reference.json.
func reference(t *testing.T) struct {
	Sha256 []struct {
		InputHex string `json:"input_hex"`
		Digest   string `json:"digest"`
	} `json:"sha256"`
	Crc32 []struct {
		InputHex string `json:"input_hex"`
		Crc32    string `json:"crc32"`
	} `json:"crc32"`
	Adler32 []struct {
		InputHex string `json:"input_hex"`
		Adler32  string `json:"adler32"`
	} `json:"adler32"`
	Fnv1a64 []struct {
		InputHex string `json:"input_hex"`
		Fnv1a64  string `json:"fnv1a64"`
	} `json:"fnv1a64"`
	Splitmix64 []struct {
		SeedHex string   `json:"seed_hex"`
		Outputs []string `json:"outputs"`
	} `json:"splitmix64"`
} {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Sha256 []struct {
			InputHex string `json:"input_hex"`
			Digest   string `json:"digest"`
		} `json:"sha256"`
		Crc32 []struct {
			InputHex string `json:"input_hex"`
			Crc32    string `json:"crc32"`
		} `json:"crc32"`
		Adler32 []struct {
			InputHex string `json:"input_hex"`
			Adler32  string `json:"adler32"`
		} `json:"adler32"`
		Fnv1a64 []struct {
			InputHex string `json:"input_hex"`
			Fnv1a64  string `json:"fnv1a64"`
		} `json:"fnv1a64"`
		Splitmix64 []struct {
			SeedHex string   `json:"seed_hex"`
			Outputs []string `json:"outputs"`
		} `json:"splitmix64"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed
}

// TestReferenceVectorsHexExact replays every committed reference.json
// vector through the cdylib and compares hex-exact — the same vectors
// the Rust gen-reference verify gate and the Python/Node SDKs check.
func TestReferenceVectorsHexExact(t *testing.T) {
	ref := reference(t)
	for i, want := range ref.Sha256 {
		got, err := Sha256(mustHex(t, want.InputHex))
		if err != nil {
			t.Fatalf("sha256[%d]: %v", i, err)
		}
		if hex.EncodeToString(got[:]) != want.Digest {
			t.Errorf("sha256[%d]: digest %s, want %s", i, hex.EncodeToString(got[:]), want.Digest)
		}
	}
	for i, want := range ref.Crc32 {
		got, err := Crc32(mustHex(t, want.InputHex))
		if err != nil {
			t.Fatalf("crc32[%d]: %v", i, err)
		}
		if got != mustU32(t, want.Crc32) {
			t.Errorf("crc32[%d]: %08x, want %s", i, got, want.Crc32)
		}
	}
	for i, want := range ref.Adler32 {
		got, err := Adler32(mustHex(t, want.InputHex))
		if err != nil {
			t.Fatalf("adler32[%d]: %v", i, err)
		}
		if got != mustU32(t, want.Adler32) {
			t.Errorf("adler32[%d]: %08x, want %s", i, got, want.Adler32)
		}
	}
	for i, want := range ref.Fnv1a64 {
		got, err := Fnv1a64(mustHex(t, want.InputHex))
		if err != nil {
			t.Fatalf("fnv1a64[%d]: %v", i, err)
		}
		if got != mustU64(t, want.Fnv1a64) {
			t.Errorf("fnv1a64[%d]: %016x, want %s", i, got, want.Fnv1a64)
		}
	}
	for i, want := range ref.Splitmix64 {
		got, err := SplitMix64Fill(mustU64(t, want.SeedHex), len(want.Outputs))
		if err != nil {
			t.Fatalf("splitmix64[%d]: %v", i, err)
		}
		for j, out := range got {
			if out != mustU64(t, want.Outputs[j]) {
				t.Errorf("splitmix64[%d][%d]: %016x, want %s", i, j, out, want.Outputs[j])
			}
		}
	}
}

// TestRustPinnedValues pins vectors the Rust unit tests re-derive, so
// the binding fails loudly even if reference.json were regenerated
// wrongly.
func TestRustPinnedValues(t *testing.T) {
	digest, err := Sha256([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	const wantDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Errorf("sha256(abc): %s, want %s", got, wantDigest)
	}
	outputs, err := SplitMix64Fill(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if outputs[0] != 0xe220a8397b1dcdaf {
		t.Errorf("splitmix64(0)[0]: %016x, want e220a8397b1dcdaf", outputs[0])
	}
}

// TestEmptyInputReproducesTheEmptyDigest checks the nil-data path:
// zero-length input goes through as a valid (empty) preimage.
func TestEmptyInputReproducesTheEmptyDigest(t *testing.T) {
	digest, err := Sha256(nil)
	if err != nil {
		t.Fatal(err)
	}
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Errorf("sha256(): %s, want %s", got, want)
	}
	if got, err := Crc32(nil); err != nil || got != 0 {
		t.Errorf("crc32(nil): %08x, %v", got, err)
	}
	if got, err := Adler32(nil); err != nil || got != 1 {
		t.Errorf("adler32(nil): %08x, %v", got, err)
	}
	if got, err := Fnv1a64(nil); err != nil || got != 0xcbf29ce484222325 {
		t.Errorf("fnv1a64(nil): %016x, %v", got, err)
	}
}

// TestZeroCountIsANoop checks the splitmix64 zero-count path.
func TestZeroCountIsANoop(t *testing.T) {
	got, err := SplitMix64Fill(0, 0)
	if err != nil || len(got) != 0 {
		t.Errorf("SplitMix64Fill(0, 0): %v, %v", got, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func mustU32(t *testing.T, s string) uint32 {
	t.Helper()
	v, err := parseU64(s)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(v)
}

func mustU64(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := parseU64(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func parseU64(s string) (uint64, error) {
	var v uint64
	for _, r := range s {
		v <<= 4
		switch {
		case r >= '0' && r <= '9':
			v |= uint64(r - '0')
		case r >= 'a' && r <= 'f':
			v |= uint64(r-'a') + 10
		default:
			return 0, hex.InvalidByteError(r)
		}
	}
	return v, nil
}

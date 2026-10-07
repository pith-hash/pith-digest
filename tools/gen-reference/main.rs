//! Regenerates and verifies `reference.json`: the hex-exact cross-SDK
//! test vectors for `pith-digest`.
//!
//! Every vector is computed live from the library, so `gen` is a true
//! regeneration and `verify` fails the build the moment committed bytes
//! drift from what the code actually produces. The corpus is the
//! published-specification set the conformance tests pin (FIPS 180-2,
//! RFC 1950, the PNG spec, the FNV reference, the splitmix64 paper)
//! plus the padding-boundary inputs; all values are lowercase hex
//! strings so Python, Node and Go SDKs compare the same bytes.
//!
//! Usage:
//!
//! ```text
//! gen-reference gen      # write ./reference.json
//! gen-reference verify   # compare ./reference.json byte-for-byte
//! ```

use std::fs;
use std::process::ExitCode;

use pith_digest::{SplitMix64, adler32, crc32, fnv1a64, sha256};

/// The file the suite contract fixes at the repository root.
const PATH: &str = "reference.json";

/// The SHA-256 corpus: the published FIPS 180-2 appendix vectors and
/// the padding-boundary lengths around the 55/56/64-byte tails. The
/// one-million-'a' multi-block vector stays in the Rust conformance
/// suite; this file carries only inputs an SDK test can replay cheaply.
const SHA256_INPUTS: [&[u8]; 8] = [
    b"",
    b"abc",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    &[b'x'; 55],
    &[b'x'; 56],
    &[b'x'; 64],
    &[b'x'; 65],
    b"xxxx",
];

/// The CRC-32 corpus: the canonical check value and a text sample.
const CRC32_INPUTS: [&[u8]; 3] = [
    b"",
    b"123456789",
    b"The quick brown fox jumps over the lazy dog",
];

/// The Adler-32 corpus: the RFC 1950 examples.
const ADLER32_INPUTS: [&[u8]; 4] = [b"", b"a", b"abc", b"Wikipedia"];

/// The FNV-1a 64 corpus: the reference vectors.
const FNV1A64_INPUTS: [&[u8]; 3] = [b"", b"a", b"foobar"];

/// The splitmix64 corpus: seeds with their first eight outputs.
const SPLITMIX64_SEEDS: [u64; 3] = [0, 42, 7];

/// The number of outputs recorded per splitmix64 seed.
const SPLITMIX64_VALUES: usize = 8;

fn main() -> ExitCode {
    let mode = match std::env::args().nth(1) {
        Some(mode) => mode,
        None => {
            eprintln!(
                "usage: gen-reference <gen|verify>  (operates on {PATH} in the working directory)"
            );
            return ExitCode::from(2);
        }
    };
    match mode.as_str() {
        "gen" => {
            let contents = render();
            match fs::write(PATH, &contents) {
                Ok(()) => {
                    println!("wrote {PATH} ({} bytes)", contents.len());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("FAIL: could not write {PATH}: {err}");
                    ExitCode::from(1)
                }
            }
        }
        "verify" => {
            let expected = render();
            let actual = match fs::read(PATH) {
                Ok(bytes) => bytes,
                Err(err) => {
                    eprintln!("FAIL: could not read {PATH}: {err}");
                    return ExitCode::from(1);
                }
            };
            if actual == expected.as_bytes() {
                println!(
                    "reference vectors are current: {PATH} matches the live library ({} bytes)",
                    expected.len()
                );
                ExitCode::SUCCESS
            } else {
                let first = actual
                    .iter()
                    .zip(expected.as_bytes())
                    .position(|(a, e)| a != e)
                    .unwrap_or_else(|| actual.len().min(expected.len()));
                eprintln!(
                    "FAIL: {PATH} is stale: {} actual bytes vs {} expected, first difference at byte {first}",
                    actual.len(),
                    expected.len(),
                );
                eprintln!("regenerate with: cargo run --bin gen-reference -- gen");
                ExitCode::from(1)
            }
        }
        other => {
            eprintln!("usage: gen-reference <gen|verify>  (got {other:?})");
            ExitCode::from(2)
        }
    }
}

/// Builds the complete byte-exact `reference.json` contents from the
/// live library. Field order, indentation and the trailing newline are
/// fixed so two runs on any machine produce identical bytes.
fn render() -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema\": \"pith-digest/reference-vectors/1\",\n");

    out.push_str("  \"sha256\": [\n");
    for (i, input) in SHA256_INPUTS.iter().enumerate() {
        let digest = hex(sha256(input).expect("within size limit").as_bytes());
        out.push_str(&format!(
            "    {{\"input_hex\": \"{}\", \"digest\": \"{}\"}}{}\n",
            hex(input),
            digest,
            comma(i, SHA256_INPUTS.len()),
        ));
    }
    out.push_str("  ],\n");

    section_u32(&mut out, "crc32", &CRC32_INPUTS, crc32);
    section_u32(&mut out, "adler32", &ADLER32_INPUTS, adler32);

    out.push_str("  \"fnv1a64\": [\n");
    for (i, input) in FNV1A64_INPUTS.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"input_hex\": \"{}\", \"fnv1a64\": \"{}\"}}{}\n",
            hex(input),
            hex_u64(fnv1a64(input)),
            comma(i, FNV1A64_INPUTS.len()),
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"splitmix64\": [\n");
    for (i, seed) in SPLITMIX64_SEEDS.iter().enumerate() {
        let mut rng = SplitMix64::new(*seed);
        out.push_str(&format!(
            "    {{\"seed_hex\": \"{}\", \"outputs\": [",
            hex_u64(*seed),
        ));
        for v in 0..SPLITMIX64_VALUES {
            out.push_str(&format!("\"{}\"", hex_u64(rng.next_u64())));
            if v + 1 < SPLITMIX64_VALUES {
                out.push_str(", ");
            }
        }
        out.push_str(&format!("]}}{}\n", comma(i, SPLITMIX64_SEEDS.len())));
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

/// Appends one named section of `{"input_hex", "<name>"}` u32 cases.
fn section_u32(out: &mut String, name: &str, inputs: &[&[u8]], f: fn(&[u8]) -> u32) {
    out.push_str(&format!("  \"{name}\": [\n"));
    for (i, input) in inputs.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"input_hex\": \"{}\", \"{name}\": \"{}\"}}{}\n",
            hex(input),
            hex_u32(f(input)),
            comma(i, inputs.len()),
        ));
    }
    out.push_str("  ],\n");
}

/// The comma that separates a JSON array item from the next one.
fn comma(index: usize, len: usize) -> &'static str {
    if index + 1 == len { "" } else { "," }
}

/// Lowercase hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Lowercase 8-digit hex of a `u32`.
fn hex_u32(value: u32) -> String {
    hex(&value.to_be_bytes())
}

/// Lowercase 16-digit hex of a `u64`.
fn hex_u64(value: u64) -> String {
    hex(&value.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two renders are byte-identical: the generator is deterministic.
    #[test]
    fn render_is_deterministic() {
        assert_eq!(render(), render());
    }

    /// The rendered document is complete, balanced JSON with a trailing
    /// newline, and every section is present with plausible entries.
    #[test]
    fn render_shape_is_complete() {
        let doc = render();
        assert!(doc.starts_with("{\n"));
        assert!(doc.ends_with("\"\n}\n") || doc.ends_with("}\n"));
        assert_eq!(doc.matches('{').count(), doc.matches('}').count());
        assert_eq!(doc.matches('[').count(), doc.matches(']').count());
        for section in [
            "\"schema\": \"pith-digest/reference-vectors/1\"",
            "\"sha256\": [",
            "\"crc32\": [",
            "\"adler32\": [",
            "\"fnv1a64\": [",
            "\"splitmix64\": [",
        ] {
            assert!(doc.contains(section), "missing {section}");
        }
        // No array item is followed by a stray comma before the close.
        assert!(!doc.contains(",\n  ]"));
        assert!(!doc.contains(", ]\n"));
    }

    /// The recorded vectors are the published values, read back out of
    /// the rendered document through the live library.
    #[test]
    fn recorded_vectors_match_the_specifications() {
        let doc = render();
        // FIPS 180-2 "abc".
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(doc.contains(&format!(
            "\"input_hex\": \"{}\", \"digest\": \"{want}\"",
            hex(b"abc")
        )));
        // FIPS 180-2 empty message.
        assert!(doc.contains(
            "\"digest\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\""
        ));
        // PNG spec CRC-32 check value.
        assert!(doc.contains(&format!("\"crc32\": \"{}\"", hex_u32(0xCBF4_3926))));
        // RFC 1950 Adler-32 of "Wikipedia".
        assert!(doc.contains(&format!(
            "\"input_hex\": \"{}\", \"adler32\": \"{}\"",
            hex(b"Wikipedia"),
            hex_u32(0x11E6_0398)
        )));
        // FNV reference values.
        assert!(doc.contains(&format!(
            "\"fnv1a64\": \"{}\"",
            hex_u64(0xcbf2_9ce4_8422_2325)
        )));
        assert!(doc.contains(&format!(
            "\"input_hex\": \"{}\", \"fnv1a64\": \"{}\"",
            hex(b"foobar"),
            hex_u64(0x8594_4171_f739_67e8)
        )));
        // splitmix64 seed 0 paper sequence.
        assert!(doc.contains(
            "\"seed_hex\": \"0000000000000000\", \"outputs\": [\"e220a8397b1dcdaf\", \
             \"6e789e6aa1b965f4\""
        ));
    }

    /// A written render reads back as current: the verify comparison is
    /// byte-for-byte against exactly these bytes.
    #[test]
    fn written_file_verifies_byte_for_byte() {
        let dir = std::env::temp_dir().join("pith-digest-gen-reference-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("reference.json");
        std::fs::write(&path, render()).expect("write");
        let read_back = std::fs::read(&path).expect("read");
        assert_eq!(read_back, render().as_bytes());
        std::fs::remove_file(&path).ok();
    }

    /// The hex helpers pin lowercase, fixed-width, big-endian output.
    #[test]
    fn hex_helpers_are_lowercase_fixed_width() {
        assert_eq!(hex(b""), "");
        assert_eq!(hex(&[0x00, 0xff, 0x0a]), "00ff0a");
        assert_eq!(hex_u32(0x0000_0001), "00000001");
        assert_eq!(hex_u64(0xcbf2_9ce4_8422_2325), "cbf29ce484222325");
    }

    /// The separator helper emits commas only between items.
    #[test]
    fn comma_separates_only_between_items() {
        assert_eq!(comma(0, 1), "");
        assert_eq!(comma(0, 3), ",");
        assert_eq!(comma(1, 3), ",");
        assert_eq!(comma(2, 3), "");
    }

    /// One named u32 section renders the exact per-item shape.
    #[test]
    fn section_renders_item_shape() {
        let mut out = String::new();
        section_u32(&mut out, "crc32", &[b"123456789"], crc32);
        assert_eq!(
            out,
            "  \"crc32\": [\n    {\"input_hex\": \"\
             313233343536373839\", \"crc32\": \"cbf43926\"}\n  ],\n"
        );
    }
}

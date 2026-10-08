// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
package hash.pith.digest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

/**
 * Hex-exact conformance: the committed {@code reference.json} vectors
 * through JNI — the same vectors the Rust {@code gen-reference verify}
 * gate and the Python/Node/Go SDK suites replay, plus existing-section
 * spot checks and the refusal paths (never a crash).
 */
class PithDigestTest {

    private static final Path REPO_ROOT = findRepoRoot();

    /**
     * The repo root: the nearest ancestor (or the working directory
     * itself) holding {@code reference.json} — works both for
     * {@code mvn test} from {@code sdk/java} and from the repo root.
     */
    private static Path findRepoRoot() {
        for (Path base = Paths.get("").toAbsolutePath(); base != null; base = base.getParent()) {
            if (Files.isRegularFile(base.resolve("reference.json"))) {
                return base;
            }
        }
        throw new IllegalStateException("reference.json not found from the working directory upwards");
    }

    private static JsonNode section(String name) throws Exception {
        JsonNode root = new ObjectMapper().readTree(
                Files.newBufferedReader(REPO_ROOT.resolve("reference.json"), StandardCharsets.UTF_8));
        return root.get(name);
    }

    /** Lowercase hex of a byte array (big-endian byte order). */
    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** Bytes of a lowercase hex string. */
    private static byte[] unhex(String hexText) {
        byte[] out = new byte[hexText.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hexText.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    /** The unsigned 64-bit hex form of a carried-in-a-long value. */
    private static String hex(long value) {
        return String.format("%016x", value);
    }

    @Test
    void cdylib_is_discoverable() {
        assertTrue(Files.isRegularFile(Paths.get(PithDigest.cdylibPath())));
    }

    @Test
    void sha1_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("sha1")) {
            assertArrayEquals(unhex(v.get("digest").asText()),
                    PithDigest.sha1(unhex(v.get("input_hex").asText())));
        }
    }

    @Test
    void sha512_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("sha512")) {
            assertArrayEquals(unhex(v.get("digest").asText()),
                    PithDigest.sha512(unhex(v.get("input_hex").asText())));
        }
    }

    @Test
    void hmac_sha1_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("hmac_sha1")) {
            assertArrayEquals(unhex(v.get("mac").asText()),
                    PithDigest.hmacSha1(unhex(v.get("key_hex").asText()),
                            unhex(v.get("data_hex").asText())));
        }
    }

    @Test
    void hmac_sha256_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("hmac_sha256")) {
            assertArrayEquals(unhex(v.get("mac").asText()),
                    PithDigest.hmacSha256(unhex(v.get("key_hex").asText()),
                            unhex(v.get("data_hex").asText())));
        }
    }

    @Test
    void hmac_sha512_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("hmac_sha512")) {
            assertArrayEquals(unhex(v.get("mac").asText()),
                    PithDigest.hmacSha512(unhex(v.get("key_hex").asText()),
                            unhex(v.get("data_hex").asText())));
        }
    }

    @Test
    void xxh64_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("xxh64")) {
            assertEquals(v.get("hash").asText(),
                    hex(PithDigest.xxh64(unhex(v.get("input_hex").asText()),
                            Long.parseUnsignedLong(v.get("seed_hex").asText(), 16))));
        }
    }

    @Test
    void murmur3_x64_128_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("murmur3_x64_128")) {
            // digest is LE(h1)||LE(h2) — exactly the byte order the
            // native export hands back, hexed big-endian.
            assertArrayEquals(unhex(v.get("digest").asText()),
                    PithDigest.murmur3X64128(unhex(v.get("input_hex").asText()),
                            (int) Long.parseLong(v.get("seed_hex").asText(), 16)));
        }
    }

    @Test
    void crc32c_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("crc32c")) {
            assertEquals(v.get("crc32c").asText(),
                    String.format("%08x", PithDigest.crc32c(unhex(v.get("input_hex").asText()))));
        }
    }

    @Test
    void base64_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("base64")) {
            byte[] input = unhex(v.get("input_hex").asText());
            // encoded_hex is the ASCII-hex of the base64 text.
            String encoded = new String(PithDigest.base64Encode(input), StandardCharsets.US_ASCII);
            assertEquals(v.get("encoded_hex").asText(), hex(encoded.getBytes(StandardCharsets.US_ASCII)));
            assertArrayEquals(input, PithDigest.base64Decode(encoded.getBytes(StandardCharsets.US_ASCII)));
        }
    }

    @Test
    void xoshiro256ss_vectors_replay_hex_exact() throws Exception {
        for (JsonNode v : section("xoshiro256ss")) {
            long[] values = PithDigest.xoshiro256Fill(
                    Long.parseUnsignedLong(v.get("seed_hex").asText(), 16), 4);
            assertEquals(4, values.length);
            JsonNode expected = v.get("outputs");
            for (int i = 0; i < 4; i++) {
                assertEquals(expected.get(i).asText(), hex(values[i]));
            }
        }
    }

    @Test
    void sha256_spot_check_abc() {
        assertArrayEquals(unhex(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                PithDigest.sha256("abc".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void crc32_spot_check_123456789() {
        assertEquals(0xcbf43926L, PithDigest.crc32(
                "123456789".getBytes(StandardCharsets.US_ASCII)) & 0xFFFFFFFFL);
    }

    @Test
    void null_data_is_refused_not_crashing() {
        PithDigest.FfiError error = assertThrows(PithDigest.FfiError.class,
                () -> PithDigest.sha256(null));
        assertEquals(-1, error.status);
    }

    @Test
    void non_canonical_base64_decode_is_rejected_not_crashing() {
        // "QQ==" decodes 'A'; "QQ=A" is a malformed padding layout.
        PithDigest.FfiError error = assertThrows(PithDigest.FfiError.class,
                () -> PithDigest.base64Decode("QQ=A".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(-2, error.status);
    }

    @Test
    void ffi_error_names_the_operation() {
        PithDigest.FfiError error = assertThrows(PithDigest.FfiError.class,
                () -> PithDigest.hmacSha1(null, null));
        assertEquals("pith_digest_hmac_sha1", error.op);
        assertNotNull(error.getMessage());
    }
}

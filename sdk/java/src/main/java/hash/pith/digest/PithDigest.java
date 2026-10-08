// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
package hash.pith.digest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Java JNI bindings for the {@code pith-digest} cdylib: the digest,
 * checksum, HMAC, 64-bit-hash, PRNG-fill and base64 surface — the same
 * C library the Python (ctypes), Node (koffi) and Go (cgo) SDKs bind
 * through.
 *
 * <p>The cdylib is resolved once at class-load time, mirroring the
 * discovery chain of the other SDKs: (1) the {@code PITH_CDYLIB}
 * environment variable — the explicit file; (2) {@code PITH_CDYLIB_DIR}
 * — a directory holding one of the platform library names; (3) a
 * {@code target/release} directory at the working directory or up to
 * six ancestors above it. {@link LinkageError} names every candidate
 * when nothing matches.</p>
 *
 * <p>Unsigned 64-bit values (fnv1a64, xxh64, the xoshiro/splitmix
 * streams) are carried in a Java {@code long} — the two's-complement
 * bit pattern; format with {@code %016x} for the hex forms the
 * {@code reference.json} vectors pin. Unsigned 32-bit checksums come
 * back as an {@code int} in the same convention. Refusals raise
 * {@link FfiError}, carrying the C ABI status code.</p>
 */
public final class PithDigest {

    /** Status: success. */
    public static final int PITH_OK = 0;

    /** Status: invalid argument — a null array or pointer with a positive length. */
    public static final int PITH_E_INVALID = -1;

    /** Status: the operation refused the input (e.g. non-canonical or undersized base64 output). */
    public static final int PITH_E_REJECTED = -2;

    /** Platform cdylib file names, in probe order. */
    private static final String[] CDYLIB_NAMES = {
        "pith_digest.dll", "libpith_digest.so", "libpith_digest.dylib",
    };

    private static final String CDYLIB_PATH = findCdylib();

    static {
        System.load(CDYLIB_PATH);
    }

    private PithDigest() {
    }

    /** The absolute path of the loaded cdylib (tests and diagnostics). */
    public static String cdylibPath() {
        return CDYLIB_PATH;
    }

    private static native byte[] sha256Native(byte[] data, int[] status);

    private static native byte[] sha1Native(byte[] data, int[] status);

    private static native byte[] sha512Native(byte[] data, int[] status);

    private static native byte[] hmacSha1Native(byte[] key, byte[] data, int[] status);

    private static native byte[] hmacSha256Native(byte[] key, byte[] data, int[] status);

    private static native byte[] hmacSha512Native(byte[] key, byte[] data, int[] status);

    private static native int crc32Native(byte[] data, int[] status);

    private static native int adler32Native(byte[] data, int[] status);

    private static native int crc32cNative(byte[] data, int[] status);

    private static native long fnv1a64Native(byte[] data, int[] status);

    private static native long xxh64Native(byte[] data, long seed, int[] status);

    private static native byte[] murmur3X64128Native(byte[] data, int seed, int[] status);

    private static native long[] splitmix64FillNative(long seed, int count, int[] status);

    private static native long[] xoshiro256FillNative(long seed, int count, int[] status);

    private static native byte[] base64EncodeNative(byte[] data, int[] status);

    private static native byte[] base64DecodeNative(byte[] data, int[] status);

    /** Runs a fixed-width digest export and refuses non-OK statuses. */
    private static byte[] digest(String op, byte[] data, byte[] raw, int[] status) {
        if (status[0] != PITH_OK) {
            throw new FfiError(op, status[0]);
        }
        return raw;
    }

    /** Runs a scalar export and refuses non-OK statuses. */
    private static long scalar(String op, long value, int[] status) {
        if (status[0] != PITH_OK) {
            throw new FfiError(op, status[0]);
        }
        return value;
    }

    /**
     * The 32-byte SHA-256 digest of {@code data}.
     *
     * @throws FfiError for a null digest input (status {@code PITH_E_INVALID})
     */
    public static byte[] sha256(byte[] data) {
        int[] status = new int[1];
        return digest("pith_digest_sha256", data, sha256Native(data, status), status);
    }

    /**
     * The 20-byte SHA-1 digest of {@code data}.
     *
     * @throws FfiError for a null digest input (status {@code PITH_E_INVALID})
     */
    public static byte[] sha1(byte[] data) {
        int[] status = new int[1];
        return digest("pith_digest_sha1", data, sha1Native(data, status), status);
    }

    /**
     * The 64-byte SHA-512 digest of {@code data}.
     *
     * @throws FfiError for a null digest input (status {@code PITH_E_INVALID})
     */
    public static byte[] sha512(byte[] data) {
        int[] status = new int[1];
        return digest("pith_digest_sha512", data, sha512Native(data, status), status);
    }

    /**
     * HMAC-SHA-1 of {@code data} under {@code key}: a 20-byte MAC.
     *
     * @throws FfiError for a null key or data (status {@code PITH_E_INVALID})
     */
    public static byte[] hmacSha1(byte[] key, byte[] data) {
        int[] status = new int[1];
        return digest("pith_digest_hmac_sha1", data,
                hmacSha1Native(key, data, status), status);
    }

    /**
     * HMAC-SHA-256 of {@code data} under {@code key}: a 32-byte MAC.
     *
     * @throws FfiError for a null key or data (status {@code PITH_E_INVALID})
     */
    public static byte[] hmacSha256(byte[] key, byte[] data) {
        int[] status = new int[1];
        return digest("pith_digest_hmac_sha256", data,
                hmacSha256Native(key, data, status), status);
    }

    /**
     * HMAC-SHA-512 of {@code data} under {@code key}: a 64-byte MAC.
     *
     * @throws FfiError for a null key or data (status {@code PITH_E_INVALID})
     */
    public static byte[] hmacSha512(byte[] key, byte[] data) {
        int[] status = new int[1];
        return digest("pith_digest_hmac_sha512", data,
                hmacSha512Native(key, data, status), status);
    }

    /**
     * The CRC-32 (IEEE) checksum of {@code data}, as an unsigned value
     * in an {@code int}.
     *
     * @throws FfiError for a null input (status {@code PITH_E_INVALID})
     */
    public static int crc32(byte[] data) {
        int[] status = new int[1];
        return (int) scalar("pith_digest_crc32", crc32Native(data, status), status);
    }

    /**
     * The Adler-32 checksum of {@code data}, as an unsigned value in
     * an {@code int}.
     *
     * @throws FfiError for a null input (status {@code PITH_E_INVALID})
     */
    public static int adler32(byte[] data) {
        int[] status = new int[1];
        return (int) scalar("pith_digest_adler32", adler32Native(data, status), status);
    }

    /**
     * The CRC-32C (Castagnoli) checksum of {@code data}, as an
     * unsigned value in an {@code int}.
     *
     * @throws FfiError for a null input (status {@code PITH_E_INVALID})
     */
    public static int crc32c(byte[] data) {
        int[] status = new int[1];
        return (int) scalar("pith_digest_crc32c", crc32cNative(data, status), status);
    }

    /**
     * The 64-bit FNV-1a hash of {@code data}, as an unsigned value in
     * a {@code long}.
     *
     * @throws FfiError for a null input (status {@code PITH_E_INVALID})
     */
    public static long fnv1a64(byte[] data) {
        int[] status = new int[1];
        return scalar("pith_digest_fnv1a64", fnv1a64Native(data, status), status);
    }

    /**
     * The 64-bit xxHash of {@code data} under {@code seed}, as an
     * unsigned value in a {@code long}.
     *
     * @throws FfiError for a null input (status {@code PITH_E_INVALID})
     */
    public static long xxh64(byte[] data, long seed) {
        int[] status = new int[1];
        return scalar("pith_digest_xxh64", xxh64Native(data, seed, status), status);
    }

    /**
     * The 128-bit MurmurHash3 (x64) of {@code data} under {@code seed}:
     * 16 bytes in the reference byte order — {@code h1} little-endian
     * followed by {@code h2} little-endian.
     *
     * @throws FfiError for a null input (status {@code PITH_E_INVALID})
     */
    public static byte[] murmur3X64128(byte[] data, int seed) {
        int[] status = new int[1];
        return digest("pith_digest_murmur3_x64_128", data,
                murmur3X64128Native(data, seed, status), status);
    }

    /**
     * Fills {@code count} values of the splitmix64 stream seeded by
     * {@code seed}, as unsigned values in {@code long}s.
     *
     * @throws FfiError for a non-positive count (status {@code PITH_E_INVALID})
     */
    public static long[] splitmix64Fill(long seed, int count) {
        int[] status = new int[1];
        long[] values = splitmix64FillNative(seed, count, status);
        if (status[0] != PITH_OK) {
            throw new FfiError("pith_digest_splitmix64_fill", status[0]);
        }
        return values;
    }

    /**
     * Fills {@code count} values of the xoshiro256** stream seeded by
     * {@code seed}, as unsigned values in {@code long}s.
     *
     * @throws FfiError for a non-positive count (status {@code PITH_E_INVALID})
     */
    public static long[] xoshiro256Fill(long seed, int count) {
        int[] status = new int[1];
        long[] values = xoshiro256FillNative(seed, count, status);
        if (status[0] != PITH_OK) {
            throw new FfiError("pith_digest_xoshiro256_fill", status[0]);
        }
        return values;
    }

    /**
     * The RFC 4648 base64 text of {@code data} (canonical, padded),
     * as its ASCII bytes.
     *
     * @throws FfiError for a null input (status {@code PITH_E_INVALID})
     */
    public static byte[] base64Encode(byte[] data) {
        int[] status = new int[1];
        return digest("pith_digest_base64_encode", data,
                base64EncodeNative(data, status), status);
    }

    /**
     * Decodes canonical padded base64 text ({@code data} as ASCII
     * bytes) back to the raw bytes.
     *
     * @throws FfiError for a null input ({@code PITH_E_INVALID}) or
     *     non-canonical text ({@code PITH_E_REJECTED})
     */
    public static byte[] base64Decode(byte[] data) {
        int[] status = new int[1];
        return digest("pith_digest_base64_decode", data,
                base64DecodeNative(data, status), status);
    }

    /**
     * A native call refused or failed: the C ABI status code plus the
     * operation that reported it — the Java face of the ctypes/koffi/
     * cgo {@code FfiError}.
     */
    public static final class FfiError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        /** The refusing operation (its C ABI name). */
        public final String op;

        /** The C ABI status code ({@code -1} invalid, {@code -2} rejected). */
        public final int status;

        FfiError(String op, int status) {
            super(op + " failed with status " + status);
            this.op = op;
            this.status = status;
        }
    }

    /**
     * Resolves the cdylib path: {@code PITH_CDYLIB} (explicit file),
     * then {@code PITH_CDYLIB_DIR} + platform name, then a
     * {@code target/release} directory at the working directory or up
     * to six ancestors above it.
     */
    private static String findCdylib() {
        Path cwd = Paths.get("").toAbsolutePath();

        String explicitFile = System.getenv("PITH_CDYLIB");
        if (explicitFile != null && !explicitFile.isEmpty()) {
            Path file = Paths.get(explicitFile).toAbsolutePath();
            if (Files.isRegularFile(file)) {
                return file.toString();
            }
        }

        String dir = System.getenv("PITH_CDYLIB_DIR");
        if (dir != null && !dir.isEmpty()) {
            Path base = Paths.get(dir).toAbsolutePath();
            for (String name : CDYLIB_NAMES) {
                Path candidate = base.resolve(name);
                if (Files.isRegularFile(candidate)) {
                    return candidate.toString();
                }
            }
        }

        for (Path base = cwd; base != null; base = base.getParent()) {
            for (String name : CDYLIB_NAMES) {
                Path candidate = base.resolve("target").resolve("release").resolve(name);
                if (Files.isRegularFile(candidate)) {
                    return candidate.toString();
                }
            }
        }

        throw new LinkageError(
                "cannot locate the pith_digest cdylib; set PITH_CDYLIB or PITH_CDYLIB_DIR"
                + " (probed PITH_CDYLIB, PITH_CDYLIB_DIR, and target/release at "
                + cwd + " and its ancestors)");
    }
}

package com.github.guoyyit.oblivioustransferjava.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Symmetric-only IKNP OT extension primitives: bit-string handling,
 * matrix transpose and per-row random-oracle key derivation.
 *
 * <p>Notation (IKNP03, roles reversed so the final Receiver acts as base-OT
 * sender): k = {@link #BASE_COUNT} base OTs, each carrying an n-bit column.
 */
public final class Iknp {

    public static final int BASE_COUNT = 128;

    private static final byte[] ROW_INFO = "iknp-ext-row/v1".getBytes(StandardCharsets.UTF_8);

    private Iknp() {
    }

    public static int packedBytes(int bitLength) {
        return (bitLength + 7) >>> 3;
    }

    /** Uniform random packed bit string. */
    public static byte[] randomBitString(int bitLength) {
        if (bitLength <= 0) {
            throw new IllegalArgumentException("bit length must be positive");
        }
        return CryptoRandom.randomBytes(packedBytes(bitLength));
    }

    public static int getBit(byte[] packed, int index) {
        return (packed[index >>> 3] >>> (index & 7)) & 1;
    }

    public static void setBit(byte[] packed, int index, int value) {
        int mask = 1 << (index & 7);
        if (value == 0) {
            packed[index >>> 3] &= (byte) ~mask;
        } else {
            packed[index >>> 3] |= (byte) mask;
        }
    }

    public static byte[] xorBitStrings(byte[] left, byte[] right) {
        if (left.length != right.length) {
            throw new IllegalArgumentException("length mismatch");
        }
        byte[] out = new byte[left.length];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (left[i] ^ right[i]);
        }
        return out;
    }

    /**
     * Transposes a k x rowCount bit matrix into rowCount packed k-bit rows.
     *
     * @param columns  k packed column strings, each rowCount bits long
     * @param rowCount number of rows
     * @return rowCount packed strings of k = {@link #BASE_COUNT} bits each
     */
    public static byte[][] transpose(byte[][] columns, int rowCount) {
        if (columns.length != BASE_COUNT) {
            throw new IllegalArgumentException("expected " + BASE_COUNT + " columns");
        }
        int rowBytes = packedBytes(BASE_COUNT);
        byte[][] rows = new byte[rowCount][rowBytes];
        for (int j = 0; j < BASE_COUNT; j++) {
            byte[] column = columns[j];
            if (column == null || column.length < packedBytes(rowCount)) {
                throw new IllegalArgumentException("short column " + j);
            }
            for (int i = 0; i < rowCount; i++) {
                if (getBit(column, i) == 1) {
                    setBit(rows[i], j, 1);
                }
            }
        }
        return rows;
    }

    /**
     * Random oracle for one extended OT row:
     * K_i^side = HKDF(rowBits, info || i || side).
     *
     * @param rowBits     packed k-bit correlated string
     * @param globalIndex position of this row across all batches
     * @param side        0 or 1
     */
    public static byte[] rowKey(byte[] rowBits, int globalIndex, int side) {
        if (rowBits.length != packedBytes(BASE_COUNT)) {
            throw new IllegalArgumentException("row must be " + BASE_COUNT + " bits");
        }
        if (side != 0 && side != 1) {
            throw new IllegalArgumentException("side must be 0 or 1");
        }
        byte[] info = new byte[ROW_INFO.length + 5];
        System.arraycopy(ROW_INFO, 0, info, 0, ROW_INFO.length);
        info[ROW_INFO.length] = (byte) (globalIndex >>> 24);
        info[ROW_INFO.length + 1] = (byte) (globalIndex >>> 16);
        info[ROW_INFO.length + 2] = (byte) (globalIndex >>> 8);
        info[ROW_INFO.length + 3] = (byte) globalIndex;
        info[ROW_INFO.length + 4] = (byte) side;
        return Kdf.hkdf(Arrays.copyOf(rowBits, rowBits.length), info, Kdf.KEY_LEN);
    }
}

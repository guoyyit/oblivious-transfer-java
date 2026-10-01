package com.github.guoyyit.oblivioustransferjava.ot.extension;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * IKNP 随机 OT 扩展接收方（原版 κ 位向量构造）。
 *
 * <p>为每个基础 OT j 生成随机 κ 位串 t0_j，并令 t1_j = t0_j ⊕ 1_κ
 * （全 1 翻转）。基础 OT 阶段把 (t0_j, t1_j) 作为两条消息交给发送方选择。
 * 扩展阶段对每列 j 发送两个矩阵列：
 * <ul>
 *   <li>A：第 i 行固定为 t0_j；</li>
 *   <li>B：第 i 行为 t0_j ⊕ (r_i 重复 κ 位)，即 r_i=0 时为 t0_j，
 *       r_i=1 时为 t1_j。</li>
 * </ul>
 * 行密钥：r_i=0 时跨列收集 t0_j 的第 j 位（等于发送方 R_i）；
 * r_i=1 时收集 t1_j 的第 j 位（等于发送方 R_i⊕s）。
 */
public final class ExtensionReceiver {

    private final int kappa;
    private final byte[] choices;
    private final SecureRandom random;

    private byte[][] t0;
    private byte[][] t1;

    public ExtensionReceiver(int kappa, byte[] choices, SecureRandom random) {
        if (kappa <= 0 || kappa % 8 != 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "基础 OT 数量 kappa 必须为正的 8 的倍数");
        }
        if (choices == null || choices.length == 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "选择向量不能为空");
        }
        for (byte choice : choices) {
            if (choice != 0 && choice != 1) {
                throw new OtException(ErrorCode.INVALID_PARAMETER, "选择向量只能包含 0/1");
            }
        }
        if (random == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "随机源不能为空");
        }
        this.kappa = kappa;
        this.choices = choices.clone();
        this.random = random;
    }

    public int kappa() {
        return kappa;
    }

    public int seedBytes() {
        return kappa / 8;
    }

    public int size() {
        return choices.length;
    }

    /**
     * 生成 κ 对基础 OT 串（t0 随机，t1 为其按位取反）。
     */
    public byte[][][] generateBasePairs() {
        t0 = new byte[kappa][];
        t1 = new byte[kappa][];
        byte[][][] pairs = new byte[kappa][2][];
        for (int j = 0; j < kappa; j++) {
            t0[j] = new byte[seedBytes()];
            random.nextBytes(t0[j]);
            t1[j] = complement(t0[j]);
            pairs[j][0] = t1[j].clone();
            pairs[j][1] = t0[j].clone();
        }
        return pairs;
    }

    public void installBaseSeeds(byte[][] seedsZero, byte[][] seedsOne) {
        t0 = new byte[kappa][];
        t1 = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            t0[j] = seedsZero[j].clone();
            t1[j] = seedsOne[j].clone();
        }
    }

    /**
     * 生成一个扩展批次的 A/B 矩阵列（各 κ 列，行主序，每行 κ 位）。
     */
    public BatchColumns produceColumns(int globalStart, int batchLength) {
        if (t0 == null || t1 == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础串尚未生成");
        }
        if (batchLength <= 0 || globalStart < 0
                || globalStart + batchLength > choices.length) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "批次范围非法");
        }
        int totalBytes = (batchLength * kappa + 7) / 8;
        byte[][] aColumns = new byte[kappa][];
        byte[][] bColumns = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            byte[] a = new byte[totalBytes];
            byte[] b = new byte[totalBytes];
            for (int local = 0; local < batchLength; local++) {
                int globalIndex = globalStart + local;
                for (int k = 0; k < kappa; k++) {
                    int bitIndex = local * kappa + k;
                    boolean bit0 = bit(t0[j], k);
                    boolean bit1 = bit(t1[j], k);
                    boolean choice = choices[globalIndex] == 1;
                    setBit(a, bitIndex, bit0);
                    setBit(b, bitIndex, choice ? bit1 : bit0);
                }
            }
            aColumns[j] = a;
            bColumns[j] = b;
        }
        return new BatchColumns(aColumns, bColumns);
    }

    /**
     * 派生第 index 条被选 OT 的密钥：跨 κ 列收集 t0_j（r=0）或 t1_j（r=1）
     * 的第 j 位组成行串后散列。
     */
    public byte[] deriveKey(int index) {
        if (t0 == null || t1 == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础串尚未生成");
        }
        if (index < 0 || index >= choices.length) {
            throw new OtException(ErrorCode.OUT_OF_RANGE, "行索引越界: " + index);
        }
        byte[] row = new byte[kappa / 8];
        for (int j = 0; j < kappa; j++) {
            byte[] source = choices[index] == 0 ? t0[j] : t1[j];
            if (bit(source, j)) {
                row[j >>> 3] |= (byte) (1 << (7 - (j & 7)));
            }
        }
        byte[] domain = choices[index] == 0
                ? new byte[]{'i', 'k', 'n', 'p', '-', 'r', 'o', 'w', '0'}
                : new byte[]{'i', 'k', 'n', 'p', '-', 'r', 'o', 'w', '1'};
        return ExtensionSender.hashRow(row, index, choices.length, domain);
    }

    public int choiceAt(int index) {
        if (index < 0 || index >= choices.length) {
            throw new OtException(ErrorCode.OUT_OF_RANGE, "选择位索引越界: " + index);
        }
        return choices[index];
    }

    public byte[] choices() {
        return choices.clone();
    }

    public void wipe() {
        if (t0 != null) {
            for (byte[] seed : t0) {
                SymCrypto.wipe(seed);
            }
        }
        if (t1 != null) {
            for (byte[] seed : t1) {
                SymCrypto.wipe(seed);
            }
        }
        t0 = null;
        t1 = null;
        Arrays.fill(choices, (byte) 0);
    }

    private static byte[] complement(byte[] value) {
        byte[] out = new byte[value.length];
        for (int i = 0; i < value.length; i++) {
            out[i] = (byte) ~value[i];
        }
        return out;
    }

    private static boolean bit(byte[] data, int index) {
        return (data[index >>> 3] & (1 << (7 - (index & 7)))) != 0;
    }

    private static void setBit(byte[] data, int index, boolean value) {
        if (value) {
            data[index >>> 3] |= (byte) (1 << (7 - (index & 7)));
        }
    }

    public record BatchColumns(byte[][] a, byte[][] b) {
    }
}

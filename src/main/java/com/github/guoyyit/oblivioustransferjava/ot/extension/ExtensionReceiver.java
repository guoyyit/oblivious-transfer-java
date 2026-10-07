package com.github.guoyyit.oblivioustransferjava.ot.extension;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * IKNP 随机 OT 扩展接收方（PRG 掩码构造）。
 *
 * <p>为每个基础 OT j 生成一对独立随机的 κ 位种子 (k0_j, k1_j)，并作为基础 OT
 * 发送方把种子对交给扩展发送方按 s_j 选择。扩展阶段对每列 j 只发送一个
 * 经 PRG 掩码的矩阵列：
 * <ul>
 *   <li>t_j = G(k0_j)、g_j = G(k1_j)（全局比特流，按行主序每行 κ 位，
 *       批 i 的起始偏移为 globalStart·κ/8 字节，批次边界不改变比特流）；</li>
 *   <li>u_j = t_j ⊕ g_j ⊕ (r ⊗ 1_κ)，即第 i 行的 κ 位在 r_i=1 时整体翻转。</li>
 * </ul>
 * 发送方对 s_j=0 的列不知 k1_j、对 s_j=1 的列不知 k0_j，u_j 中始终残留一个
 * 发送方无法计算的伪随机掩码，因此选择向量 r 对发送方计算隐藏（归约到 PRG
 * 不可区分性，与逐次执行基础 OT 的安全强度一致）。
 *
 * <p>行密钥：第 i 行跨列收集 t_j 的第 (i·κ+j) 位组成行串 t^i 后散列；
 * r_i=0 时 t^i 等于发送方 R_i，r_i=1 时等于 R_i⊕s。
 */
public final class ExtensionReceiver {

    private final int kappa;
    private final byte[] choices;
    private final SecureRandom random;

    private byte[][] seed0;
    private byte[][] seed1;

    /** 当前批次的 T 矩阵列缓存（G(k0_j) 展开结果），供 deriveKey 按位读取。 */
    private byte[][] cachedT;
    private int cachedStart;
    private int cachedLength;

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
     * 生成 κ 对基础 OT 种子（k0、k1 各自独立随机）。pairs[j][b] 即扩展发送方
     * 选择位 s_j=b 时取回的种子。
     */
    public byte[][][] generateBasePairs() {
        seed0 = new byte[kappa][];
        seed1 = new byte[kappa][];
        byte[][][] pairs = new byte[kappa][2][];
        for (int j = 0; j < kappa; j++) {
            seed0[j] = new byte[seedBytes()];
            random.nextBytes(seed0[j]);
            seed1[j] = new byte[seedBytes()];
            random.nextBytes(seed1[j]);
            pairs[j][0] = seed0[j].clone();
            pairs[j][1] = seed1[j].clone();
        }
        return pairs;
    }

    public void installBaseSeeds(byte[][] seedsZero, byte[][] seedsOne) {
        seed0 = new byte[kappa][];
        seed1 = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            seed0[j] = seedsZero[j].clone();
            seed1[j] = seedsOne[j].clone();
        }
    }

    /**
     * 生成一个扩展批次的掩码矩阵列（κ 列，行主序，每行 κ 位）。
     *
     * <p>返回的 {@code a} 为 u 矩阵（u_j = G(k0_j) ⊕ G(k1_j) ⊕ r⊗1），是唯一
     * 需要上线的矩阵；{@code b} 为兼容保留的零宽占位，不承载任何协议数据。
     * 本批次的 T 矩阵列被缓存供 {@link #deriveKey(int)} 使用，单批内存
     * O(κ × 批大小)，与总条数无关。
     */
    public BatchColumns produceColumns(int globalStart, int batchLength) {
        if (seed0 == null || seed1 == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础串尚未生成");
        }
        if (batchLength <= 0 || globalStart < 0
                || globalStart + batchLength > choices.length) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "批次范围非法");
        }
        int totalBytes = (batchLength * kappa + 7) / 8;
        long streamOffset = (long) globalStart * kappa / Byte.SIZE;
        byte[][] uColumns = new byte[kappa][];
        byte[][] tColumns = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            byte[] t = StreamingPrg.expand(seed0[j], ExtensionSender.domainColumn(),
                    streamOffset, totalBytes);
            byte[] g = StreamingPrg.expand(seed1[j], ExtensionSender.domainColumn(),
                    streamOffset, totalBytes);
            byte[] u = SymCrypto.xor(t, g);
            SymCrypto.wipe(g);
            for (int local = 0; local < batchLength; local++) {
                if (choices[globalStart + local] == 1) {
                    for (int k = 0; k < kappa; k++) {
                        flipBit(u, local * kappa + k);
                    }
                }
            }
            uColumns[j] = u;
            tColumns[j] = t;
        }
        installTCache(globalStart, batchLength, tColumns);
        return new BatchColumns(uColumns, emptyColumns());
    }

    /**
     * 派生第 index 条被选 OT 的密钥：跨 κ 列收集 T 矩阵第 index 行的第 j 位
     * 组成行串后散列。优先读取本批次缓存；缓存未覆盖时按全局流偏移重新展开。
     */
    public byte[] deriveKey(int index) {
        if (seed0 == null || seed1 == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础串尚未生成");
        }
        if (index < 0 || index >= choices.length) {
            throw new OtException(ErrorCode.OUT_OF_RANGE, "行索引越界: " + index);
        }
        byte[] row = new byte[kappa / 8];
        if (cachedT != null && index >= cachedStart
                && index < cachedStart + cachedLength) {
            int local = index - cachedStart;
            for (int j = 0; j < kappa; j++) {
                if (bit(cachedT[j], local * kappa + j)) {
                    row[j >>> 3] |= (byte) (1 << (7 - (j & 7)));
                }
            }
        } else {
            for (int j = 0; j < kappa; j++) {
                long bitPosition = (long) index * kappa + j;
                byte[] block = StreamingPrg.expand(seed0[j],
                        ExtensionSender.domainColumn(), bitPosition >>> 3, 1);
                if ((block[0] & (1 << (7 - (bitPosition & 7)))) != 0) {
                    row[j >>> 3] |= (byte) (1 << (7 - (j & 7)));
                }
                SymCrypto.wipe(block);
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
        wipeSeeds();
        wipeTCache();
        Arrays.fill(choices, (byte) 0);
    }

    private void installTCache(int globalStart, int batchLength, byte[][] tColumns) {
        wipeTCache();
        cachedT = tColumns;
        cachedStart = globalStart;
        cachedLength = batchLength;
    }

    private void wipeSeeds() {
        if (seed0 != null) {
            for (byte[] seed : seed0) {
                SymCrypto.wipe(seed);
            }
        }
        if (seed1 != null) {
            for (byte[] seed : seed1) {
                SymCrypto.wipe(seed);
            }
        }
        seed0 = null;
        seed1 = null;
    }

    private void wipeTCache() {
        if (cachedT != null) {
            for (byte[] column : cachedT) {
                SymCrypto.wipe(column);
            }
        }
        cachedT = null;
        cachedStart = 0;
        cachedLength = 0;
    }

    private byte[][] emptyColumns() {
        byte[][] columns = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            columns[j] = new byte[0];
        }
        return columns;
    }

    private static boolean bit(byte[] data, int index) {
        return (data[index >>> 3] & (1 << (7 - (index & 7)))) != 0;
    }

    private static void flipBit(byte[] data, int index) {
        data[index >>> 3] ^= (byte) (1 << (7 - (index & 7)));
    }

    public record BatchColumns(byte[][] a, byte[][] b) {
    }
}

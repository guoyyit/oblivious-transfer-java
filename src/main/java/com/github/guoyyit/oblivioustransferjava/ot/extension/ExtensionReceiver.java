package com.github.guoyyit.oblivioustransferjava.ot.extension;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * IKNP 随机 OT 扩展接收方（PRG 种子构造，选择隐私修复版）。
 *
 * <p>为每个基础 OT j 生成一对独立随机的 κ 位种子 (k0_j, k1_j)，
 * 基础 OT 阶段把 (k0_j, k1_j) 作为两条消息交给发送方按 s_j 选择。
 * 扩展阶段对每列 j 仅发送一个矩阵列：
 * <pre>
 *   U_j = G(k0_j) ⊕ G(k1_j) ⊕ (r ⊗ 1_κ)
 * </pre>
 * 其中 G 为可寻址 HMAC-SHA256 PRG（{@link StreamingPrg}），按行主序展开
 * 本批次的比特区间；r 为本批选择向量，r_i=1 时该行 κ 位块全部翻转。
 *
 * <p>选择隐私：发送方只持有 k_{s_j,j}，G(k_{1-s_j,j}) 对其伪随机且不可预测，
 * 因此 U_j 是选择向量的一次一密；发送方从 U 中得不到任何选择位信息，
 * 安全性归约为 PRG 安全性与基础 OT 的发送方隐私，与逐次执行基础 OT 同强度。
 *
 * <p>行密钥：无论选择位为何，第 i 行密钥都由 T0 矩阵第 i 行
 * （跨列收集 G(k0_j) 第 i 行块的第 j 位）散列得到，仅散列域随选择位区分；
 * 与发送方的 (H(i,Q_i), H(i,Q_i⊕s)) 中恰好被选那一项一致。
 */
public final class ExtensionReceiver {

    private final int kappa;
    private final byte[] choices;
    private final SecureRandom random;

    private byte[][] seeds0;
    private byte[][] seeds1;

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
     * 生成 κ 对基础 OT 种子（k0、k1 各自独立随机），
     * pairs[j][0]=k0_j，pairs[j][1]=k1_j。
     */
    public byte[][][] generateBasePairs() {
        seeds0 = new byte[kappa][];
        seeds1 = new byte[kappa][];
        byte[][][] pairs = new byte[kappa][2][];
        for (int j = 0; j < kappa; j++) {
            seeds0[j] = new byte[seedBytes()];
            random.nextBytes(seeds0[j]);
            seeds1[j] = new byte[seedBytes()];
            random.nextBytes(seeds1[j]);
            pairs[j][0] = seeds0[j].clone();
            pairs[j][1] = seeds1[j].clone();
        }
        return pairs;
    }

    public void installBaseSeeds(byte[][] seedsZero, byte[][] seedsOne) {
        seeds0 = new byte[kappa][];
        seeds1 = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            seeds0[j] = seedsZero[j].clone();
            seeds1[j] = seedsOne[j].clone();
        }
    }

    /**
     * 生成一个扩展批次的 U 矩阵列（κ 列，行主序，每行 κ 位）。
     *
     * <p>U_j = G(k0_j) ⊕ G(k1_j) ⊕ (r ⊗ 1_κ)，只展开本批比特区间，
     * 单批内存 O(批大小 × κ) 位，与总条数无关。返回记录的两个分量
     * 引用同一 U 列数组（第二分量仅为兼容既有调用方保留，
     * 发送方不再需要也不应使用第二个矩阵）。
     */
    public BatchColumns produceColumns(int globalStart, int batchLength) {
        if (seeds0 == null || seeds1 == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础种子尚未生成");
        }
        if (batchLength <= 0 || globalStart < 0
                || globalStart + batchLength > choices.length) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "批次范围非法");
        }
        long batchByteOffset = (long) globalStart * seedBytes();
        int batchBytes = batchLength * seedBytes();
        byte[][] uColumns = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            byte[] domain = StreamingPrg.columnDomain(j);
            byte[] u = StreamingPrg.expand(seeds0[j], domain, batchByteOffset, batchBytes);
            byte[] pad1 = StreamingPrg.expand(seeds1[j], domain, batchByteOffset, batchBytes);
            for (int i = 0; i < u.length; i++) {
                u[i] ^= pad1[i];
            }
            SymCrypto.wipe(pad1);
            for (int local = 0; local < batchLength; local++) {
                if (choices[globalStart + local] == 1) {
                    flipRow(u, local);
                }
            }
            uColumns[j] = u;
        }
        return new BatchColumns(uColumns, uColumns);
    }

    /**
     * 派生第 index 条被选 OT 的密钥：跨 κ 列收集 G(k0_j) 第 index 行块
     * 的第 j 位组成行串后散列（散列域随选择位区分，与发送方行密钥对中
     * 被选那一项一致）。通过可寻址 PRG 仅展开该行，内存 O(κ)，与 n 无关。
     */
    public byte[] deriveKey(int index) {
        if (seeds0 == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础种子尚未生成");
        }
        if (index < 0 || index >= choices.length) {
            throw new OtException(ErrorCode.OUT_OF_RANGE, "行索引越界: " + index);
        }
        byte[] row = new byte[kappa / 8];
        long rowByteOffset = (long) index * seedBytes();
        for (int j = 0; j < kappa; j++) {
            byte[] block = StreamingPrg.expand(
                    seeds0[j], StreamingPrg.columnDomain(j), rowByteOffset, seedBytes());
            if (bit(block, j)) {
                row[j >>> 3] |= (byte) (1 << (7 - (j & 7)));
            }
            SymCrypto.wipe(block);
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
        if (seeds0 != null) {
            for (byte[] seed : seeds0) {
                SymCrypto.wipe(seed);
            }
        }
        if (seeds1 != null) {
            for (byte[] seed : seeds1) {
                SymCrypto.wipe(seed);
            }
        }
        seeds0 = null;
        seeds1 = null;
        Arrays.fill(choices, (byte) 0);
    }

    private void flipRow(byte[] column, int local) {
        int rowBytes = seedBytes();
        int from = local * rowBytes;
        for (int i = from; i < from + rowBytes; i++) {
            column[i] = (byte) ~column[i];
        }
    }

    private static boolean bit(byte[] data, int index) {
        return (data[index >>> 3] & (1 << (7 - (index & 7)))) != 0;
    }

    public record BatchColumns(byte[][] a, byte[][] b) {
    }
}

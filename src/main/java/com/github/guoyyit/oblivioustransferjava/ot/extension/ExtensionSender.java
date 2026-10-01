package com.github.guoyyit.oblivioustransferjava.ot.extension;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.security.SecureRandom;

/**
 * IKNP 随机 OT 扩展发送方（原版 κ 位向量构造，仅对称原语）。
 *
 * <p>基础阶段发送方扮演接收方，选择向量 s ∈ {{0,1}}^κ，对每个基础 OT j
 * 取回 κ 位串 x_j。扩展阶段接收方对每列 j 发送 n×κ 位：
 * <pre>
 *   u_j = t0_j ⊕ (r_n ⊗ 1_κ) ⊕ t0_j ... 即两矩阵
 *   A 列 j = t0_j（对所有行 i 相同的 κ 位）
 *   B 列 j = t0_j ⊕ (r_i 重复 κ 次)（随 i 变化）
 * </pre>
 * 发送方按 s_j 选择 A 或 B，得到串 x_j，并对每条 OT i 跨 κ 列恢复行
 * R_i（满足 R_i 的第 j 位 = t0_{j,i} ⊕ s_j·r_i）。输出相关随机串对
 * <pre>
 *   k_i^0 = H(i, R_i),  k_i^1 = H(i, R_i ⊕ s)
 * </pre>
 * 接收方 r_i=0 持有 R_i，r_i=1 持有 R_i⊕s。分批时每批临时内存为
 * O(批大小 × κ) 位，与 n 无关。
 */
public final class ExtensionSender {

    public static final int OUTPUT_BYTES = 32;

    private static final byte[] DOMAIN_ROW0 = {'i', 'k', 'n', 'p', '-', 'r', 'o', 'w', '0'};
    private static final byte[] DOMAIN_ROW1 = {'i', 'k', 'n', 'p', '-', 'r', 'o', 'w', '1'};
    private static final byte[] HKDF_INFO = {'i', 'k', 'n', 'p', '-', 'r', 'o', 'w'};

    private final int kappa;
    private final SecureRandom random;

    private boolean[] s;

    public ExtensionSender(int kappa, SecureRandom random) {
        if (kappa <= 0 || kappa % 8 != 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "基础 OT 数量 kappa 必须为正的 8 的倍数");
        }
        if (random == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "随机源不能为空");
        }
        this.kappa = kappa;
        this.random = random;
    }

    public int kappa() {
        return kappa;
    }

    public int seedBytes() {
        return kappa / 8;
    }

    public boolean[] generateS() {
        s = new boolean[kappa];
        for (int j = 0; j < kappa; j++) {
            s[j] = random.nextBoolean();
        }
        return s.clone();
    }

    public boolean[] generateU() {
        return generateS();
    }

    /**
     * 保存基础 OT 取回的 κ 位串（按 s_j 选择的那一份）。
     */
    public void installBaseStrings(byte[][] received) {
        if (s == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "尚未生成选择向量 s");
        }
        if (received == null || received.length != kappa) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "基础串数量必须等于 kappa");
        }
        chosen = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            if (received[j] == null || received[j].length != seedBytes()) {
                throw new OtException(ErrorCode.INVALID_PARAMETER, "基础串长度非法");
            }
            chosen[j] = received[j].clone();
        }
    }

    public void installBaseSeeds(byte[][] received) {
        installBaseStrings(received);
    }

    private byte[][] chosen;

    /**
     * 处理一个扩展批次。
     *
     * @param globalStart 批起始全局索引
     * @param totalN      全部 OT 条数
     * @param aColumns    接收方矩阵 A 的 κ 列，每列 ceil(batch*κ/8) 字节，
     *                     行主序：第 local 行的 κ 位连续
     * @param bColumns    接收方矩阵 B 的 κ 列（同上布局）
     */
    public RowPair[] deriveBatch(int globalStart, int totalN,
                                 byte[][] aColumns, byte[][] bColumns) {
        if (chosen == null || s == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础串尚未装配");
        }
        if (aColumns == null || bColumns == null
                || aColumns.length != kappa || bColumns.length != kappa) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列数必须等于 kappa");
        }
        int batchLength = inferBatch(aColumns[0].length);
        if (batchLength <= 0 || globalStart < 0
                || globalStart + batchLength > totalN) {
            throw new OtException(ErrorCode.OUT_OF_RANGE, "扩展批次范围越界");
        }
        RowPair[] rows = new RowPair[batchLength];
        for (int local = 0; local < batchLength; local++) {
            int globalIndex = globalStart + local;
            byte[] rowR = new byte[kappa / 8];
            for (int j = 0; j < kappa; j++) {
                int expectedBytes = (batchLength * kappa + 7) / 8;
                if (aColumns[j] == null || aColumns[j].length != expectedBytes
                        || bColumns[j] == null || bColumns[j].length != expectedBytes) {
                    throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列宽不一致");
                }
                byte[][] picked = s[j] ? aColumns : bColumns;
                // 从该列第 local 行第 j 位取值（行主序 local*kappa + j）
                boolean value = bit(picked[j], local * kappa + j);
                if (value) {
                    rowR[j >>> 3] |= (byte) (1 << (7 - (j & 7)));
                }
            }
            byte[] rowRxorS = xorS(rowR);
            rows[local] = new RowPair(
                    hashRow(rowR, globalIndex, totalN, DOMAIN_ROW0),
                    hashRow(rowRxorS, globalIndex, totalN, DOMAIN_ROW1));
            SymCrypto.wipe(rowRxorS);
        }
        return rows;
    }

    /**
     * 兼容单矩阵 PRG 变体的占位（批处理层不再使用）。
     */
    public RowPair[] deriveBatch(int globalStart, int totalN, byte[][] single) {
        throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "需要 A/B 两个矩阵");
    }

    private int inferBatch(int columnBytes) {
        return columnBytes * 8 / kappa;
    }

    private byte[] xorS(byte[] row) {
        byte[] out = row.clone();
        for (int j = 0; j < kappa; j++) {
            if (s[j]) {
                out[j >>> 3] ^= (byte) (1 << (7 - (j & 7)));
            }
        }
        return out;
    }

    private static boolean bit(byte[] data, int index) {
        return (data[index >>> 3] & (1 << (7 - (index & 7)))) != 0;
    }

    static byte[] hashRow(byte[] rowBits, int globalIndex, int totalN, byte[] domain) {
        byte[] info = new byte[domain.length + 8];
        System.arraycopy(domain, 0, info, 0, domain.length);
        info[domain.length] = (byte) (totalN >>> 24);
        info[domain.length + 1] = (byte) (totalN >>> 16);
        info[domain.length + 2] = (byte) (totalN >>> 8);
        info[domain.length + 3] = (byte) totalN;
        info[domain.length + 4] = (byte) (globalIndex >>> 24);
        info[domain.length + 5] = (byte) (globalIndex >>> 16);
        info[domain.length + 6] = (byte) (globalIndex >>> 8);
        info[domain.length + 7] = (byte) globalIndex;
        byte[] prk = SymCrypto.hmacSha256(info, rowBits);
        return SymCrypto.hkdfExpand(prk, HKDF_INFO, OUTPUT_BYTES);
    }

    public void wipe() {
        if (chosen != null) {
            for (byte[] value : chosen) {
                SymCrypto.wipe(value);
            }
        }
        chosen = null;
        s = null;
    }

    public record RowPair(byte[] k0, byte[] k1) {
    }
}

package com.github.guoyyit.oblivioustransferjava.ot.extension;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.security.SecureRandom;

/**
 * IKNP 随机 OT 扩展发送方（PRG 掩码构造，仅对称原语）。
 *
 * <p>基础阶段发送方扮演接收方，选择向量 s ∈ {0,1}^κ，对每个基础 OT j 取回
 * κ 位种子 k_{s_j}。扩展阶段接收方对每列 j 只发送一个 n批×κ 位掩码矩阵列
 * <pre>
 *   u_j = G(k0_j) ⊕ G(k1_j) ⊕ (r ⊗ 1_κ)
 * </pre>
 * 发送方按列计算 q_j = (s_j ? u_j : 0) ⊕ G(k_{s_j})，于是 q_j = t_j ⊕ (s_j·r)
 * （t_j = G(k0_j)），并对每条 OT i 跨 κ 列恢复行 R_i（第 j 位取自第 j 列的
 * 第 i·κ+j 位）。输出相关随机串对
 * <pre>
 *   k_i^0 = H(i, R_i),  k_i^1 = H(i, R_i ⊕ s)
 * </pre>
 * 接收方 r_i=0 持有 R_i，r_i=1 持有 R_i⊕s。
 *
 * <p>选择隐私：对任意列 j，发送方只持有 k0_j、k1_j 之一，u_j 中始终残留一个
 * 它无法重构的 PRG 输出作为掩码；在 PRG 不可区分性假设下，发送方视图不泄漏
 * 选择向量的任何信息（与逐次执行基础 OT 同等强度的计算安全性）。分批时按
 * 全局流偏移展开，单批临时内存 O(批大小 × κ) 位，与 n 无关，且批次边界不
 * 改变任何比特。
 */
public final class ExtensionSender {

    public static final int OUTPUT_BYTES = 32;

    private static final byte[] DOMAIN_ROW0 = {'i', 'k', 'n', 'p', '-', 'r', 'o', 'w', '0'};
    private static final byte[] DOMAIN_ROW1 = {'i', 'k', 'n', 'p', '-', 'r', 'o', 'w', '1'};
    private static final byte[] DOMAIN_COLUMN = {'i', 'k', 'n', 'p', '-', 'c', 'o', 'l'};
    private static final byte[] HKDF_INFO = {'i', 'k', 'n', 'p', '-', 'r', 'o', 'w'};

    private final int kappa;
    private final SecureRandom random;

    private boolean[] s;
    private byte[][] chosen;

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
     * 保存基础 OT 取回的 κ 位种子（按 s_j 选择的那一份，即 k_{s_j}）。
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

    /**
     * 处理一个扩展批次。
     *
     * @param globalStart 批起始全局索引
     * @param totalN      全部 OT 条数
     * @param uColumns    接收方 u 矩阵的 κ 列，每列 ceil(batch*κ/8) 字节，
     *                    行主序：第 local 行的 κ 位连续
     * @param placeholder 兼容保留的第二矩阵槽位：必须为 κ 个零宽列；携带任何
     *                    非空内容（旧版双矩阵格式）一律按协议违规拒绝
     */
    public RowPair[] deriveBatch(int globalStart, int totalN,
                                 byte[][] uColumns, byte[][] placeholder) {
        if (chosen == null || s == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础串尚未装配");
        }
        if (uColumns == null || uColumns.length != kappa) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列数必须等于 kappa");
        }
        if (placeholder == null || placeholder.length != kappa) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "占位矩阵列数必须等于 kappa");
        }
        for (int j = 0; j < kappa; j++) {
            if (placeholder[j] == null || placeholder[j].length != 0) {
                throw new OtException(ErrorCode.PROTOCOL_VIOLATION,
                        "第二矩阵槽位必须为空（协议只承载单个掩码矩阵）");
            }
        }
        return deriveFromMask(globalStart, totalN, uColumns);
    }

    /**
     * 单矩阵形式：只携带 u 矩阵列的扩展批次。
     */
    public RowPair[] deriveBatch(int globalStart, int totalN, byte[][] uColumns) {
        if (chosen == null || s == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础串尚未装配");
        }
        if (uColumns == null || uColumns.length != kappa) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列数必须等于 kappa");
        }
        return deriveFromMask(globalStart, totalN, uColumns);
    }

    private RowPair[] deriveFromMask(int globalStart, int totalN, byte[][] uColumns) {
        int batchLength = inferBatch(uColumns[0].length);
        if (batchLength <= 0 || globalStart < 0
                || globalStart + batchLength > totalN) {
            throw new OtException(ErrorCode.OUT_OF_RANGE, "扩展批次范围越界");
        }
        int expectedBytes = (batchLength * kappa + 7) / 8;
        long streamOffset = (long) globalStart * kappa / Byte.SIZE;
        byte[][] qColumns = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            if (uColumns[j] == null || uColumns[j].length != expectedBytes) {
                throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列宽不一致");
            }
            byte[] g = StreamingPrg.expand(chosen[j], DOMAIN_COLUMN,
                    streamOffset, expectedBytes);
            qColumns[j] = s[j] ? SymCrypto.xor(uColumns[j], g) : g;
        }
        RowPair[] rows = new RowPair[batchLength];
        for (int local = 0; local < batchLength; local++) {
            int globalIndex = globalStart + local;
            byte[] rowR = new byte[kappa / 8];
            for (int j = 0; j < kappa; j++) {
                if (bit(qColumns[j], local * kappa + j)) {
                    rowR[j >>> 3] |= (byte) (1 << (7 - (j & 7)));
                }
            }
            byte[] rowRxorS = xorS(rowR);
            rows[local] = new RowPair(
                    hashRow(rowR, globalIndex, totalN, DOMAIN_ROW0),
                    hashRow(rowRxorS, globalIndex, totalN, DOMAIN_ROW1));
            SymCrypto.wipe(rowRxorS);
            SymCrypto.wipe(rowR);
        }
        for (byte[] column : qColumns) {
            SymCrypto.wipe(column);
        }
        return rows;
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

    static byte[] domainColumn() {
        return DOMAIN_COLUMN;
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

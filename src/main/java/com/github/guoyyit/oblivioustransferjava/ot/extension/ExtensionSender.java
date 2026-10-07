package com.github.guoyyit.oblivioustransferjava.ot.extension;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.security.SecureRandom;

/**
 * IKNP 随机 OT 扩展发送方（PRG 种子构造，仅对称原语）。
 *
 * <p>基础阶段发送方扮演接收方，选择向量 s ∈ {0,1}^κ，对每个基础 OT j
 * 取回 κ 位种子 k_{s_j,j}（配对种子 k_{1-s_j,j} 对其不可知）。
 * 扩展阶段接收方对每列 j 只发送一个矩阵列：
 * <pre>
 *   U_j = G(k0_j) ⊕ G(k1_j) ⊕ (r ⊗ 1_κ)
 * </pre>
 * 发送方按列计算 Q_j = G(k_{s_j,j}) ⊕ (s_j ? U_j : 0)，于是
 * Q 的第 i 行 = T0 第 i 行 ⊕ (r_i·s)。对每条 OT i 输出相关随机串对
 * <pre>
 *   k_i^0 = H(i, Q_i),  k_i^1 = H(i, Q_i ⊕ s)
 * </pre>
 * 接收方无论 r_i 为何都持有 T0 第 i 行，恰好恢复被选那一项。
 *
 * <p>选择隐私：U_j 被发送方不可知的 PRG 流 G(k_{1-s_j,j}) 一次性掩码，
 * 发送方视图（基础阶段状态、随机源与全部收到的协议消息）与选择向量独立，
 * 安全性归约为 PRG 伪随机性与基础 OT 的发送方隐私，与逐次执行基础 OT 同强度。
 * 分批时每批临时内存为 O(批大小 × κ) 位，与 n 无关。
 */
public final class ExtensionSender {

    public static final int OUTPUT_BYTES = 32;

    private static final byte[] DOMAIN_ROW0 = {'i', 'k', 'n', 'p', '-', 'r', 'o', 'w', '0'};
    private static final byte[] DOMAIN_ROW1 = {'i', 'k', 'n', 'p', '-', 'r', 'o', 'w', '1'};
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
     * 保存基础 OT 取回的 κ 位种子（按 s_j 选择的那一份）。
     */
    public void installBaseSeeds(byte[][] received) {
        if (s == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "尚未生成选择向量 s");
        }
        if (received == null || received.length != kappa) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "基础种子数量必须等于 kappa");
        }
        chosen = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            if (received[j] == null || received[j].length != seedBytes()) {
                throw new OtException(ErrorCode.INVALID_PARAMETER, "基础种子长度非法");
            }
            chosen[j] = received[j].clone();
        }
    }

    public void installBaseStrings(byte[][] received) {
        installBaseSeeds(received);
    }

    /**
     * 处理一个扩展批次。
     *
     * @param globalStart 批起始全局索引
     * @param totalN      全部 OT 条数
     * @param uColumns    接收方 U 矩阵的 κ 列，每列 batch*κ/8 字节，
     *                    行主序：第 local 行的 κ 位连续
     * @param unused      兼容旧双矩阵调用的占位参数，忽略（可为 null）；
     *                    修复后发送方只接收 U 一个矩阵
     */
    public RowPair[] deriveBatch(int globalStart, int totalN,
                               byte[][] uColumns, byte[][] unused) {
        if (chosen == null || s == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "基础种子尚未装配");
        }
        if (uColumns == null || uColumns.length != kappa) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列数必须等于 kappa");
        }
        if (uColumns[0] == null) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列不能为空");
        }
        int columnBytes = uColumns[0].length;
        if (columnBytes <= 0 || columnBytes % seedBytes() != 0) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列宽与 kappa 不对齐");
        }
        int batchLength = columnBytes / seedBytes();
        if (globalStart < 0 || globalStart + batchLength > totalN) {
            throw new OtException(ErrorCode.OUT_OF_RANGE, "扩展批次范围越界");
        }
        int expectedBytes = batchLength * seedBytes();
        long batchByteOffset = (long) globalStart * seedBytes();

        byte[][] qColumns = new byte[kappa][];
        try {
            for (int j = 0; j < kappa; j++) {
                if (uColumns[j] == null || uColumns[j].length != expectedBytes) {
                    throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列宽不一致");
                }
                byte[] q = StreamingPrg.expand(
                        chosen[j], StreamingPrg.columnDomain(j), batchByteOffset, expectedBytes);
                if (s[j]) {
                    for (int i = 0; i < q.length; i++) {
                        q[i] ^= uColumns[j][i];
                    }
                }
                qColumns[j] = q;
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
            return rows;
        } finally {
            for (byte[] q : qColumns) {
                SymCrypto.wipe(q);
            }
        }
    }

    /**
     * 兼容单矩阵 PRG 变体的占位（批处理层不再使用）。
     */
    public RowPair[] deriveBatch(int globalStart, int totalN, byte[][] single) {
        throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "需要 U 矩阵列参数");
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

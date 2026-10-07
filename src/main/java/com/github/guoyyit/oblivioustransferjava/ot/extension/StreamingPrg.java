package com.github.guoyyit.oblivioustransferjava.ot.extension;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import javax.crypto.Mac;

/**
 * 仅使用对称原语的流式伪随机生成器：以 HMAC-SHA256 为核心，
 * {@code block_i = HMAC(key=seed, msg=domain || counter4)}，counter 为大端 4 字节，
 * 支持任意长度输出而不受 HKDF 单次扩展长度限制。
 */
public final class StreamingPrg {

    private static final int BLOCK_SIZE = SymCrypto.HMAC_SHA256_LENGTH;
    private static final byte[] COLUMN_DOMAIN_PREFIX =
            {'i', 'k', 'n', 'p', '2', '-', 'p', 'r', 'g'};

    private StreamingPrg() {
    }

    /**
     * IKNP 扩展中第 column 列的 PRG 分离域（收发双方必须一致）。
     */
    static byte[] columnDomain(int column) {
        byte[] domain = new byte[COLUMN_DOMAIN_PREFIX.length + 4];
        System.arraycopy(COLUMN_DOMAIN_PREFIX, 0, domain, 0, COLUMN_DOMAIN_PREFIX.length);
        domain[COLUMN_DOMAIN_PREFIX.length] = (byte) (column >>> 24);
        domain[COLUMN_DOMAIN_PREFIX.length + 1] = (byte) (column >>> 16);
        domain[COLUMN_DOMAIN_PREFIX.length + 2] = (byte) (column >>> 8);
        domain[COLUMN_DOMAIN_PREFIX.length + 3] = (byte) column;
        return domain;
    }

    public static byte[] expand(byte[] seed, byte[] domain, int outputLength) {
        return expand(seed, domain, 0L, outputLength);
    }

    /**
     * 可寻址扩展：仅计算输出流中 {@code [byteOffset, byteOffset+length)} 的片段。
     *
     * <p>与 {@link #expand(byte[], byte[], int)} 使用同一计数器流（counter 为块下标），
     * 因此相同种子、域与偏移下双方得到一致输出；派生单行密钥只需 O(输出长度)
     * 内存，与流的全长无关，支撑大批量下的有界内存分批推进。
     */
    public static byte[] expand(byte[] seed, byte[] domain, long byteOffset, int length) {
        if (seed == null || seed.length == 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "PRG 种子不能为空");
        }
        if (byteOffset < 0 || length < 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "PRG 输出范围非法");
        }
        try {
            Mac mac = SymCrypto.hmacSha256Mac();
            mac.init(new javax.crypto.spec.SecretKeySpec(seed, "HmacSHA256"));
            byte[] output = new byte[length];
            int filled = 0;
            long counter = byteOffset / BLOCK_SIZE;
            int skip = (int) (byteOffset % BLOCK_SIZE);
            while (filled < length) {
                if (domain != null) {
                    mac.update(domain);
                }
                mac.update((byte) (counter >>> 24));
                mac.update((byte) (counter >>> 16));
                mac.update((byte) (counter >>> 8));
                mac.update((byte) counter);
                byte[] block = mac.doFinal();
                int take = Math.min(BLOCK_SIZE - skip, length - filled);
                System.arraycopy(block, skip, output, filled, take);
                filled += take;
                counter++;
                skip = 0;
            }
            return output;
        } catch (Exception e) {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "PRG 扩展失败", e);
        }
    }
}

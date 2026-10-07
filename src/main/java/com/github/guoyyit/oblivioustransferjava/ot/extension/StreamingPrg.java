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

    private StreamingPrg() {
    }

    public static byte[] expand(byte[] seed, byte[] domain, int outputLength) {
        return expand(seed, domain, 0L, outputLength);
    }

    /**
     * 从全局流的 {@code skipBytes} 字节偏移处开始取 {@code outputLength} 字节，
     * 使分批扩展与一次性扩展得到完全一致的比特流（批次边界不影响输出）。
     */
    public static byte[] expand(byte[] seed, byte[] domain, long skipBytes, int outputLength) {
        if (seed == null || seed.length == 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "PRG 种子不能为空");
        }
        if (skipBytes < 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "PRG 偏移不能为负");
        }
        if (outputLength < 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "PRG 输出长度非法");
        }
        try {
            Mac mac = SymCrypto.hmacSha256Mac();
            mac.init(new javax.crypto.spec.SecretKeySpec(seed, "HmacSHA256"));
            byte[] output = new byte[outputLength];
            int filled = 0;
            long counter = skipBytes / BLOCK_SIZE;
            int blockOffset = (int) (skipBytes % BLOCK_SIZE);
            while (filled < outputLength) {
                if (domain != null) {
                    mac.update(domain);
                }
                mac.update((byte) (counter >>> 24));
                mac.update((byte) (counter >>> 16));
                mac.update((byte) (counter >>> 8));
                mac.update((byte) counter);
                byte[] block = mac.doFinal();
                int take = Math.min(BLOCK_SIZE - blockOffset, outputLength - filled);
                System.arraycopy(block, blockOffset, output, filled, take);
                filled += take;
                counter++;
                blockOffset = 0;
            }
            return output;
        } catch (Exception e) {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "PRG 扩展失败", e);
        }
    }
}

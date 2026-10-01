package com.github.guoyyit.oblivioustransferjava.ot.crypto;

import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

/**
 * 将任意输入散列为定长字节串，用于 IKNP 行校正与基础 OT 密钥导出。
 */
public final class RandomOracle {

    private static final byte[] EXPAND_INFO = {'O', 'T', '-', 'R', 'O'};

    private final int outputLengthBytes;
    private final byte[] domainTag;

    public RandomOracle(int outputLengthBytes, byte[] domainTag) {
        if (outputLengthBytes <= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "随机预言机输出长度必须为正");
        }
        this.outputLengthBytes = outputLengthBytes;
        this.domainTag = domainTag == null ? new byte[0] : domainTag.clone();
    }

    public byte[] digest(byte[] input) {
        if (input == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "随机预言机输入不能为空");
        }
        byte[] prk = SymCrypto.hkdfExtract(domainTag, input);
        return SymCrypto.hkdfExpand(prk, EXPAND_INFO, outputLengthBytes);
    }
}

package com.github.guoyyit.oblivioustransferjava.ot.protocol;

/**
 * 发送方持有的一条消息对，两条消息长度可以不同（均允许空字节串但不允许 null）。
 */
public record MessagePair(byte[] message0, byte[] message1) {

    public MessagePair {
        if (message0 == null || message1 == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "消息对中的消息不能为 null");
        }
        message0 = message0.clone();
        message1 = message1.clone();
    }

    @Override
    public byte[] message0() {
        return message0.clone();
    }

    @Override
    public byte[] message1() {
        return message1.clone();
    }
}

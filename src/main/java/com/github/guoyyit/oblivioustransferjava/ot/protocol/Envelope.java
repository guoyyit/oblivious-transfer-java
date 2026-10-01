package com.github.guoyyit.oblivioustransferjava.ot.protocol;

/**
 * 所有协议消息的统一信封：携带会话标识、消息类型、序列号与密文载荷。
 * 完整性与防重放由 MessageAuthenticator 负责。
 */
public record Envelope(
        byte[] sessionId,
        long seq,
        int messageType,
        byte[] nonce,
        byte[] sealedBody
) {
}

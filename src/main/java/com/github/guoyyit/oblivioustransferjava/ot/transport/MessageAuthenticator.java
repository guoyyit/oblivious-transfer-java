package com.github.guoyyit.oblivioustransferjava.ot.transport;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.Envelope;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * 消息信封的封装/解封装。
 *
 * <p>每条消息体经 AES-128-GCM 加密并认证；AAD 为
 * {@code sessionId || seq || messageType}，因此：
 * <ul>
 *   <li>会话标识与消息体绑定，跨会话混用必然认证失败；</li>
 *   <li>序列号参与认证且收端维护严格递增窗口，重复/乱序消息被拒绝；</li>
 *   <li>截断、翻转等任何篡改都会导致 GCM 标签校验失败。</li>
 * </ul>
 */
public final class MessageAuthenticator {

    private static final int KEY_LENGTH = 16;
    private static final int NONCE_LENGTH = SymCrypto.GCM_IV_LENGTH;
    private static final long SEQ_INITIAL = 0L;

    private final byte[] sessionId;
    private final byte[] sendKey;
    private final byte[] recvKey;

    private long sendSeq = SEQ_INITIAL;
    private long recvNextSeq = SEQ_INITIAL;

    public MessageAuthenticator(byte[] sessionId, byte[] sendKey, byte[] recvKey) {
        if (sessionId == null || sessionId.length == 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "会话标识不能为空");
        }
        if (sendKey == null || sendKey.length != KEY_LENGTH
                || recvKey == null || recvKey.length != KEY_LENGTH) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "信封密钥长度非法");
        }
        this.sessionId = sessionId.clone();
        this.sendKey = sendKey.clone();
        this.recvKey = recvKey.clone();
    }

    /**
     * 封装消息体：生成随机 nonce，加密并认证，附带单调递增序列号。
     */
    public synchronized Envelope seal(int messageType, byte[] body) {
        if (messageType < 0 || messageType > 0xFFFF) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "消息类型越界");
        }
        byte[] nonce = new byte[NONCE_LENGTH];
        SymCrypto.secureRandom().nextBytes(nonce);
        long seq = sendSeq++;
        byte[] aad = buildAad(sessionId, seq, messageType);
        byte[] sealed = sealWithAad(sendKey, nonce, aad,
                body == null ? new byte[0] : body);
        return new Envelope(sessionId.clone(), seq, messageType, nonce, sealed);
    }

    /**
     * 校验并解封装消息：会话不匹配、序列号非法、重放或认证失败均抛出可区分错误。
     */
    public synchronized byte[] open(Envelope envelope) {
        if (envelope == null) {
            throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "消息为空");
        }
        if (envelope.sessionId() == null) {
            throw new OtException(ErrorCode.CROSS_SESSION_MESSAGE, "缺少会话标识");
        }
        if (!Arrays.equals(envelope.sessionId(), sessionId)) {
            throw new OtException(ErrorCode.CROSS_SESSION_MESSAGE, "会话标识不匹配");
        }
        if (envelope.seq() != recvNextSeq) {
            if (envelope.seq() < recvNextSeq) {
                throw new OtException(ErrorCode.MESSAGE_REPLAY,
                        "重复或乱序消息 seq=" + envelope.seq());
            }
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION,
                    "消息序列号错位 expected=" + recvNextSeq + " actual=" + envelope.seq());
        }
        if (envelope.messageType() < 0 || envelope.messageType() > 0xFFFF) {
            throw new OtException(ErrorCode.MESSAGE_TAMPERED, "消息类型越界");
        }
        if (envelope.nonce() == null || envelope.nonce().length != NONCE_LENGTH) {
            throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "nonce 长度非法");
        }
        if (envelope.sealedBody() == null) {
            throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "认证密文为空");
        }
        byte[] aad = buildAad(sessionId, envelope.seq(), envelope.messageType());
        byte[] plaintext;
        try {
            plaintext = openWithAad(recvKey, envelope.nonce(), aad, envelope.sealedBody());
        } catch (OtException e) {
            if (e.code() == ErrorCode.DECRYPTION_FAILED) {
                throw new OtException(ErrorCode.MESSAGE_TAMPERED,
                        "完整性校验失败（消息可能被伪造或截断）", e);
            }
            throw e;
        }
        recvNextSeq++;
        return plaintext;
    }

    static byte[] buildAad(byte[] sessionId, long seq, int messageType) {
        ByteBuffer buffer = ByteBuffer.allocate(sessionId.length + 8 + 2);
        buffer.put(sessionId);
        buffer.putLong(seq);
        buffer.putShort((short) messageType);
        return buffer.array();
    }

    private static byte[] sealWithAad(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        try {
            javax.crypto.Cipher cipher =
                    javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(key, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(SymCrypto.GCM_TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "信封封装失败", e);
        }
    }

    private static byte[] openWithAad(byte[] key, byte[] nonce, byte[] aad, byte[] sealed) {
        try {
            javax.crypto.Cipher cipher =
                    javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(key, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(SymCrypto.GCM_TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(sealed);
        } catch (Exception e) {
            throw new OtException(ErrorCode.DECRYPTION_FAILED, "信封认证失败", e);
        }
    }
}

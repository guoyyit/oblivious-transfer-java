package com.github.guoyyit.oblivioustransferjava.ot.base;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.Group;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.RandomOracle;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * 基础 OT 接收方，与 {@link BaseOtSender} 的单公钥 DH 协议对应。
 * 共享密钥统一为 K = C^r，恰为发送方第 b 分支使用的密钥。
 */
public final class BaseOtReceiver {

    private static final byte[] DOMAIN_BASE_OT = {'b', 'a', 's', 'e', '-', 'o', 't'};

    private final Group group;
    private final SecureRandom random;

    public BaseOtReceiver(Group group, SecureRandom random) {
        if (group == null || random == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "群与随机源不能为空");
        }
        this.group = group;
        this.random = random;
    }

    public Choice choose(byte[] c0Encoded, byte[] c1Unused, int bit) {
        return choose(c0Encoded, bit);
    }

    /**
     * @param c0Encoded 发送方 C=g^a 的编码
     * @param bit        选择位 0/1；Pk = g^r · C^bit，共享密钥 K = C^r
     */
    public Choice choose(byte[] c0Encoded, int bit) {
        if (bit != 0 && bit != 1) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "选择位必须为 0 或 1");
        }
        BigInteger c = group.decodeElement(c0Encoded);
        BigInteger r = group.randomExponent(random);
        BigInteger gR = group.generatorPow(r);
        BigInteger pk = bit == 0 ? gR : group.multiply(gR, c);
        BigInteger shared = group.exponentiate(c, r);
        return new Choice(bit, group.encodeElement(pk), new State(shared));
    }

    public byte[] decode(Choice choice, byte[][] ciphertexts, int messageLength) {
        if (choice == null || choice.privateState() == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "接收方未生成选择");
        }
        if (ciphertexts == null || ciphertexts.length != 2
                || ciphertexts[0] == null || ciphertexts[1] == null) {
            throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "密文对不完整");
        }
        State state = (State) choice.privateState();
        byte[] cipher = ciphertexts[choice.bit()];
        int nonceLength = SymCrypto.GCM_IV_LENGTH;
        if (cipher.length < nonceLength) {
            throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "密文长度不足");
        }
        byte[] nonce = new byte[nonceLength];
        System.arraycopy(cipher, 0, nonce, 0, nonceLength);
        byte[] sealed = new byte[cipher.length - nonceLength];
        System.arraycopy(cipher, nonceLength, sealed, 0, sealed.length);

        byte[] key = deriveKey(state.shared(), (byte) choice.bit());
        try {
            byte[] plaintext = SymCrypto.open(key, nonce, sealed);
            if (messageLength >= 0 && plaintext.length != messageLength) {
                throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "解密消息长度与预期不符");
            }
            return plaintext;
        } finally {
            SymCrypto.wipe(key);
        }
    }

    private byte[] deriveKey(BigInteger shared, byte branch) {
        byte[] encoded = group.encodeElement(shared);
        byte[] input = new byte[1 + encoded.length];
        input[0] = branch;
        System.arraycopy(encoded, 0, input, 1, encoded.length);
        return new RandomOracle(16, DOMAIN_BASE_OT).digest(input);
    }

    public record Choice(int bit, byte[] pk, Object privateState) {
    }

    private record State(BigInteger shared) {
    }
}

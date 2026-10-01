package com.github.guoyyit.oblivioustransferjava.ot.base;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.Group;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.RandomOracle;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * 基础 OT 发送方（DH/DDH 型，Even–Goldreich–Lempel 风格的单公钥变体）。
 *
 * <ol>
 *   <li>发送方随机 a，公布 C=g^a。</li>
 *   <li>接收方选择 b，随机 r，发送 Pk = g^r · C^b。</li>
 *   <li>发送方计算 K0 = Pk^a，K1 = (Pk·C^{-1})^a，
 *       分别用 HKDF 导出 AES-GCM 密钥加密 m0、m1。</li>
 *   <li>接收方由 C^r 得到 K_b（b=0: Pk=g^r → Pk^a = C^r；
 *       b=1: Pk·C^{-1}=g^r → 其 a 次幂 = C^r）。</li>
 * </ol>
 * 选择位信息论安全（Pk 在两种 b 下都为一致随机群元素），
 * 未选择消息在 DDH（离散对数）困难假设下保密。
 */
public final class BaseOtSender {

    private static final byte[] DOMAIN_BASE_OT = {'b', 'a', 's', 'e', '-', 'o', 't'};

    private final Group group;
    private final SecureRandom random;

    public BaseOtSender(Group group, SecureRandom random) {
        if (group == null || random == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "群与随机源不能为空");
        }
        this.group = group;
        this.random = random;
    }

    public Init init() {
        BigInteger a = group.randomExponent(random);
        BigInteger c = group.generatorPow(a);
        return new Init(group.encodeElement(c), new byte[0], new State(a, c));
    }

    public byte[][] respond(Init init, byte[] receiverChoice, MessagePair messages) {
        if (init == null || init.privateState() == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "发送方未初始化");
        }
        if (messages == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "消息对不能为空");
        }
        State state = (State) init.privateState();
        BigInteger pk = group.decodeElement(receiverChoice);
        BigInteger cInverse = state.c().modInverse(group.prime());
        BigInteger pkAdjusted = pk.multiply(cInverse).mod(group.prime());

        BigInteger k0 = group.exponentiate(pk, state.a());
        BigInteger k1 = group.exponentiate(pkAdjusted, state.a());

        byte[] key0 = deriveKey(k0, (byte) 0);
        byte[] key1 = deriveKey(k1, (byte) 1);
        try {
            return new byte[][]{encrypt(key0, messages.message0()),
                    encrypt(key1, messages.message1())};
        } finally {
            SymCrypto.wipe(key0);
            SymCrypto.wipe(key1);
        }
    }

    private byte[] encrypt(byte[] key, byte[] plaintext) {
        byte[] nonce = new byte[SymCrypto.GCM_IV_LENGTH];
        random.nextBytes(nonce);
        byte[] sealed = SymCrypto.seal(key, nonce, plaintext);
        byte[] out = new byte[nonce.length + sealed.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(sealed, 0, out, nonce.length, sealed.length);
        return out;
    }

    private byte[] deriveKey(BigInteger shared, byte branch) {
        byte[] encoded = group.encodeElement(shared);
        byte[] input = new byte[1 + encoded.length];
        input[0] = branch;
        System.arraycopy(encoded, 0, input, 1, encoded.length);
        return new RandomOracle(16, DOMAIN_BASE_OT).digest(input);
    }

    public record Init(byte[] c0, byte[] c1, Object privateState) {
    }

    private record State(BigInteger a, BigInteger c) {
    }
}

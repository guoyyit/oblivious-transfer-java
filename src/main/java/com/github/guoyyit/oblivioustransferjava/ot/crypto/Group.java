package com.github.guoyyit.oblivioustransferjava.ot.crypto;

import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * 素数阶循环群，安全性依赖离散对数困难假设（RFC 3526 2048 位 MODP 群的素阶子群）。
 */
public final class Group {

    private static final BigInteger MODP2048_PRIME = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                    + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                    + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);

    private final BigInteger prime;
    private final BigInteger order;
    private final BigInteger generator;
    private final int encodedLength;

    private Group(BigInteger prime, BigInteger order, BigInteger generator) {
        this.prime = prime;
        this.order = order;
        this.generator = generator;
        this.encodedLength = (prime.bitLength() + 7) / 8;
    }

    public static Group modp2048() {
        BigInteger p = MODP2048_PRIME;
        BigInteger q = p.subtract(BigInteger.ONE).shiftRight(1);
        BigInteger g = BigInteger.valueOf(4).mod(p);
        return new Group(p, q, g);
    }

    public BigInteger prime() {
        return prime;
    }

    public BigInteger order() {
        return order;
    }

    public BigInteger generator() {
        return generator;
    }

    public BigInteger randomExponent(SecureRandom random) {
        if (random == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "随机源不能为空");
        }
        BigInteger exponent;
        do {
            exponent = new BigInteger(order.bitLength(), random);
        } while (exponent.signum() == 0 || exponent.compareTo(order) >= 0);
        return exponent;
    }

    public BigInteger generatorPow(BigInteger exponent) {
        return exponentiate(generator, exponent);
    }

    public BigInteger exponentiate(BigInteger base, BigInteger exponent) {
        validateElement(base);
        if (exponent == null || exponent.signum() <= 0 || exponent.compareTo(order) >= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "指数必须位于 [1, q-1]");
        }
        return base.modPow(exponent, prime);
    }

    public BigInteger multiply(BigInteger a, BigInteger b) {
        validateElement(a);
        validateElement(b);
        return a.multiply(b).mod(prime);
    }

    public byte[] encodeElement(BigInteger element) {
        validateElement(element);
        byte[] raw = element.toByteArray();
        byte[] out = new byte[encodedLength];
        if (raw.length == encodedLength) {
            System.arraycopy(raw, 0, out, 0, encodedLength);
        } else if (raw.length == encodedLength + 1 && raw[0] == 0) {
            System.arraycopy(raw, 1, out, 0, encodedLength);
        } else if (raw.length < encodedLength) {
            System.arraycopy(raw, 0, out, encodedLength - raw.length, raw.length);
        } else {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "群元素编码长度异常");
        }
        return out;
    }

    public BigInteger decodeElement(byte[] encoded) {
        if (encoded == null || encoded.length != encodedLength) {
            throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "群元素编码长度非法");
        }
        BigInteger element = new BigInteger(1, encoded);
        validateElement(element);
        return element;
    }

    private void validateElement(BigInteger element) {
        if (element == null || element.signum() <= 0 || element.compareTo(prime) >= 0) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "群元素越界");
        }
        if (element.equals(BigInteger.ONE)) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "拒绝单位元");
        }
        if (!element.modPow(order, prime).equals(BigInteger.ONE)) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "群元素不属于素阶子群");
        }
    }
}

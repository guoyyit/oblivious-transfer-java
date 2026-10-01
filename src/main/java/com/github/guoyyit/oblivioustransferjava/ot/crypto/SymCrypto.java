package com.github.guoyyit.oblivioustransferjava.ot.crypto;

import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import javax.crypto.Mac;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 扩展阶段只允许使用对称原语：SHA-256、HMAC-SHA-256、AES-GCM、HKDF。
 */
public final class SymCrypto {

    private SymCrypto() {
    }

    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    public static final int HMAC_SHA256_LENGTH = 32;

    /**
     * 进程内共享的随机数来源：JDK 默认 SecureRandom（macOS/Linux 上为经内核熵播种的
     * NativePRNG/DRBG），所有使用点仅通过此入口取随机性，内部自身线程安全。
     */
    public static SecureRandom secureRandom() {
        return LazyRandom.RANDOM;
    }

    public static byte[] sha256(byte[] input) {
        MessageDigest digest = sha256Digest();
        digest.update(input);
        return digest.digest();
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = hmacSha256Mac();
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            if (data != null && data.length > 0) {
                mac.update(data);
            }
            return mac.doFinal();
        } catch (Exception e) {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "HMAC-SHA256 计算失败", e);
        }
    }

    /**
     * RFC 5869 HKDF-Extract。
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        byte[] effectiveSalt = salt;
        if (effectiveSalt == null || effectiveSalt.length == 0) {
            effectiveSalt = new byte[HMAC_SHA256_LENGTH];
        }
        return hmacSha256(effectiveSalt, ikm == null ? new byte[0] : ikm);
    }

    /**
     * RFC 5869 HKDF-Expand。
     */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        if (length <= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "HKDF 输出长度必须为正");
        }
        if (length > 255 * HMAC_SHA256_LENGTH) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "HKDF 输出长度超限");
        }
        try {
            Mac mac = hmacSha256Mac();
            mac.init(new SecretKeySpec(prk, HMAC_SHA256));
            byte[] previous = new byte[0];
            byte[] output = new byte[length];
            int filled = 0;
            byte counter = 1;
            byte[] safeInfo = info == null ? new byte[0] : info;
            while (filled < length) {
                mac.update(previous);
                mac.update(safeInfo);
                mac.update(counter);
                previous = mac.doFinal();
                int take = Math.min(previous.length, length - filled);
                System.arraycopy(previous, 0, output, filled, take);
                filled += take;
                counter++;
            }
            return output;
        } catch (Exception e) {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "HKDF-Expand 计算失败", e);
        }
    }

    public static byte[] xor(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "XOR 输入长度不一致");
        }
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    /**
     * AES-GCM 加密（12 字节 nonce 由调用方提供，128 位认证标签）。
     * 返回仅含密文与标签的字节串，nonce 由协议层单独携带。
     */
    public static byte[] seal(byte[] key, byte[] nonce, byte[] plaintext) {
        validateKeyAndNonce(key, nonce);
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
            return cipher.doFinal(plaintext == null ? new byte[0] : plaintext);
        } catch (Exception e) {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "AES-GCM 加密失败", e);
        }
    }

    /**
     * AES-GCM 解密；认证失败抛出 DECRYPTION_FAILED。输入为 nonce || ciphertextWithTag。
     */
    public static byte[] open(byte[] key, byte[] nonce, byte[] ciphertext) {
        validateKeyAndNonce(key, nonce);
        if (ciphertext == null) {
            throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "密文为空");
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new OtException(ErrorCode.DECRYPTION_FAILED, "AES-GCM 认证解密失败", e);
        }
    }

    public static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "SHA-256 不可用", e);
        }
    }

    public static Mac hmacSha256Mac() {
        try {
            return Mac.getInstance(HMAC_SHA256);
        } catch (NoSuchAlgorithmException e) {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "HMAC-SHA256 不可用", e);
        }
    }

    private static void validateKeyAndNonce(byte[] key, byte[] nonce) {
        if (key == null || (key.length != 16 && key.length != 32)) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "AES 密钥长度必须为 16 或 32 字节");
        }
        if (nonce == null || nonce.length != GCM_IV_LENGTH) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "GCM nonce 必须为 12 字节");
        }
    }

    public static void wipe(byte[] material) {
        if (material != null) {
            Arrays.fill(material, (byte) 0);
        }
    }

    private static final class LazyRandom {
        private static final SecureRandom RANDOM = createSecureRandom();

        private static SecureRandom createSecureRandom() {
            SecureRandom random = new SecureRandom();
            random.nextBytes(new byte[32]);
            return random;
        }
    }
}

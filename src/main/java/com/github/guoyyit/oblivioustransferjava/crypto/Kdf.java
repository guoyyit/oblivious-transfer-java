package com.github.guoyyit.oblivioustransferjava.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * Symmetric helpers used in the extension phase: HKDF-SHA256 derivation and
 * AES-GCM authenticated sealing. No public-key operation is performed through
 * this class.
 */
public final class Kdf {

    public static final int KEY_LEN = 32;
    private static final int GCM_NONCE_LEN = 12;
    private static final int GCM_TAG_BITS = 128;

    private Kdf() {
    }

    /**
     * Single-step HKDF-SHA256: PRK = HMAC-SHA256(zero salt, keyMaterial),
     * then expand against {@code info} to the requested length.
     */
    public static byte[] hkdf(byte[] keyMaterial, byte[] info, int outputLength) {
        if (outputLength <= 0 || outputLength > 255 * 32) {
            throw new IllegalArgumentException("bad output length");
        }
        byte[] prk = MacUtil.hmacSha256(new byte[32], keyMaterial);
        byte[] okm = new byte[outputLength];
        byte[] previous = new byte[0];
        int generated = 0;
        byte counter = 1;
        while (generated < outputLength) {
            byte[] data = new byte[previous.length + info.length + 1];
            System.arraycopy(previous, 0, data, 0, previous.length);
            System.arraycopy(info, 0, data, previous.length, info.length);
            data[data.length - 1] = counter;
            previous = MacUtil.hmacSha256(prk, data);
            int take = Math.min(previous.length, outputLength - generated);
            System.arraycopy(previous, 0, okm, generated, take);
            generated += take;
            counter++;
        }
        return okm;
    }

    /**
     * AES-GCM seal. {@code nonce} must be 12 bytes and never reused under the
     * same key. Output layout is raw ciphertext with the GCM tag appended.
     */
    public static byte[] seal(byte[] key, byte[] nonce, byte[] plaintext) {
        checkNonce(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM seal failed", e);
        }
    }

    /** AES-GCM open; throws AEADBadTagException-equivalent on tampering. */
    public static byte[] open(byte[] key, byte[] nonce, byte[] ciphertext) {
        checkNonce(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("AES-GCM open failed", e);
        }
    }

    public static int nonceLength() {
        return GCM_NONCE_LEN;
    }

    private static void checkNonce(byte[] nonce) {
        if (nonce == null || nonce.length != GCM_NONCE_LEN) {
            throw new IllegalArgumentException("nonce must be 12 bytes");
        }
    }
}

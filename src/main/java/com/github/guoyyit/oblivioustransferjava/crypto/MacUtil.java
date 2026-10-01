package com.github.guoyyit.oblivioustransferjava.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * HMAC-SHA256 helpers for per-envelope integrity protection.
 */
public final class MacUtil {

    public static final int TAG_LEN = 32;

    private MacUtil() {
    }

    public static byte[] hmacSha256(byte[] key, byte[] message) {
        if (key == null || message == null) {
            throw new IllegalArgumentException("null hmac input");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[]... parts) {
        if (key == null) {
            throw new IllegalArgumentException("null hmac key");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] part : parts) {
                mac.update(part);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /** Constant-time comparison. */
    public static boolean constantTimeEquals(byte[] expected, byte[] actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return java.security.MessageDigest.isEqual(expected, actual);
    }
}

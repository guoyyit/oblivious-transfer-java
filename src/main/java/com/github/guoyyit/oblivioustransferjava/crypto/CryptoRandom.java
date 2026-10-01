package com.github.guoyyit.oblivioustransferjava.crypto;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Process-wide cryptographic randomness. The shared {@link SecureRandom} is
 * thread-safe, so concurrent sessions never share derived stream state.
 */
public final class CryptoRandom {

    private static final SecureRandom SOURCE = create();

    private CryptoRandom() {
    }

    public static SecureRandom source() {
        return SOURCE;
    }

    public static byte[] randomBytes(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("negative length");
        }
        byte[] out = new byte[length];
        SOURCE.nextBytes(out);
        return out;
    }

    /** Uniform random exponent in [1, order - 1]. */
    public static BigInteger randomExponent(BigInteger order) {
        BigInteger exponent;
        do {
            exponent = new BigInteger(order.bitLength(), SOURCE);
        } while (exponent.signum() == 0 || exponent.compareTo(order) >= 0);
        return exponent;
    }

    private static SecureRandom create() {
        // NativePRNGNonBlocking on Linux / NativePRNG on macOS is backed by the
        // kernel CSPRNG; it is thread-safe and never blocks.
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            if (os.contains("linux")) {
                return SecureRandom.getInstance("NativePRNGNonBlocking");
            }
            if (os.contains("mac")) {
                return SecureRandom.getInstance("NativePRNG");
            }
        } catch (NoSuchAlgorithmException ignored) {
            // fall through to default
        }
        return new SecureRandom();
    }
}

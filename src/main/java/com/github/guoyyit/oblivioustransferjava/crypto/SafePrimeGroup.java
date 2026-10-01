package com.github.guoyyit.oblivioustransferjava.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Prime-order cyclic group for the discrete-logarithm based base OT:
 * the order-q subgroup of Z_p^*, p = 2q + 1 a safe prime (RFC 3526 MODP-2048).
 */
public final class SafePrimeGroup {

    private static final String HEX_P = """
            FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
            29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
            EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
            E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
            EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
            C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
            83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
            670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
            E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
            DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
            15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
            """;

    public static final SafePrimeGroup MODP_2048 = new SafePrimeGroup(
            new BigInteger(HEX_P.replaceAll("\\s", ""), 16));

    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;
    private final BigInteger crs;
    private final int elementSize;

    private SafePrimeGroup(BigInteger p) {
        this.p = p;
        this.q = p.subtract(BigInteger.ONE).shiftRight(1);
        // 2 is a primitive root mod this safe prime; 4 = 2^2 generates the
        // order-q quadratic-residue subgroup.
        this.g = BigInteger.valueOf(4);
        this.crs = deriveCrs(p);
        this.elementSize = (p.bitLength() + 7) / 8;
    }

    public BigInteger p() {
        return p;
    }

    public BigInteger q() {
        return q;
    }

    public BigInteger generator() {
        return g;
    }

    /** Fixed group element with unknown discrete logarithm (common reference string). */
    public BigInteger crs() {
        return crs;
    }

    public BigInteger randomExponent() {
        BigInteger exponent;
        do {
            exponent = new BigInteger(q.bitLength(), CryptoRandom.source());
        } while (exponent.signum() == 0 || exponent.compareTo(q) >= 0);
        return exponent;
    }

    /** g^exponent mod p */
    public BigInteger pow(BigInteger exponent) {
        return g.modPow(exponent, p);
    }

    /** base^exponent mod p */
    public BigInteger pow(BigInteger base, BigInteger exponent) {
        return base.modPow(exponent, p);
    }

    /** left * right mod p */
    public BigInteger mul(BigInteger left, BigInteger right) {
        return left.multiply(right).mod(p);
    }

    /** left / right mod p */
    public BigInteger div(BigInteger left, BigInteger right) {
        return left.multiply(right.modInverse(p)).mod(p);
    }

    public int elementSize() {
        return elementSize;
    }

    /**
     * Validates an element received off the wire: a non-trivial member of the
     * order-q subgroup.
     */
    public boolean isValidElement(BigInteger element) {
        if (element == null) {
            return false;
        }
        if (element.signum() <= 0 || element.compareTo(p) >= 0) {
            return false;
        }
        if (element.equals(BigInteger.ONE) || element.equals(p.subtract(BigInteger.ONE))) {
            return false;
        }
        // Euler criterion: element is a quadratic residue iff element^q = 1.
        return element.modPow(q, p).equals(BigInteger.ONE);
    }

    public static byte[] elementToBytes(BigInteger element) {
        return MODP_2048.encodeElement(element);
    }

    public static BigInteger bytesToElement(byte[] encoded) {
        return MODP_2048.decodeElementBytes(encoded);
    }

    public byte[] encodeElement(BigInteger element) {
        byte[] raw = element.toByteArray();
        byte[] out = new byte[elementSize];
        int srcPos = Math.max(0, raw.length - elementSize);
        int length = Math.min(raw.length, elementSize);
        System.arraycopy(raw, srcPos, out, elementSize - length, length);
        return out;
    }

    public BigInteger decodeElementBytes(byte[] encoded) {
        if (encoded == null || encoded.length != elementSize) {
            return null;
        }
        return new BigInteger(1, encoded);
    }

    /**
     * Derives a fixed element with unknown discrete logarithm: a hashed seed is
     * mapped to Z_p then squared, landing in the quadratic-residue subgroup.
     */
    private static BigInteger deriveCrs(BigInteger p) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] seed = digest.digest(
                    "oblivious-transfer-java/crs/v1".getBytes(StandardCharsets.UTF_8));
            BigInteger candidate = new BigInteger(1, seed);
            return candidate.mod(p).modPow(BigInteger.TWO, p);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

}

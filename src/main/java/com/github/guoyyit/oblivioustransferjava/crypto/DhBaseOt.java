package com.github.guoyyit.oblivioustransferjava.crypto;

import java.math.BigInteger;

/**
 * 1-out-of-2 oblivious transfer under the Diffie-Hellman/DDH assumption
 * (Chou-Orlandi style with a fixed element U whose discrete log is unknown).
 *
 * <p>Sender picks a and publishes A = g^a.
 * Receiver with choice bit sigma picks x and sends
 * B = g^x (sigma=0) or B = U * g^x (sigma=1), deriving k = H(A^x).
 * Sender computes k0 = H(B^a), k1 = H((B/U)^a).
 *
 * <p>Receiver privacy: for sigma=0, B is a random element; for sigma=1, U*g^x
 * is a random element; the two cases are DDH-indistinguishable to the sender.
 * Sender privacy: the unchosen key involves a power of A with an exponent the
 * receiver cannot compute without the discrete log of U.
 */
public final class DhBaseOt {

    private DhBaseOt() {
    }

    public record SenderInit(BigInteger secret, BigInteger publicElement) {
    }

    public record ReceiverReply(BigInteger publicElement, byte[] key) {
    }

    public static SenderInit createSenderInit(SafePrimeGroup group) {
        BigInteger a = group.randomExponent();
        return new SenderInit(a, group.pow(a));
    }

    public static ReceiverReply createReceiverReply(SafePrimeGroup group,
                                                    BigInteger senderPublic,
                                                    int choiceBit) {
        if (choiceBit != 0 && choiceBit != 1) {
            throw new IllegalArgumentException("choice bit must be 0 or 1");
        }
        if (!group.isValidElement(senderPublic)) {
            throw new IllegalArgumentException("invalid sender public element");
        }
        BigInteger x = group.randomExponent();
        BigInteger gx = group.pow(x);
        BigInteger b = choiceBit == 0 ? gx : group.mul(group.crs(), gx);
        // k = H(A^x)
        byte[] key = hashShared(group.pow(senderPublic, x));
        return new ReceiverReply(b, key);
    }

    /** @return two derived keys at index 0 and 1 */
    public static byte[][] deriveSenderKeys(SafePrimeGroup group,
                                            SenderInit senderInit,
                                            BigInteger receiverPublic) {
        if (!group.isValidElement(receiverPublic)) {
            throw new IllegalArgumentException("invalid receiver public element");
        }
        BigInteger a = senderInit.secret();
        // k0 = H(B^a)
        byte[] k0 = hashShared(group.pow(receiverPublic, a));
        // k1 = H((B/U)^a)
        BigInteger bDivU = group.div(receiverPublic, group.crs());
        byte[] k1 = hashShared(group.pow(bDivU, a));
        return new byte[][]{k0, k1};
    }

    public static byte[] encodeElement(BigInteger element) {
        return SafePrimeGroup.elementToBytes(element);
    }

    public static BigInteger decodeElement(byte[] encoded) {
        return SafePrimeGroup.bytesToElement(encoded);
    }

    /**
     * Random-oracle style key derivation from a group element:
     * HKDF-SHA256 over the fixed-width encoded element with domain info.
     */
    private static byte[] hashShared(BigInteger shared) {
        byte[] encoded = SafePrimeGroup.elementToBytes(shared);
        return Kdf.hkdf(encoded, "dh-base-ot/v1".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                Kdf.KEY_LEN);
    }
}

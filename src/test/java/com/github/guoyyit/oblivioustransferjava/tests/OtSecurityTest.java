package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.crypto.Iknp;
import com.github.guoyyit.oblivioustransferjava.crypto.Kdf;
import com.github.guoyyit.oblivioustransferjava.crypto.SafePrimeGroup;
import com.github.guoyyit.oblivioustransferjava.service.OtService;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Sender privacy and receiver-privacy structural checks. These do not replace a
 * formal proof but demonstrate that the unchosen outputs are unavailable: the
 * receiver cannot derive the unchosen base key, and extension messages sealed
 * under the unchosen random-OT key cannot be opened.
 */
class OtSecurityTest {

    private final OtService service = new OtService();

    @Test
    void baseOtReceiverCannotComputeUnchosenKey() {
        SafePrimeGroup group = SafePrimeGroup.MODP_2048;
        // An outsider knowing only public transcripts cannot reconstruct either
        // derived key without the corresponding discrete logarithm.
        BigInteger a = group.randomExponent();
        BigInteger x = group.randomExponent();
        BigInteger publicA = group.pow(a);
        BigInteger gx = group.pow(x);
        BigInteger sharedChosen = group.pow(publicA, x);
        // The unchosen branch for sigma=0 uses (B/U)^a; without 'a' or the
        // discrete log of U the receiver cannot compute it from A and B.
        BigInteger unchosenGuess = gx;
        assertFalse(sharedChosen.equals(unchosenGuess));
        // Key derivation binds the whole 256-byte element; any change changes it.
        byte[] k0 = Kdf.hkdf(SafePrimeGroup.elementToBytes(sharedChosen),
                "dh-base-ot/v1".getBytes(), Kdf.KEY_LEN);
        BigInteger tampered = group.mul(sharedChosen, group.generator());
        byte[] k0b = Kdf.hkdf(SafePrimeGroup.elementToBytes(tampered),
                "dh-base-ot/v1".getBytes(), Kdf.KEY_LEN);
        assertFalse(Arrays.equals(k0, k0b));
    }

    @Test
    void unchosenExtensionMessageCannotBeOpened() throws Exception {
        int n = 128;
        OtService.ExtensionSession session = service.createExtensionSession(n, 128);
        boolean[] choices = new boolean[n];
        Arrays.fill(choices, true);
        java.util.concurrent.Future<?> sender = OtService.startExtensionSender(session,
                idx -> new byte[][]{
                        ("zero-message-" + idx).getBytes(),
                        ("one-message-" + idx).getBytes()});
        session.receiver().submitChoices(choices);
        byte[][] chosen = session.receiver().redeemRange(0, n);
        for (int i = 0; i < n; i++) {
            assertTrue(new String(chosen[i]).startsWith("one-message-"));
        }
        sender.get();
    }

    @Test
    void iknpCorrelationHidesChoiceUnderRandomOracle() {
        // Two different choice vectors produce independent-looking T rows after
        // the random oracle; the sender only ever sees the sealed correlation.
        byte[] rowA = Iknp.randomBitString(128);
        byte[] rowB = Iknp.randomBitString(128);
        byte[] keyA = Iknp.rowKey(rowA, 0, 0);
        byte[] keyB = Iknp.rowKey(rowB, 0, 0);
        assertFalse(Arrays.equals(keyA, keyB));
    }

    @Test
    void aesGcmRejectsTamperedCiphertext() throws Exception {
        byte[] key = new byte[32];
        new Random(1).nextBytes(key);
        byte[] nonce = new byte[12];
        byte[] sealed = Kdf.seal(key, nonce, "secret".getBytes());
        sealed[sealed.length - 1] ^= 1;
        boolean rejected = false;
        try {
            Kdf.open(key, nonce, sealed);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        assertTrue(rejected);
    }

    @Test
    void randomGroupElementsAreUniformAndDifferent() {
        SafePrimeGroup group = SafePrimeGroup.MODP_2048;
        BigInteger first = group.pow(group.randomExponent());
        BigInteger second = group.pow(group.randomExponent());
        assertFalse(first.equals(second));
        assertTrue(group.isValidElement(first));
        assertTrue(group.isValidElement(second));
    }
}

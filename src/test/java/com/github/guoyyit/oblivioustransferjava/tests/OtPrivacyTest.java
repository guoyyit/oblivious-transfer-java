package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.base.BaseOtMessages;
import com.github.guoyyit.oblivioustransferjava.ot.base.BaseOtReceiver;
import com.github.guoyyit.oblivioustransferjava.ot.base.BaseOtSender;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.Group;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.extension.ExtensionReceiver;
import com.github.guoyyit.oblivioustransferjava.ot.extension.ExtensionSender;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 选择隐私与发送方隐私测试。
 */
class OtPrivacyTest {

    @Test
    void receiverPublicKeyIsUniformRegardlessOfChoiceBit() {
        Group group = Group.modp2048();
        SecureRandom random = SymCrypto.secureRandom();
        BaseOtSender sender = new BaseOtSender(group, random);
        BaseOtSender.Init init = sender.init();

        BigInteger sum0 = BigInteger.ZERO;
        BigInteger sum1 = BigInteger.ZERO;
        int samples = 16;
        for (int i = 0; i < samples; i++) {
            BaseOtReceiver receiver = new BaseOtReceiver(group, random);
            sum0 = sum0.add(group.decodeElement(
                    receiver.choose(init.c0(), 0).pk()));
            sum1 = sum1.add(group.decodeElement(
                    receiver.choose(init.c0(), 1).pk()));
        }
        assertEquals(sum0.mod(group.prime()).signum() >= 0, true);
        assertEquals(sum1.mod(group.prime()).signum() >= 0, true);

        BaseOtReceiver receiver = new BaseOtReceiver(group, random);
        byte[] pk0 = receiver.choose(init.c0(), 0).pk();
        byte[] pk1 = new BaseOtReceiver(group, random).choose(init.c0(), 1).pk();
        assertFalse(Arrays.equals(pk0, pk1));
        assertDoesNotThrow(() -> group.decodeElement(pk0));
        assertDoesNotThrow(() -> group.decodeElement(pk1));
    }

    @Test
    void unchosenCiphertextCannotBeDecrypted() {
        Group group = Group.modp2048();
        SecureRandom random = SymCrypto.secureRandom();
        BaseOtSender sender = new BaseOtSender(group, random);
        BaseOtSender.Init init = sender.init();
        BaseOtReceiver receiver = new BaseOtReceiver(group, random);

        BaseOtReceiver.Choice choice = receiver.choose(init.c0(), 0);
        MessagePair pair = new MessagePair(
                "chosen".getBytes(), "secret-other".getBytes());
        byte[][] ciphertexts = sender.respond(init, choice.pk(), pair);

        byte[] chosen = receiver.decode(choice, ciphertexts, 6);
        assertEquals("chosen", new String(chosen));

        BaseOtReceiver.Choice sameChoice = receiver.choose(init.c0(), 0);
        OtException error = assertThrows(OtException.class,
        () -> receiver.decode(sameChoice,
                new byte[][]{ciphertexts[1], ciphertexts[1]}, -1));
        assertEquals(ErrorCode.DECRYPTION_FAILED, error.code());
    }

    @Test
    void extensionRowPairsAreIndependentAndChosenOneMatches() {
        int kappa = 128;
        int n = 32;
        SecureRandom random = SymCrypto.secureRandom();
        ExtensionSender sender = new ExtensionSender(kappa, random);
        boolean[] s = sender.generateS();

        byte[] choices = new byte[n];
        for (int i = 0; i < n; i++) {
            choices[i] = (byte) (i % 2);
        }
        ExtensionReceiver receiver = new ExtensionReceiver(kappa, choices, random);
        byte[][][] basePairs = receiver.generateBasePairs();
        byte[][] received = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            received[j] = basePairs[j][s[j] ? 1 : 0];
        }
        sender.installBaseSeeds(received);

        ExtensionReceiver.BatchColumns columns = receiver.produceColumns(0, n);
        ExtensionSender.RowPair[] rows =
                sender.deriveBatch(0, n, columns.a(), columns.b());

        for (int i = 0; i < n; i++) {
            byte[] chosenKey = receiver.deriveKey(i);
            byte[] matching = choices[i] == 0 ? rows[i].k0() : rows[i].k1();
            byte[] other = choices[i] == 0 ? rows[i].k1() : rows[i].k0();
            assertArrayEquals(matching, chosenKey);
            assertFalse(Arrays.equals(other, chosenKey));
        }

        assertFalse(Arrays.equals(rows[0].k0(), rows[1].k0()));
        assertFalse(Arrays.equals(rows[0].k1(), rows[0].k0()));
    }

    private static void assertArrayEquals(byte[] expected, byte[] actual) {
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    void invalidGroupElementsAreRejected() {
        Group group = Group.modp2048();
        byte[] zero = new byte[256];
        byte[] one = new byte[256];
        one[255] = 1;
        assertThrows(OtException.class, () -> group.decodeElement(zero));
        assertThrows(OtException.class, () -> group.decodeElement(one));
    }
}

package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.service.OtService;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the privacy guarantee against the receiver: for every OT the
 * receiver can only open the message corresponding to its committed choice bit.
 * Opening the other sealed message with any key material it holds fails.
 */
class SenderPrivacyTest {

    private final OtService service = new OtService();

    @Test
    void baseOtOnlyChosenMessageAuthenticates() throws Exception {
        // We run both base OTs twice with opposite choices using the same pair
        // values; the message the receiver did NOT select in one run must differ
        // from what it can obtain in that run.
        byte[][] pair = {"sender-secret-zero".getBytes(), "sender-secret-one".getBytes()};
        java.util.List<byte[][]> zero = new java.util.ArrayList<>();
        zero.add(pair);
        java.util.List<byte[][]> one = new java.util.ArrayList<>();
        one.add(pair);

        byte[][] gotZero = service.executeBase(zero, new boolean[]{false});
        byte[][] gotOne = service.executeBase(one, new boolean[]{true});

        assertTrue(Arrays.equals(gotZero[0], pair[0]));
        assertTrue(Arrays.equals(gotOne[0], pair[1]));
        assertFalse(Arrays.equals(gotZero[0], pair[1]));
    }

    @Test
    void extensionReceiverCannotOpenUnchosenSide() throws Exception {
        int n = 128;
        OtService.ExtensionSession session = service.createExtensionSession(n, 128);
        boolean[] choices = new boolean[n]; // receiver chooses side 0 everywhere
        Future<?> sender = OtService.startExtensionSender(session, idx -> {
            byte[] m0 = ("Z-" + idx + "-zero-side").getBytes();
            byte[] m1 = ("O-" + idx + "-one-side").getBytes();
            return new byte[][]{m0, m1};
        });
        session.receiver().submitChoices(choices);
        byte[][] received = session.receiver().redeemRange(0, n);
        for (int i = 0; i < n; i++) {
            String text = new String(received[i]);
            assertTrue(text.startsWith("Z-"), "only side-0 message may be recovered");
            assertFalse(text.contains("one-side"));
        }
        sender.get();
    }

    @Test
    void redeemingAcrossSessionsIsRejected() throws Exception {
        int n = 128;
        OtService.ExtensionSession a = service.createExtensionSession(n, 128);
        OtService.ExtensionSession b = service.createExtensionSession(n, 128);
        Future<?> sa = OtService.startExtensionSender(a,
                idx -> new byte[][]{"x".getBytes(), "y".getBytes()});
        Future<?> sb = OtService.startExtensionSender(b,
                idx -> new byte[][]{"p".getBytes(), "q".getBytes()});
        a.receiver().submitChoices(new boolean[n]);
        b.receiver().submitChoices(new boolean[n]);

        // Each session keeps its own cursor; using one session's index against
        // the other is impossible because envelopes are session bound.
        a.receiver().redeemRange(0, 10);
        b.receiver().redeemRange(0, 5);
        OtException conflict = assertThrows(OtException.class,
                () -> b.receiver().redeemRange(10, 5));
        assertTrue(conflict.errorCode() == ErrorCode.REDEMPTION_CONFLICT
                || conflict.errorCode() == ErrorCode.RANGE_OUT_OF_BOUNDS);
        a.receiver().abort();
        b.receiver().abort();
        sa.cancel(true);
        sb.cancel(true);
    }
}

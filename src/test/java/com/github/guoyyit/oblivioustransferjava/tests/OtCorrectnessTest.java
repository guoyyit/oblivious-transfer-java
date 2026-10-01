package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.service.OtService;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OtCorrectnessTest {

    private final OtService service = new OtService();

    private static List<byte[][]> pairs(List<byte[]> m0, List<byte[]> m1) {
        List<byte[][]> out = new ArrayList<>();
        for (int i = 0; i < m0.size(); i++) {
            out.add(new byte[][]{m0.get(i), m1.get(i)});
        }
        return out;
    }

    @Test
    void baseOtDeliversExactlyTheChosenMessage() {
        int n = 50;
        List<byte[]> m0 = new ArrayList<>();
        List<byte[]> m1 = new ArrayList<>();
        boolean[] choices = new boolean[n];
        Random random = new Random(42);
        for (int i = 0; i < n; i++) {
            choices[i] = random.nextBoolean();
            byte[] a = new byte[1 + random.nextInt(32)];
            byte[] b = new byte[1 + random.nextInt(64)];
            random.nextBytes(a);
            random.nextBytes(b);
            m0.add(a);
            m1.add(b);
        }
        List<byte[][]> data = pairs(m0, m1);
        byte[][] received = service.executeBase(data, choices);
        for (int i = 0; i < n; i++) {
            assertArrayEquals(data.get(i)[choices[i] ? 1 : 0], received[i]);
        }
    }

    @Test
    void baseOtSupportsEmptyAndBinaryMessages() {
        List<byte[][]> data = new ArrayList<>();
        data.add(new byte[][]{new byte[0], new byte[]{0, 1, 2}});
        data.add(new byte[][]{{(byte) 0xFF}, new byte[0]});
        byte[][] r0 = service.executeBase(data, new boolean[]{false, false});
        byte[][] r1 = service.executeBase(data, new boolean[]{true, true});
        assertArrayEquals(new byte[0], r0[0]);
        assertArrayEquals(new byte[]{0, 1, 2}, r1[0]);
        // Pair 2: choice true selects the second message (empty here).
        assertArrayEquals(new byte[0], r1[1]);
        // Choice false on pair 2 selects 0xFF (first message).
        byte[][] mixed = service.executeBase(data, new boolean[]{false, false});
        assertArrayEquals(new byte[0], mixed[0]);
        assertArrayEquals(new byte[]{(byte) 0xFF}, mixed[1]);
    }

    @Test
    void extensionOtDeliversExactlyTheChosenMessagesAcrossBatches() {
        int n = 1000;
        byte[][][] data = new byte[n][][];
        boolean[] choices = new boolean[n];
        Random random = new Random(7);
        for (int i = 0; i < n; i++) {
            choices[i] = i % 2 == 0;
            byte[] second = new byte[1 + random.nextInt(100)];
            random.nextBytes(second);
            data[i] = new byte[][]{("m0-" + i).getBytes(), second};
        }
        byte[][] received = service.executeExtension(
                idx -> new byte[][]{data[idx][0], data[idx][1]}, choices, 128);
        for (int i = 0; i < n; i++) {
            assertArrayEquals(data[i][choices[i] ? 1 : 0], received[i]);
        }
    }

    @Test
    void extensionSupportsSingleAndRangeRedemption() throws Exception {
        int n = 260;
        OtService.ExtensionSession session = service.createExtensionSession(n, 128);
        boolean[] choices = new boolean[n];
        for (int i = 0; i < n; i++) {
            choices[i] = i % 5 == 0;
        }
        java.util.concurrent.Future<?> sender = OtService.startExtensionSender(session,
                idx -> new byte[][]{("a" + idx).getBytes(), ("b" + idx).getBytes()});
        session.receiver().submitChoices(choices);

        assertArrayEquals(("b" + 0).getBytes(), session.receiver().redeemOne(0));
        byte[][] range = session.receiver().redeemRange(1, 126);
        for (int i = 1; i < 127; i++) {
            assertEquals(choices[i] ? "b" + i : "a" + i, new String(range[i - 1]));
        }
        session.receiver().redeemOne(127);
        // Batches are 128, 128, 4 (last batch absorbs the remainder).
        byte[][] middle = session.receiver().redeemRange(128, 128);
        assertEquals(128, middle.length);
        byte[][] tail = session.receiver().redeemRange(256, 4);
        assertEquals(4, tail.length);
        assertEquals("a259", new String(tail[3]));
        sender.get();
    }

    @Test
    void rejectsIllegalBaseParameters() {
        OtException countError = assertThrows(OtException.class,
                () -> service.createBaseSession(0));
        assertEquals(ErrorCode.INVALID_PARAMETER, countError.errorCode());

        List<byte[][]> bad = new ArrayList<>();
        bad.add(new byte[][]{null, new byte[]{1}});
        OtException nullMessage = assertThrows(OtException.class,
                () -> service.executeBase(bad, new boolean[]{false}));
        assertEquals(ErrorCode.INVALID_PARAMETER, nullMessage.errorCode());
    }

    @Test
    void rejectsIllegalBatchSizes() {
        OtException tooSmall = assertThrows(OtException.class,
                () -> service.createExtensionSession(1000, 8));
        assertEquals(ErrorCode.INVALID_PARAMETER, tooSmall.errorCode());
    }

    @Test
    void rejectedChoiceVectorDoesNotEstablishSession() {
        OtService.ExtensionSession session = service.createExtensionSession(10, 128);
        OtException error = assertThrows(OtException.class,
                () -> session.receiver().submitChoices(new boolean[3]));
        assertEquals(ErrorCode.CHOICE_OUT_OF_RANGE, error.errorCode());
        assertTrue(service.registry().activeCount() <= 1);
    }

    @Test
    void rejectsOutOfOrderAndDuplicateRedemption() throws Exception {
        int n = 260;
        OtService.ExtensionSession session = service.createExtensionSession(n, 128);
        boolean[] choices = new boolean[n];
        java.util.concurrent.Future<?> sender = OtService.startExtensionSender(session,
                idx -> new byte[][]{("a" + idx).getBytes(), ("b" + idx).getBytes()});
        session.receiver().submitChoices(choices);

        session.receiver().redeemRange(0, 2);
        OtException skipped = assertThrows(OtException.class,
                () -> session.receiver().redeemRange(3, 10));
        assertEquals(ErrorCode.REDEMPTION_CONFLICT, skipped.errorCode());
        session.receiver().redeemRange(2, 10);
        OtException duplicate = assertThrows(OtException.class,
                () -> session.receiver().redeemOne(3));
        assertEquals(ErrorCode.REDEMPTION_CONFLICT, duplicate.errorCode());

        OtException outOfBounds = assertThrows(OtException.class,
                () -> session.receiver().redeemRange(12, 1000));
        assertEquals(ErrorCode.RANGE_OUT_OF_BOUNDS, outOfBounds.errorCode());
        session.receiver().abort();
        sender.cancel(true);
    }
}

package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.OtService;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtConfig;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BatchOtCorrectnessTest {

    private OtService service(int batchSize) {
        return new OtService(OtConfig.defaults().securityBits(128).batchSize(batchSize));
    }

    private byte[] runAll(OtService.BatchSession session, int n) {
        List<byte[]> received = new ArrayList<>();
        while (session.receiver().cursor() < n) {
            for (byte[] message : session.receiver().redeemNextBatch()) {
                received.add(message);
            }
        }
        assertEquals(n, received.size());
        return null;
    }

    @Test
    void unevenLengthMessagesAreDeliveredCorrectly() {
        OtService service = service(3);
        try {
            int n = 7;
            List<MessagePair> pairs = new ArrayList<>();
            pairs.add(new MessagePair(new byte[0], "x".getBytes(StandardCharsets.UTF_8)));
            pairs.add(new MessagePair("abc".getBytes(StandardCharsets.UTF_8), new byte[0]));
            for (int i = 2; i < n; i++) {
                pairs.add(new MessagePair(
                        ("a" + i).getBytes(StandardCharsets.UTF_8),
                        ("much-longer-second-message-" + i).getBytes(StandardCharsets.UTF_8)));
            }
            byte[] choices = {1, 0, 0, 1, 1, 0, 1};
            OtService.BatchSession session =
                    service.createBatchSession(TestSupport.source(pairs), choices);
            session.receiver().start(n, choices);

            List<byte[]> received = new ArrayList<>();
            while (session.receiver().cursor() < n) {
                for (byte[] message : session.receiver().redeemNextBatch()) {
                    received.add(message);
                }
            }
            for (int i = 0; i < n; i++) {
                byte[] expected = choices[i] == 0
                        ? pairs.get(i).message0() : pairs.get(i).message1();
                assertArrayEquals(expected, received.get(i));
            }
        } finally {
            service.shutdown();
        }
    }

    @Test
    void singleRedemptionStrictlyFollowsOrder() {
        OtService service = service(100);
        try {
            int n = 5;
            List<MessagePair> pairs = TestSupport.messages(n);
            byte[] choices = {1, 1, 0, 0, 1};
            OtService.BatchSession session =
                    service.createBatchSession(TestSupport.source(pairs), choices);
            session.receiver().start(n, choices);

            assertThrows(OtException.class, () -> session.receiver().redeemOne(1));

            for (int i = 0; i < n; i++) {
                byte[] message = session.receiver().redeemOne(i);
                assertArrayEquals(choices[i] == 0
                        ? pairs.get(i).message0() : pairs.get(i).message1(), message);
            }
        } finally {
            service.shutdown();
        }
    }

    @Test
    void outOfOrderRangeRedemptionIsRejected() {
        OtService service = service(4);
        try {
            int n = 10;
            List<MessagePair> pairs = TestSupport.messages(n);
            byte[] choices = TestSupport.alternatingChoices(n);
            OtService.BatchSession session =
                    service.createBatchSession(TestSupport.source(pairs), choices);
            session.receiver().start(n, choices);

            assertThrows(OtException.class,
                    () -> session.receiver().redeemRange(2, 4));
            byte[][] first = session.receiver().redeemRange(0, 4);
            assertEquals(4, first.length);
            assertThrows(OtException.class,
                    () -> session.receiver().redeemRange(4, 8));
        } finally {
            service.shutdown();
        }
    }

    @Test
    void illegalArgumentsRejectedBeforeSessionCreation() {
        OtService service = service(4);
        try {
            List<MessagePair> pairs = TestSupport.messages(3);
            assertThrows(OtException.class,
                    () -> service.createBatchSession(null, new byte[]{0, 1, 0}));
            assertThrows(OtException.class,
                    () -> service.createBatchSession(TestSupport.source(pairs),
                            new byte[]{0, 1, 2}));
            assertThrows(OtException.class,
                    () -> service.createBatchSession(TestSupport.source(pairs),
                            new byte[]{0, 1}));
            assertEquals(0, service.activeSessionCount());
        } finally {
            service.shutdown();
        }
    }
}

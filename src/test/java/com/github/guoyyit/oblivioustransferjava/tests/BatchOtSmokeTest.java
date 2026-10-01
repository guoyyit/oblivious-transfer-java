package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.OtService;
import com.github.guoyyit.oblivioustransferjava.ot.batch.BatchSender;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtConfig;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class BatchOtSmokeTest {

    private static List<MessagePair> messages(int n) {
        List<MessagePair> pairs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            pairs.add(new MessagePair(
                    ("m0-" + i).getBytes(StandardCharsets.UTF_8),
                    ("second-message-1-" + i).getBytes(StandardCharsets.UTF_8)));
        }
        return pairs;
    }

    private static BatchSenderMessageSource source(List<MessagePair> pairs) {
        return new BatchSenderMessageSource(pairs);
    }

    @Test
    void smallBatchDeliversChosenMessages() {
        OtConfig config = OtConfig.defaults().securityBits(128).batchSize(4);
        OtService service = new OtService(config);
        try {
            int n = 10;
            List<MessagePair> pairs = messages(n);
            byte[] choices = {0, 1, 1, 0, 1, 0, 0, 1, 1, 0};

            OtService.BatchSession session =
                    service.createBatchSession(source(pairs), choices);
            session.receiver().start(n, choices);

            List<byte[]> received = new ArrayList<>();
            while (session.receiver().cursor() < n) {
                byte[][] batch = session.receiver().redeemNextBatch();
                for (byte[] message : batch) {
                    received.add(message);
                }
            }

            assertEquals(n, received.size());
            for (int i = 0; i < n; i++) {
                byte[] expected = choices[i] == 0
                        ? pairs.get(i).message0() : pairs.get(i).message1();
                assertArrayEquals(expected, received.get(i));
            }
        } finally {
            service.shutdown();
        }
    }

    static final class BatchSenderMessageSource implements BatchSender.MessageSource {
        private final List<MessagePair> pairs;

        BatchSenderMessageSource(List<MessagePair> pairs) {
            this.pairs = pairs;
        }

        @Override
        public int size() {
            return pairs.size();
        }

        @Override
        public MessagePair get(int index) {
            return pairs.get(index);
        }
    }
}

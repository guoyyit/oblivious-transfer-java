package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.OtService;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtConfig;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LargeBatchTest {

    @Test
    void largeNumberOfMessagesRedeemedInConfiguredBatches() {
        int batchSize = 256;
        OtService service = new OtService(
                OtConfig.defaults().securityBits(128).batchSize(batchSize));
        try {
            int n = 2_000;
            List<MessagePair> pairs = new ArrayList<>();
            byte[] choices = new byte[n];
            for (int i = 0; i < n; i++) {
                pairs.add(new MessagePair(
                        ("l0-" + i).getBytes(), ("l1-" + i).getBytes()));
                choices[i] = (byte) (i % 3 == 0 ? 1 : 0);
            }
            OtService.BatchSession session =
                    service.createBatchSession(TestSupport.source(pairs), choices);
            session.receiver().start(n, choices);

            int redeemed = 0;
            int batches = 0;
            while (session.receiver().cursor() < n) {
                int before = session.receiver().cursor();
                byte[][] batch = session.receiver().redeemNextBatch();
                int count = session.receiver().cursor() - before;
                assertTrue(count <= batchSize);
                for (int local = 0; local < batch.length; local++) {
                    int index = before + local;
                    byte[] expected = choices[index] == 0
                            ? pairs.get(index).message0() : pairs.get(index).message1();
                    assertArrayEquals(expected, batch[local]);
                }
                redeemed += count;
                batches++;
            }
            assertTrue(redeemed == n);
            assertTrue(batches == (n + batchSize - 1) / batchSize);
        } finally {
            service.shutdown();
        }
    }

    @Test
    void largeBatchCanBeCancelledMidway() throws Exception {
        int batchSize = 128;
        OtService service = new OtService(
                OtConfig.defaults().securityBits(128).batchSize(batchSize));
        try {
            int n = 5_000;
            List<MessagePair> pairs = new ArrayList<>();
            byte[] choices = new byte[n];
            for (int i = 0; i < n; i++) {
                pairs.add(new MessagePair(("a" + i).getBytes(), ("b" + i).getBytes()));
                choices[i] = (byte) (i % 2);
            }
            OtService.BatchSession session =
                    service.createBatchSession(TestSupport.source(pairs), choices);
            session.receiver().start(n, choices);
            for (int round = 0; round < 3; round++) {
                session.receiver().redeemNextBatch();
            }
            int partial = session.receiver().cursor();
            assertTrue(partial < n);

            Runtime runtime = Runtime.getRuntime();
            runtime.gc();
            long before = runtime.totalMemory() - runtime.freeMemory();
            session.receiver().cancel();
            runtime.gc();
            Thread.sleep(200);
            long after = runtime.totalMemory() - runtime.freeMemory();

            long retainedDelta = after - before;
            assertTrue(retainedDelta < 4L * 1024 * 1024,
                    "取消后不应残留大量中间状态, delta=" + retainedDelta);
        } finally {
            service.shutdown();
        }
    }
}

package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.service.OtService;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Concurrent-session isolation, mid-protocol abort and post-cancel cleanup.
 */
class OtConcurrencyAbortTest {

    private final OtService service = new OtService();

    @RepeatedTest(5)
    void manyConcurrentSessionsStayIsolatedAndCorrect() throws Exception {
        int sessions = 12;
        int n = 400;
        ExecutorService pool = Executors.newFixedThreadPool(sessions);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger verified = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        for (int sid = 0; sid < sessions; sid++) {
            final int sessionSeed = sid;
            futures.add(pool.submit(() -> {
                start.await();
                byte[][][] data = new byte[n][][];
                boolean[] choices = new boolean[n];
                for (int i = 0; i < n; i++) {
                    choices[i] = (i + sessionSeed) % 2 == 0;
                    data[i] = new byte[][]{
                            ("s" + sessionSeed + "-m0-" + i).getBytes(),
                            ("s" + sessionSeed + "-m1-" + i).getBytes()};
                }
                byte[][] received = service.executeExtension(
                        idx -> data[idx], choices, 128);
                for (int i = 0; i < n; i++) {
                    byte[] expected = data[i][choices[i] ? 1 : 0];
                    if (!Arrays.equals(expected, received[i])) {
                        throw new AssertionError("cross-session data leak at " + sessionSeed);
                    }
                }
                verified.incrementAndGet();
                return null;
            }));
        }
        start.countDown();
        for (Future<?> future : futures) {
            future.get();
        }
        pool.shutdown();
        assertEquals(sessions, verified.get());
        assertEquals(0, service.registry().activeCount());
    }

    @Test
    void abortingOneSessionDoesNotAffectOthers() throws Exception {
        int n = 128;
        OtService.ExtensionSession victim = service.createExtensionSession(n, 128);
        OtService.ExtensionSession healthy = service.createExtensionSession(n, 128);

        Future<?> victimSender = OtService.startExtensionSender(victim,
                idx -> new byte[][]{("a" + idx).getBytes(), ("b" + idx).getBytes()});
        Future<?> healthySender = OtService.startExtensionSender(healthy,
                idx -> new byte[][]{("h0-" + idx).getBytes(), ("h1-" + idx).getBytes()});

        victim.receiver().submitChoices(new boolean[n]);
        healthy.receiver().submitChoices(new boolean[n]);

        victim.receiver().redeemRange(0, 10);
        victim.receiver().cancel();

        byte[][] healthyMessages = healthy.receiver().redeemRange(0, n);
        assertEquals(n, healthyMessages.length);
        assertTrue(new String(healthyMessages[0]).startsWith("h0-"));
        healthySender.get();
        victimSender.cancel(true);
    }

    @Test
    void cancelledSessionIsTombstonedAndCannotReuseState() throws Exception {
        int n = 128;
        OtService.ExtensionSession session = service.createExtensionSession(n, 128);
        Future<?> sender = OtService.startExtensionSender(session,
                idx -> new byte[][]{("a" + idx).getBytes(), ("b" + idx).getBytes()});
        session.receiver().submitChoices(new boolean[n]);
        session.receiver().redeemRange(0, 5);
        int totalBefore = service.registry().totalCount();
        session.receiver().cancel();
        sender.cancel(true);

        OtException reuse = assertCancelled(() ->
                session.receiver().redeemRange(5, 5));
        assertTrue(reuse.errorCode() == ErrorCode.CANCELLED
                || reuse.errorCode() == ErrorCode.SESSION_ABORTED);
        // Registry still tracks the id as a tombstone; a fresh id differs.
        assertEquals(totalBefore, service.registry().totalCount());
    }

    @Test
    void invalidParametersDoNotConsumeActiveSessions() {
        int before = service.registry().totalCount();
        try {
            service.createBaseSession(-1);
        } catch (OtException expected) {
            assertEquals(ErrorCode.INVALID_PARAMETER, expected.errorCode());
        }
        assertEquals(before, service.registry().totalCount());
    }

    private interface ThrowingRunnable {
        void run();
    }

    private static OtException assertCancelled(ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("expected OtException");
        } catch (OtException error) {
            return error;
        }
    }
}

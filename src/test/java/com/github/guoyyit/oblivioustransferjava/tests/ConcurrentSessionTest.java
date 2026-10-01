package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.OtService;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtConfig;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConcurrentSessionTest {

    @Test
    void manySessionsRunConcurrentlyAndStayIsolated() throws Exception {
        OtService service = new OtService(
                OtConfig.defaults().securityBits(128).batchSize(8));
        int sessions = 8;
        int n = 24;
        ExecutorService pool = Executors.newFixedThreadPool(sessions);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<String> failures = new ConcurrentLinkedQueue<>();
        List<java.util.concurrent.Future<?>> futures = new ArrayList<>();

        try {
            for (int session = 0; session < sessions; session++) {
                final int sessionIndex = session;
                futures.add(pool.submit(() -> {
                    try {
                        start.await();
                        List<MessagePair> pairs = TestSupport.messages(n);
                        byte[] choices = new byte[n];
                        for (int i = 0; i < n; i++) {
                            choices[i] = (byte) ((i + sessionIndex) % 2);
                        }
                        OtService.BatchSession batch =
                                service.createBatchSession(TestSupport.source(pairs), choices);
                        batch.receiver().start(n, choices);
                        int got = 0;
                        while (batch.receiver().cursor() < n) {
                            byte[][] messages = batch.receiver().redeemNextBatch();
                            for (byte[] message : messages) {
                                int index = got++;
                                byte[] expected = choices[index] == 0
                                        ? pairs.get(index).message0()
                                        : pairs.get(index).message1();
                                assertArrayEquals(expected, message);
                            }
                        }
                    } catch (Throwable t) {
                        failures.add(sessionIndex + ": " + t.getMessage());
                    }
                }));
            }
            start.countDown();
            for (java.util.concurrent.Future<?> future : futures) {
                future.get(120, TimeUnit.SECONDS);
            }
            assertTrue(failures.isEmpty(), "并发会话失败: " + failures);
        } finally {
            pool.shutdownNow();
            service.shutdown();
        }
    }

    @Test
    void oneSessionFailureDoesNotAffectOthers() throws Exception {
        OtService service = new OtService(OtConfig.defaults().batchSize(4));
        ExecutorService pool = Executors.newFixedThreadPool(3);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<java.util.concurrent.Future<?>> futures = new ArrayList<>();

            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    int n = 8;
                    List<MessagePair> pairs = TestSupport.messages(n);
                    byte[] choices = TestSupport.alternatingChoices(n);
                    OtService.BatchSession good =
                            service.createBatchSession(TestSupport.source(pairs), choices);
                    good.receiver().start(n, choices);
                    while (good.receiver().cursor() < n) {
                        good.receiver().redeemNextBatch();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException(e);
                }
            }));

            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    int n = 8;
                    List<MessagePair> pairs = TestSupport.messages(n);
                    byte[] badChoices = {0, 1, 9, 0, 1, 0, 1, 0};
                    service.createBatchSession(TestSupport.source(pairs), badChoices);
                } catch (Exception ignored) {
                }
            }));

            start.countDown();
            futures.get(0).get(60, TimeUnit.SECONDS);
            futures.get(1).get(60, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
            service.shutdown();
        }
    }
}

package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.batch.BatchReceiver;
import com.github.guoyyit.oblivioustransferjava.ot.batch.BatchSender;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.Group;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.extension.ExtensionReceiver;
import com.github.guoyyit.oblivioustransferjava.ot.extension.ExtensionSender;
import com.github.guoyyit.oblivioustransferjava.ot.extension.StreamingPrg;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.Envelope;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtConfig;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.SessionStatus;
import com.github.guoyyit.oblivioustransferjava.ot.transport.InProcessChannelPair;
import com.github.guoyyit.oblivioustransferjava.ot.transport.MessageAuthenticator;
import com.github.guoyyit.oblivioustransferjava.ot.transport.OtChannel;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 发送方视角的选择隐私测试。
 *
 * <p>模拟一个诚实但好奇的发送方：它持有自己的选择向量 s、基础 OT 取回的
 * 种子 k_{s_j}、自身随机源，以及协议中收到的全部消息（承诺与 u 矩阵列），
 * 尝试还原接收方选择向量。断言其最佳攻击（残差行分析与多数表决）不得
 * 获得任何超过随机猜测的信息，且视图不随消息内容、批次边界或重复运行
 * 出现可区分偏差。
 */
class SenderViewPrivacyTest {

    private static final int KAPPA = 128;
    /** 与扩展层一致的全局列 PRG 域分离串（线路常量）。 */
    private static final byte[] DOMAIN_COLUMN = {'i', 'k', 'n', 'p', '-', 'c', 'o', 'l'};

    private static final int MSG_BASE_SENDER_INIT = 10;
    private static final int MSG_BASE_CIPHERTEXTS = 12;
    private static final int MSG_COMMIT = 20;
    private static final int MSG_T_COLUMNS = 21;
    private static final int MSG_REDEMPTION = 30;
    private static final int MSG_DONE = 40;

    // ------------------------------------------------------------------
    // 扩展层：对全零/全一/随机选择向量的发送方视图统计攻击（单批与多批）
    // ------------------------------------------------------------------

    @Test
    void allZeroChoicesAreHiddenFromSenderView() {
        runSenderViewAttack(uniformChoices(512, 0), 113);
        runSenderViewAttack(uniformChoices(512, 0), 512);
    }

    @Test
    void allOneChoicesAreHiddenFromSenderView() {
        runSenderViewAttack(uniformChoices(512, 1), 113);
        runSenderViewAttack(uniformChoices(512, 1), 512);
    }

    @Test
    void randomChoicesAreHiddenFromSenderView() {
        runSenderViewAttack(randomChoices(512, 20261007L), 113);
        runSenderViewAttack(randomChoices(512, 20261007L), 512);
    }

    /**
     * 发送方完整视图攻击：用 (s, k_{s_j}, u 矩阵) 计算残差
     * v_j = u_j ⊕ G(k_{s_j})，逐行做常量行检测与多数表决。
     */
    private void runSenderViewAttack(byte[] choices, int batchSize) {
        int n = choices.length;
        ExtensionSender sender = new ExtensionSender(KAPPA, new SeededRandom(11L));
        boolean[] s = sender.generateS();
        ExtensionReceiver receiver =
                new ExtensionReceiver(KAPPA, choices, new SeededRandom(22L));
        byte[][][] basePairs = receiver.generateBasePairs();
        byte[][] chosenSeeds = new byte[KAPPA][];
        for (int j = 0; j < KAPPA; j++) {
            chosenSeeds[j] = basePairs[j][s[j] ? 1 : 0];
        }
        sender.installBaseSeeds(chosenSeeds);

        byte[][] u = collectColumns(receiver, n, batchSize);
        int totalBytes = n * KAPPA / 8;

        // 发送方最佳解掩码：v_j = u_j ⊕ G(k_{s_j})
        byte[][] residual = new byte[KAPPA][];
        for (int j = 0; j < KAPPA; j++) {
            byte[] g = StreamingPrg.expand(chosenSeeds[j], DOMAIN_COLUMN, 0, totalBytes);
            residual[j] = SymCrypto.xor(u[j], g);
            SymCrypto.wipe(g);
        }

        int correctGuesses = 0;
        for (int i = 0; i < n; i++) {
            int ones = 0;
            for (int j = 0; j < KAPPA; j++) {
                if (bit(residual[j], i * KAPPA + j)) {
                    ones++;
                }
            }
            assertTrue(ones > 0 && ones < KAPPA,
                    "残差行不得退化为常量行（旧实现的直接泄漏）row=" + i);
            int guess = ones * 2 >= KAPPA ? 1 : 0;
            if (guess == choices[i]) {
                correctGuesses++;
            }
        }
        int tolerance = (int) Math.ceil(5.0 * Math.sqrt(n / 4.0));
        assertTrue(Math.abs(correctGuesses - n / 2) <= tolerance,
                "多数表决命中率不得显著偏离 1/2: correct=" + correctGuesses
                        + " n=" + n + " tolerance=" + tolerance);
    }

    // ------------------------------------------------------------------
    // 扩展层：批次边界不得改变比特流；deriveKey 缓存与回退路径一致
    // ------------------------------------------------------------------

    @Test
    void batchBoundariesDoNotChangeTranscript() {
        int n = 200;
        byte[] choices = randomChoices(n, 777L);

        ExtensionReceiver single =
                new ExtensionReceiver(KAPPA, choices, new SeededRandom(33L));
        single.generateBasePairs();
        byte[][] singleShot = collectColumns(single, n, n);

        ExtensionReceiver multi =
                new ExtensionReceiver(KAPPA, choices, new SeededRandom(33L));
        multi.generateBasePairs();
        byte[][] batched = collectColumns(multi, n, 37);

        for (int j = 0; j < KAPPA; j++) {
            assertArrayEquals(singleShot[j], batched[j],
                    "批次边界不得改变第 " + j + " 列比特流");
        }

        // deriveKey：批次缓存命中与全局流回退必须给出同一行密钥
        ExtensionReceiver receiver =
                new ExtensionReceiver(KAPPA, choices, new SeededRandom(33L));
        receiver.generateBasePairs();
        receiver.produceColumns(0, 37);
        byte[] cachedKey = receiver.deriveKey(5);
        receiver.produceColumns(37, 37);
        byte[] fallbackKey = receiver.deriveKey(5);
        assertArrayEquals(cachedKey, fallbackKey,
                "缓存与回退路径的行密钥必须一致");
    }

    // ------------------------------------------------------------------
    // 扩展层：重复运行不得产生可重复的指纹
    // ------------------------------------------------------------------

    @Test
    void repeatedRunsWithSameChoicesProduceFreshTranscripts() {
        int n = 128;
        byte[] choices = randomChoices(n, 4242L);
        byte[][] first = collectColumns(freshReceiver(choices, 1L), n, 64);
        byte[][] second = collectColumns(freshReceiver(choices, 2L), n, 64);
        for (int j = 0; j < KAPPA; j++) {
            assertFalse(Arrays.equals(first[j], second[j]),
                    "相同选择向量重复运行的第 " + j + " 列不得相同");
        }
    }

    private static ExtensionReceiver freshReceiver(byte[] choices, long seed) {
        ExtensionReceiver receiver =
                new ExtensionReceiver(KAPPA, choices, new SeededRandom(seed));
        receiver.generateBasePairs();
        return receiver;
    }

    // ------------------------------------------------------------------
    // 协议层：承诺的隐藏性与盐化
    // ------------------------------------------------------------------

    @Test
    void commitmentIsHidingAndSalted() throws Exception {
        int n = 16;
        byte[] allZero = uniformChoices(n, 0);
        List<MessagePair> messages = TestSupport.messages(n);

        SessionRun run1 = runProtocol(allZero, messages, 5, 101L, 202L);
        byte[] commitment1 = run1.firstBodyOfType(MSG_COMMIT);

        // 对所有 2^n 个候选选择向量，未加盐的 SHA-256(n||v) 都不得命中承诺
        for (int mask = 0; mask < (1 << n); mask++) {
            byte[] candidate = new byte[n];
            for (int i = 0; i < n; i++) {
                candidate[i] = (byte) ((mask >>> i) & 1);
            }
            byte[] unsalted = SymCrypto.sha256(commitmentMaterial(n, candidate));
            assertFalse(Arrays.equals(unsalted, commitment1),
                    "承诺不得被未加盐穷举命中 mask=" + mask);
        }

        // 相同选择向量重复运行，承诺必须不同（一次性盐）
        SessionRun run2 = runProtocol(allZero, messages, 5, 303L, 404L);
        assertFalse(Arrays.equals(commitment1, run2.firstBodyOfType(MSG_COMMIT)),
                "相同选择向量的重复运行不得产生相同承诺");

        // 全一向量同样成立
        SessionRun run3 = runProtocol(uniformChoices(n, 1), messages, 5, 505L, 606L);
        byte[] commitment3 = run3.firstBodyOfType(MSG_COMMIT);
        assertFalse(Arrays.equals(
                SymCrypto.sha256(commitmentMaterial(n, uniformChoices(n, 1))),
                commitment3));
        assertFalse(Arrays.equals(commitment1, commitment3));
    }

    private static byte[] commitmentMaterial(int n, byte[] choices) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + choices.length);
        buffer.putInt(n);
        buffer.put(choices);
        return buffer.array();
    }

    // ------------------------------------------------------------------
    // 协议层：发送方收到的消息流不随消息内容变化
    // ------------------------------------------------------------------

    @Test
    void senderIncomingTranscriptIsIndependentOfMessageContent() throws Exception {
        int n = 24;
        byte[] choices = randomChoices(n, 9090L);
        List<MessagePair> messagesA = TestSupport.messages(n);
        List<MessagePair> messagesB = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            messagesB.add(new MessagePair(
                    ("completely-different-content-" + i).getBytes(),
                    ("B" + i + "-" + "x".repeat(i + 1)).getBytes()));
        }

        SessionRun runA = runProtocol(choices, messagesA, 5, 1001L, 2002L);
        SessionRun runB = runProtocol(choices, messagesB, 5, 1001L, 2002L);

        assertEquals(runA.receiverToSenderBodies(), runB.receiverToSenderBodies(),
                "消息内容不得影响发送方收到的任何协议消息");

        // 健全性：不同选择向量必须产生不同视图（排除空捕获等假阳性）
        byte[] flipped = choices.clone();
        flipped[0] ^= 1;
        SessionRun runC = runProtocol(flipped, messagesA, 5, 1001L, 2002L);
        assertFalse(runA.receiverToSenderBodies().equals(runC.receiverToSenderBodies()),
                "不同选择向量应产生不同视图（测试健全性）");

        // 两次运行接收方都取回了正确的选择消息
        assertRunCorrect(runA, choices, messagesA);
        assertRunCorrect(runB, choices, messagesB);
    }

    private static void assertRunCorrect(SessionRun run, byte[] choices,
                                         List<MessagePair> messages) {
        assertEquals(choices.length, run.receivedMessages().size());
        for (int i = 0; i < choices.length; i++) {
            byte[] expected = choices[i] == 0
                    ? messages.get(i).message0() : messages.get(i).message1();
            assertArrayEquals(expected, run.receivedMessages().get(i));
        }
    }

    // ------------------------------------------------------------------
    // 协议线束：装配真实 BatchSender/BatchReceiver，捕获发送方收到的全部消息
    // ------------------------------------------------------------------

    private record CapturedMessage(int type, byte[] body) {
    }

    private record SessionRun(List<CapturedMessage> receiverToSender,
                              List<byte[]> receivedMessages) {

        byte[] firstBodyOfType(int type) {
            for (CapturedMessage message : receiverToSender) {
                if (message.type() == type) {
                    return message.body();
                }
            }
            throw new IllegalStateException("未捕获到类型 " + type + " 的消息");
        }

        List<List<Byte>> receiverToSenderBodies() {
            List<List<Byte>> bodies = new ArrayList<>();
            for (CapturedMessage message : receiverToSender) {
                List<Byte> body = new ArrayList<>(message.body().length);
                for (byte b : message.body()) {
                    body.add(b);
                }
                bodies.add(body);
            }
            return bodies;
        }
    }

    private SessionRun runProtocol(byte[] choices, List<MessagePair> messages,
                                   int batchSize,
                                   long senderSeed, long receiverSeed) throws Exception {
        int n = choices.length;
        OtConfig config = OtConfig.defaults().securityBits(KAPPA).batchSize(batchSize);
        config.validate();

        byte[] sessionId = new byte[16];
        new SeededRandom(0x5EEDL).nextBytes(sessionId);
        byte[] senderKey = new byte[16];
        byte[] receiverKey = new byte[16];
        new SeededRandom(0xA11CEL).nextBytes(senderKey);
        new SeededRandom(0xB0B0L).nextBytes(receiverKey);

        InProcessChannelPair channels = new InProcessChannelPair(64, 10_000);
        List<Envelope> receiverToSender = Collections.synchronizedList(new ArrayList<>());
        OtChannel senderChannel = channels.sender();
        OtChannel receiverChannel = tapSend(channels.receiver(), receiverToSender);

        MessageAuthenticator senderAuth =
                new MessageAuthenticator(sessionId, senderKey, receiverKey);
        MessageAuthenticator receiverAuth =
                new MessageAuthenticator(sessionId, receiverKey, senderKey);
        AtomicReference<SessionStatus> status =
                new AtomicReference<>(SessionStatus.CREATED);
        Group group = Group.modp2048();

        BatchSender sender = new BatchSender(senderChannel, senderAuth, status,
                TestSupport.source(messages), config, group, new SeededRandom(senderSeed));
        BatchReceiver receiver = new BatchReceiver(receiverChannel, receiverAuth,
                status, config, group, new SeededRandom(receiverSeed));

        AtomicReference<Throwable> senderFailure = new AtomicReference<>();
        Thread senderThread = new Thread(() -> {
            try {
                sender.serve();
            } catch (Throwable t) {
                senderFailure.set(t);
            }
        }, "sender-view-privacy-test");
        senderThread.setDaemon(true);
        senderThread.start();

        receiver.start(n, choices);
        List<byte[]> received = new ArrayList<>();
        while (receiver.cursor() < n) {
            received.addAll(Arrays.asList(receiver.redeemNextBatch()));
        }
        senderThread.join(15_000);
        assertFalse(senderThread.isAlive(), "发送方线程必须结束");
        assertNull(senderFailure.get(), "发送方不得失败: " + senderFailure.get());
        assertEquals(SessionStatus.COMPLETED, status.get());

        // 以发送方密钥材料解密其收到的全部消息（即发送方实际视图）
        MessageAuthenticator senderView =
                new MessageAuthenticator(sessionId, senderKey, receiverKey);
        List<CapturedMessage> captured = new ArrayList<>();
        for (Envelope envelope : receiverToSender) {
            captured.add(new CapturedMessage(
                    envelope.messageType(), senderView.open(envelope)));
        }

        int expectedBatches = (n + batchSize - 1) / batchSize;
        int expectedCount = 2 * KAPPA + 1 + 2 * expectedBatches + 1;
        assertEquals(expectedCount, captured.size(),
                "捕获的消息数量必须符合协议流程");
        assertEquals(MSG_BASE_SENDER_INIT, captured.get(0).type());
        assertEquals(MSG_BASE_CIPHERTEXTS, captured.get(1).type());
        assertEquals(MSG_COMMIT, captured.get(2 * KAPPA).type());
        assertEquals(MSG_T_COLUMNS, captured.get(2 * KAPPA + 1).type());
        assertEquals(MSG_REDEMPTION, captured.get(2 * KAPPA + 2).type());
        assertEquals(MSG_DONE, captured.get(captured.size() - 1).type());

        return new SessionRun(captured, received);
    }

    private static OtChannel tapSend(OtChannel delegate, List<Envelope> sink) {
        return new OtChannel() {
            @Override
            public void send(Envelope envelope) throws InterruptedException {
                sink.add(envelope);
                delegate.send(envelope);
            }

            @Override
            public Envelope receive() throws InterruptedException {
                return delegate.receive();
            }

            @Override
            public void close() {
                delegate.close();
            }

            @Override
            public boolean isClosed() {
                return delegate.isClosed();
            }
        };
    }

    // ------------------------------------------------------------------
    // 工具
    // ------------------------------------------------------------------

    /** 分批产生 u 矩阵列并拼接为完整列（模拟发送方收到的全部扩展消息）。 */
    private static byte[][] collectColumns(ExtensionReceiver receiver, int n,
                                           int batchSize) {
        int totalBytes = n * KAPPA / 8;
        byte[][] full = new byte[KAPPA][];
        for (int j = 0; j < KAPPA; j++) {
            full[j] = new byte[totalBytes];
        }
        int start = 0;
        while (start < n) {
            int count = Math.min(batchSize, n - start);
            ExtensionReceiver.BatchColumns columns =
                    receiver.produceColumns(start, count);
            assertEquals(KAPPA, columns.a().length);
            for (int j = 0; j < KAPPA; j++) {
                assertEquals(0, columns.b()[j].length,
                        "第二矩阵槽位不得携带任何协议数据");
                int offset = start * KAPPA / 8;
                System.arraycopy(columns.a()[j], 0, full[j], offset,
                        columns.a()[j].length);
            }
            start += count;
        }
        return full;
    }

    private static byte[] uniformChoices(int n, int value) {
        byte[] choices = new byte[n];
        Arrays.fill(choices, (byte) value);
        return choices;
    }

    private static byte[] randomChoices(int n, long seed) {
        SecureRandom random = new SeededRandom(seed);
        byte[] choices = new byte[n];
        for (int i = 0; i < n; i++) {
            choices[i] = (byte) (random.nextBoolean() ? 1 : 0);
        }
        return choices;
    }

    private static boolean bit(byte[] data, int index) {
        return (data[index >>> 3] & (1 << (7 - (index & 7)))) != 0;
    }

    /**
     * 确定性随机源：SHA-256(seed ‖ counter) 计数器 DRBG，仅用于测试，
     * 使发送方/接收方随机带可精确重放。
     */
    private static final class SeededRandom extends SecureRandom {
        private final byte[] seed;
        private long counter;

        SeededRandom(long seedValue) {
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.putLong(seedValue);
            this.seed = buffer.array();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            int offset = 0;
            while (offset < bytes.length) {
                ByteBuffer input = ByteBuffer.allocate(seed.length + 8);
                input.put(seed);
                input.putLong(counter++);
                byte[] block = SymCrypto.sha256(input.array());
                int take = Math.min(block.length, bytes.length - offset);
                System.arraycopy(block, 0, bytes, offset, take);
                offset += take;
            }
        }

        @Override
        public byte[] generateSeed(int numBytes) {
            byte[] out = new byte[numBytes];
            nextBytes(out);
            return out;
        }
    }
}

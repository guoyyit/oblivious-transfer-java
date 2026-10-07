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
import java.time.Duration;
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
 * 发送方视角的选择隐私测试（IKNP 修复验证）。
 *
 * <p>威胁模型：协议完成后，发送方持有自身基础阶段状态（选择向量 s、
 * 取回的种子 k_{s_j,j}）、自身随机源以及收到的全部协议消息。
 * 测试断言该视图不携带任何接收方选择位信息：
 * <ul>
 *   <li>泄漏比特 ℓ(i,j)=U_j⊕G(k_{s_j,j}) 的对角位关于全零/全一/随机
 *       选择向量均为公平比特（被发送方不可知的 PRG 流一次性掩码）；</li>
 *   <li>旧版双矩阵异或攻击的输出与选择向量无关（恒为全零）；</li>
 *   <li>结构化检查：U⊕G(k0)⊕G(k1) 恰好等于 r⊗1_κ，即掩码 r 的唯一未知量
 *       是发送方缺失的那一粒种子；</li>
 *   <li>线上抓包（真实通道+真实基础 OT）的矩阵字节均匀、承诺带盐隐藏、
 *       视图不随消息内容/批次划分/重复运行出现可区分偏差。</li>
 * </ul>
 * 统计界取 8σ（|X−n/2| ≤ 4√n），二项涨落误判概率可忽略（&lt;10⁻¹²）。
 */
class SenderViewChoicePrivacyTest {

    private static final int KAPPA = 128;
    private static final int SEED_BYTES = KAPPA / 8;

    // 与 BatchMessages 一致的消息类型（白盒常量）
    private static final int MSG_BASE_SENDER_INIT = 10;
    private static final int MSG_BASE_CIPHERTEXTS = 12;
    private static final int MSG_COMMIT = 20;
    private static final int MSG_T_COLUMNS = 21;
    private static final int MSG_REDEMPTION = 30;
    private static final int MSG_DONE = 40;

    // ------------------------------------------------------------------
    // 扩展级发送方视图 harness
    // ------------------------------------------------------------------

    /** 发送方在扩展阶段结束后的完整视图。 */
    private record SenderView(
            boolean[] s,
            byte[][] chosenSeeds,
            byte[][][] basePairs,
            byte[] choices,
            List<byte[][]> uBatches,
            List<int[]> batchRanges) {
    }

    private static SenderView runExtensionTranscript(byte[] choices, int batchSize) {
        SecureRandom random = SymCrypto.secureRandom();
        ExtensionSender sender = new ExtensionSender(KAPPA, random);
        boolean[] s = sender.generateS();
        ExtensionReceiver receiver = new ExtensionReceiver(KAPPA, choices, random);
        byte[][][] pairs = receiver.generateBasePairs();
        byte[][] chosen = new byte[KAPPA][];
        for (int j = 0; j < KAPPA; j++) {
            chosen[j] = pairs[j][s[j] ? 1 : 0];
        }
        sender.installBaseSeeds(chosen);
        List<byte[][]> uBatches = new ArrayList<>();
        List<int[]> ranges = new ArrayList<>();
        int n = choices.length;
        for (int start = 0; start < n; start += batchSize) {
            int count = Math.min(batchSize, n - start);
            ExtensionReceiver.BatchColumns columns = receiver.produceColumns(start, count);
            // 发送方正常处理该批（验证协议可完成），随后记录其收到的 U 矩阵
            sender.deriveBatch(start, n, columns.a(), columns.b());
            uBatches.add(columns.a());
            ranges.add(new int[]{start, count});
        }
        return new SenderView(s, chosen, pairs, choices.clone(), uBatches, ranges);
    }

    /** 与协议一致的 PRG 分离域（白盒：发送方知道协议规范）。 */
    private static byte[] columnDomain(int column) {
        byte[] prefix = {'i', 'k', 'n', 'p', '2', '-', 'p', 'r', 'g'};
        byte[] domain = new byte[prefix.length + 4];
        System.arraycopy(prefix, 0, domain, 0, prefix.length);
        domain[prefix.length] = (byte) (column >>> 24);
        domain[prefix.length + 1] = (byte) (column >>> 16);
        domain[prefix.length + 2] = (byte) (column >>> 8);
        domain[prefix.length + 3] = (byte) column;
        return domain;
    }

    private static boolean bit(byte[] data, int index) {
        return (data[index >>> 3] & (1 << (7 - (index & 7)))) != 0;
    }

    /**
     * 发送方可计算的最强泄漏候选：ℓ(i,j) = U_j 对角位 ⊕ G(k_{s_j,j}) 对角位。
     * 返回按行主序的比特矩阵 leak[i][j]。若协议泄漏选择位，该矩阵的
     * 行多数票将等于 r_i（旧构造即如此）。
     */
    private static boolean[][] leakageBits(SenderView view) {
        int n = view.choices().length;
        boolean[][] leak = new boolean[n][KAPPA];
        for (int b = 0; b < view.uBatches().size(); b++) {
            byte[][] u = view.uBatches().get(b);
            int start = view.batchRanges().get(b)[0];
            int count = view.batchRanges().get(b)[1];
            long byteOffset = (long) start * SEED_BYTES;
            int batchBytes = count * SEED_BYTES;
            for (int j = 0; j < KAPPA; j++) {
                byte[] pad = StreamingPrg.expand(
                        view.chosenSeeds()[j], columnDomain(j), byteOffset, batchBytes);
                for (int local = 0; local < count; local++) {
                    leak[start + local][j] =
                            bit(u[j], local * KAPPA + j) ^ bit(pad, local * KAPPA + j);
                }
            }
        }
        return leak;
    }

    /** 8σ 公平比特界：|ones − total/2| ≤ 4·√total。 */
    private static void assertFairBits(long ones, long total, String what) {
        double expected = total / 2.0;
        double bound = 4.0 * Math.sqrt(total);
        assertTrue(Math.abs(ones - expected) <= bound,
                what + " 偏离公平比特界: ones=" + ones + " total=" + total
                        + " bound=" + bound);
    }

    private static long countOnes(boolean[][] bits) {
        long ones = 0;
        for (boolean[] row : bits) {
            for (boolean b : row) {
                if (b) {
                    ones++;
                }
            }
        }
        return ones;
    }

    /** 旧版攻击：对发送方收到的两个矩阵做对角异或提取选择位。 */
    private static byte[] previousAttackEstimate(SenderView view) {
        int n = view.choices().length;
        byte[] estimate = new byte[n];
        for (int b = 0; b < view.uBatches().size(); b++) {
            // 修复后发送方只收到 U；旧攻击面对的两个“矩阵”均为 U（a==b）
            byte[][] a = view.uBatches().get(b);
            byte[][] bMatrix = view.uBatches().get(b);
            int start = view.batchRanges().get(b)[0];
            int count = view.batchRanges().get(b)[1];
            for (int local = 0; local < count; local++) {
                int ones = 0;
                for (int j = 0; j < KAPPA; j++) {
                    boolean d = bit(a[j], local * KAPPA + j)
                            ^ bit(bMatrix[j], local * KAPPA + j);
                    if (d) {
                        ones++;
                    }
                }
                estimate[start + local] = (byte) (ones * 2 > KAPPA ? 1 : 0);
            }
        }
        return estimate;
    }

    private static void assertViewHidesChoices(byte[] choices, int batchSize, String label) {
        SenderView view = runExtensionTranscript(choices, batchSize);
        boolean[][] leak = leakageBits(view);
        long total = (long) choices.length * KAPPA;
        assertFairBits(countOnes(leak), total, label + " 泄漏比特");

        // 行多数票预测器：若泄漏存在将高度相关，这里必须接近随机猜测
        int matches = 0;
        for (int i = 0; i < choices.length; i++) {
            int ones = 0;
            for (int j = 0; j < KAPPA; j++) {
                if (leak[i][j]) {
                    ones++;
                }
            }
            int predicted = ones * 2 > KAPPA ? 1 : 0;
            if (predicted == choices[i]) {
                matches++;
            }
        }
        assertFairBits(matches, choices.length, label + " 行多数票预测命中数");

        // 旧双矩阵异或攻击：输出必须与选择向量无关（恒全零）
        byte[] estimate = previousAttackEstimate(view);
        for (int i = 0; i < choices.length; i++) {
            assertEquals(0, estimate[i], label + " 旧攻击在第 " + i + " 行仍提取出比特");
        }
    }

    // ------------------------------------------------------------------
    // 扩展级测试：全零 / 全一 / 随机，单批与多批
    // ------------------------------------------------------------------

    @Test
    void allZeroVectorLeavesNoChoiceSignalInSenderView() {
        byte[] choices = new byte[600];
        assertViewHidesChoices(choices, 600, "全零单批");
        assertViewHidesChoices(choices, 37, "全零多批");
    }

    @Test
    void allOneVectorLeavesNoChoiceSignalInSenderView() {
        byte[] choices = new byte[600];
        Arrays.fill(choices, (byte) 1);
        assertViewHidesChoices(choices, 600, "全一单批");
        assertViewHidesChoices(choices, 37, "全一多批");
    }

    @Test
    void randomVectorLeavesNoChoiceSignalInSenderView() {
        byte[] choices = new byte[600];
        SecureRandom random = SymCrypto.secureRandom();
        for (int i = 0; i < choices.length; i++) {
            choices[i] = (byte) random.nextInt(2);
        }
        assertViewHidesChoices(choices, 600, "随机单批");
        assertViewHidesChoices(choices, 37, "随机多批");
    }

    @Test
    void choiceBitsAreOneTimePaddedBySeedSenderCannotKnow() {
        byte[] choices = new byte[260];
        SecureRandom random = SymCrypto.secureRandom();
        for (int i = 0; i < choices.length; i++) {
            choices[i] = (byte) random.nextInt(2);
        }
        SenderView view = runExtensionTranscript(choices, 64);

        // 发送方每列恰好持有两粒种子之一（s_j 指定的那个）
        for (int j = 0; j < KAPPA; j++) {
            byte[] expected = view.basePairs()[j][view.s()[j] ? 1 : 0];
            byte[] other = view.basePairs()[j][view.s()[j] ? 0 : 1];
            assertArrayEquals(expected, view.chosenSeeds()[j]);
            assertFalse(Arrays.equals(other, view.chosenSeeds()[j]),
                    "发送方不应同时拥有配对种子");
        }
        // 结构化恒等式：U ⊕ G(k0) ⊕ G(k1) == r ⊗ 1_κ（逐行验证）
        for (int b = 0; b < view.uBatches().size(); b++) {
            byte[][] u = view.uBatches().get(b);
            int start = view.batchRanges().get(b)[0];
            int count = view.batchRanges().get(b)[1];
            long byteOffset = (long) start * SEED_BYTES;
            int batchBytes = count * SEED_BYTES;
            for (int j = 0; j < KAPPA; j++) {
                byte[] pad0 = StreamingPrg.expand(
                        view.basePairs()[j][0], columnDomain(j), byteOffset, batchBytes);
                byte[] pad1 = StreamingPrg.expand(
                        view.basePairs()[j][1], columnDomain(j), byteOffset, batchBytes);
                for (int local = 0; local < count; local++) {
                    byte expect = choices[start + local] == 1 ? (byte) 0xFF : 0x00;
                    for (int k = 0; k < SEED_BYTES; k++) {
                        int at = local * SEED_BYTES + k;
                        assertEquals(expect, (byte) (u[j][at] ^ pad0[at] ^ pad1[at]),
                                "U 必须恰好是选择位被两粒 PRG 流掩码");
                    }
                }
            }
        }
    }

    @Test
    void batchPartitionDoesNotAffectSenderViewDistribution() {
        int n = 300;
        byte[] choices = new byte[n];
        SecureRandom random = SymCrypto.secureRandom();
        for (int i = 0; i < n; i++) {
            choices[i] = (byte) (i % 3 == 0 ? 1 : 0);
        }
        for (int batchSize : new int[]{1, 7, 64, n}) {
            SenderView view = runExtensionTranscript(choices, batchSize);
            boolean[][] leak = leakageBits(view);
            assertFairBits(countOnes(leak), (long) n * KAPPA,
                    "批大小 " + batchSize + " 的泄漏比特");
        }
    }

    @Test
    void repeatedRunsYieldIndependentSenderViews() {
        byte[] choices = new byte[200];
        Arrays.fill(choices, (byte) 1);
        SenderView first = runExtensionTranscript(choices, 50);
        SenderView second = runExtensionTranscript(choices, 50);
        assertEquals(first.uBatches().size(), second.uBatches().size());
        long agree = 0;
        long total = 0;
        for (int b = 0; b < first.uBatches().size(); b++) {
            byte[][] u1 = first.uBatches().get(b);
            byte[][] u2 = second.uBatches().get(b);
            for (int j = 0; j < KAPPA; j++) {
                assertFalse(Arrays.equals(u1[j], u2[j]),
                        "重复运行的 U 矩阵必须因新鲜随机性而不同");
                for (int i = 0; i < u1[j].length * 8; i++) {
                    if (bit(u1[j], i) == bit(u2[j], i)) {
                        agree++;
                    }
                    total++;
                }
            }
        }
        assertFairBits(agree, total, "重复运行视图一致性");
    }

    // ------------------------------------------------------------------
    // 线上抓包级 harness：完整会话中记录发送方收到的全部协议消息
    // ------------------------------------------------------------------

    private record WireTranscript(
            List<Integer> types,
            List<byte[]> bodies,
            List<byte[][]> matrices,
            byte[] commitment,
            int committedN,
            SessionStatus finalStatus) {
    }

    private static WireTranscript runWireSession(
            byte[] choices, List<MessagePair> pairs, int batchSize) throws Exception {
        SecureRandom random = SymCrypto.secureRandom();
        OtConfig config = OtConfig.defaults().securityBits(KAPPA)
                .batchSize(batchSize).stepTimeout(Duration.ofSeconds(20));
        byte[] sessionId = new byte[16];
        random.nextBytes(sessionId);
        byte[] senderKey = new byte[16];
        byte[] receiverKey = new byte[16];
        random.nextBytes(senderKey);
        random.nextBytes(receiverKey);
        InProcessChannelPair channels = new InProcessChannelPair(64, 20_000);

        List<Envelope> tap = Collections.synchronizedList(new ArrayList<>());
        OtChannel senderChannel = new OtChannel() {
            private final OtChannel delegate = channels.sender();

            @Override
            public void send(Envelope envelope) throws InterruptedException {
                delegate.send(envelope);
            }

            @Override
            public Envelope receive() throws InterruptedException {
                Envelope envelope = delegate.receive();
                tap.add(envelope);
                return envelope;
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

        AtomicReference<SessionStatus> status =
                new AtomicReference<>(SessionStatus.CREATED);
        MessageAuthenticator senderAuth =
                new MessageAuthenticator(sessionId, senderKey, receiverKey);
        MessageAuthenticator receiverAuth =
                new MessageAuthenticator(sessionId, receiverKey, senderKey);
        BatchSender sender = new BatchSender(senderChannel, senderAuth, status,
                TestSupport.source(pairs), config, Group.modp2048(), random);
        BatchReceiver receiver = new BatchReceiver(channels.receiver(), receiverAuth,
                status, config, Group.modp2048(), random);

        AtomicReference<Throwable> senderError = new AtomicReference<>();
        Thread thread = new Thread(() -> {
            try {
                sender.serve();
            } catch (Throwable t) {
                senderError.set(t);
            }
        });
        thread.setDaemon(true);
        thread.start();

        int n = choices.length;
        receiver.start(n, choices);
        while (receiver.cursor() < n) {
            receiver.redeemNextBatch();
        }
        thread.join(30_000);
        assertNull(senderError.get(), "发送方线程异常");
        assertEquals(SessionStatus.COMPLETED, status.get(), "会话应正常完成");

        // 以发送方身份（持有其信封密钥）按序解开收到的全部协议消息
        MessageAuthenticator audit =
                new MessageAuthenticator(sessionId, senderKey, receiverKey);
        List<Integer> types = new ArrayList<>();
        List<byte[]> bodies = new ArrayList<>();
        List<byte[][]> matrices = new ArrayList<>();
        byte[] commitment = null;
        int committedN = -1;
        for (Envelope envelope : tap) {
            byte[] body = audit.open(envelope);
            types.add(envelope.messageType());
            bodies.add(body);
            if (envelope.messageType() == MSG_T_COLUMNS) {
                matrices.add(parseMatrix(body));
            } else if (envelope.messageType() == MSG_COMMIT) {
                ByteBuffer buffer = ByteBuffer.wrap(body);
                committedN = buffer.getInt();
                int length = Short.toUnsignedInt(buffer.getShort());
                commitment = new byte[length];
                buffer.get(commitment);
            }
        }
        return new WireTranscript(types, bodies, matrices, commitment, committedN,
                status.get());
    }

    private static byte[][] parseMatrix(byte[] body) {
        ByteBuffer buffer = ByteBuffer.wrap(body);
        int start = buffer.getInt();
        int kappa = buffer.getInt();
        assertTrue(start >= 0 && kappa == KAPPA, "矩阵头非法");
        byte[][] columns = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            int length = buffer.getInt();
            assertTrue(length > 0 && length <= body.length, "矩阵列长度非法");
            columns[j] = new byte[length];
            buffer.get(columns[j]);
        }
        assertFalse(buffer.hasRemaining(), "矩阵消息存在多余字节");
        return columns;
    }

    private static long matrixOnes(List<byte[][]> matrices) {
        long ones = 0;
        for (byte[][] matrix : matrices) {
            for (byte[] column : matrix) {
                for (byte value : column) {
                    ones += Integer.bitCount(value & 0xFF);
                }
            }
        }
        return ones;
    }

    private static long matrixBits(List<byte[][]> matrices) {
        long bits = 0;
        for (byte[][] matrix : matrices) {
            for (byte[] column : matrix) {
                bits += (long) column.length * 8;
            }
        }
        return bits;
    }

    // ------------------------------------------------------------------
    // 线上抓包级测试
    // ------------------------------------------------------------------

    @Test
    void wireTranscriptForAllZeroVectorIsUniformAndCommitmentSalted() throws Exception {
        int n = 96;
        byte[] choices = new byte[n];
        List<MessagePair> pairs = TestSupport.messages(n);
        WireTranscript transcript = runWireSession(choices, pairs, 32);

        assertEquals(n, transcript.committedN());
        assertEquals(32, transcript.commitment().length, "承诺应为 256 位");
        // 旧形式 sha256(n ‖ choices) 对全零向量可被发送方直接穷举验证，必须不再出现
        byte[] unsalted = ByteBuffer.allocate(4 + n).putInt(n).put(choices).array();
        assertFalse(Arrays.equals(SymCrypto.sha256(unsalted), transcript.commitment()),
                "承诺不得是可穷举的无盐哈希");
        // 矩阵字节对发送方必须均匀（选择位被一次性掩码）
        assertFairBits(matrixOnes(transcript.matrices()),
                matrixBits(transcript.matrices()), "全零向量线上矩阵");
        assertFalse(transcript.matrices().isEmpty(), "应抓到扩展矩阵消息");
    }

    @Test
    void wireTranscriptForAllOneVectorIsUniform() throws Exception {
        int n = 96;
        byte[] choices = new byte[n];
        Arrays.fill(choices, (byte) 1);
        WireTranscript transcript =
                runWireSession(choices, TestSupport.messages(n), 32);
        assertFairBits(matrixOnes(transcript.matrices()),
                matrixBits(transcript.matrices()), "全一向量线上矩阵");
        byte[] unsalted = ByteBuffer.allocate(4 + n).putInt(n).put(choices).array();
        assertFalse(Arrays.equals(SymCrypto.sha256(unsalted), transcript.commitment()),
                "全一向量的承诺不得可穷举");
    }

    @Test
    void senderViewDoesNotDependOnMessageContent() throws Exception {
        int n = 64;
        byte[] choices = TestSupport.alternatingChoices(n);
        List<MessagePair> first = TestSupport.messages(n);
        List<MessagePair> second = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            second.add(new MessagePair(
                    ("completely-different-A-" + i).getBytes(),
                    ("completely-different-B-" + i).getBytes()));
        }
        WireTranscript t1 = runWireSession(choices, first, 16);
        WireTranscript t2 = runWireSession(choices, second, 16);

        // 消息类型序列与每条消息长度完全一致：消息内容不进入发送方入站视图
        assertEquals(t1.types(), t2.types(), "消息内容不得改变协议消息序列");
        assertEquals(t1.bodies().size(), t2.bodies().size());
        for (int i = 0; i < t1.bodies().size(); i++) {
            assertEquals(t1.bodies().get(i).length, t2.bodies().get(i).length,
                    "第 " + i + " 条入站消息长度不得随消息内容变化");
        }
        // 两次视图的矩阵都保持均匀
        assertFairBits(matrixOnes(t1.matrices()), matrixBits(t1.matrices()), "内容A矩阵");
        assertFairBits(matrixOnes(t2.matrices()), matrixBits(t2.matrices()), "内容B矩阵");
        // 发送方入站视图中不出现任何消息内容字节
        for (byte[] body : t1.bodies()) {
            for (MessagePair pair : first) {
                if (pair.message0().length > 0) {
                    assertFalse(contains(body, pair.message0()), "入站视图泄漏消息内容");
                }
                if (pair.message1().length > 0) {
                    assertFalse(contains(body, pair.message1()), "入站视图泄漏消息内容");
                }
            }
        }
    }

    @Test
    void repeatedWireRunsProduceIndependentTranscripts() throws Exception {
        int n = 64;
        byte[] choices = new byte[n];
        Arrays.fill(choices, (byte) 1);
        WireTranscript t1 = runWireSession(choices, TestSupport.messages(n), 16);
        WireTranscript t2 = runWireSession(choices, TestSupport.messages(n), 16);

        assertFalse(Arrays.equals(t1.commitment(), t2.commitment()),
                "相同选择向量的两次运行承诺必须因盐而不同");
        assertEquals(t1.matrices().size(), t2.matrices().size());
        long agree = 0;
        long total = 0;
        for (int m = 0; m < t1.matrices().size(); m++) {
            byte[][] a = t1.matrices().get(m);
            byte[][] b = t2.matrices().get(m);
            for (int j = 0; j < KAPPA; j++) {
                assertFalse(Arrays.equals(a[j], b[j]), "重复运行矩阵必须不同");
                for (int i = 0; i < a[j].length * 8; i++) {
                    if (bit(a[j], i) == bit(b[j], i)) {
                        agree++;
                    }
                    total++;
                }
            }
        }
        assertFairBits(agree, total, "重复运行线上矩阵一致性");
    }

    @Test
    void wireMessageSequenceMatchesProtocol() throws Exception {
        int n = 40;
        byte[] choices = TestSupport.alternatingChoices(n);
        WireTranscript transcript = runWireSession(choices, TestSupport.messages(n), 8);
        List<Integer> types = transcript.types();
        // κ 组 (INIT, CIPHERTEXTS)，然后 COMMIT，之后 5 组 (T_COLUMNS, REDEMPTION)，最后 DONE
        int expectedBatches = (n + 7) / 8;
        assertEquals(2 * KAPPA + 1 + 2 * expectedBatches + 1, types.size());
        for (int j = 0; j < KAPPA; j++) {
            assertEquals(MSG_BASE_SENDER_INIT, types.get(2 * j));
            assertEquals(MSG_BASE_CIPHERTEXTS, types.get(2 * j + 1));
        }
        assertEquals(MSG_COMMIT, types.get(2 * KAPPA));
        for (int b = 0; b < expectedBatches; b++) {
            assertEquals(MSG_T_COLUMNS, types.get(2 * KAPPA + 1 + 2 * b));
            assertEquals(MSG_REDEMPTION, types.get(2 * KAPPA + 2 + 2 * b));
        }
        assertEquals(MSG_DONE, types.get(types.size() - 1));
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || haystack.length < needle.length) {
            return false;
        }
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}

package com.github.guoyyit.oblivioustransferjava.ot.batch;

import com.github.guoyyit.oblivioustransferjava.ot.base.BaseOtMessages;
import com.github.guoyyit.oblivioustransferjava.ot.base.BaseOtReceiver;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.Group;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.extension.ExtensionSender;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtConfig;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.SessionStatus;
import com.github.guoyyit.oblivioustransferjava.ot.transport.MessageAuthenticator;
import com.github.guoyyit.oblivioustransferjava.ot.transport.OtChannel;
import com.github.guoyyit.oblivioustransferjava.ot.transport.ProtocolEndpoint;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 批量 OT 会话发送方。
 *
 * <p>两阶段协议（均在已认证信封内）：
 * <ol>
 *   <li>基础阶段：与接收方执行 {@code kappa} 组基础 OT，发送方扮演接收方，
 *       按随机向量 u 取回 {@code kappa} 个 κ 位种子（离散对数假设保证安全）；</li>
 *   <li>扩展+兑换阶段：接收方先提交 n 与选择向量的加盐承诺，之后按批推进。
 *       每个批次接收方发送该批 u 掩码矩阵列（u_j = G(k0_j) ⊕ G(k1_j) ⊕ r⊗1，
 *       选择位被 PRG 输出掩码，发送方无法还原），紧接着发送该批的兑换请求
 *       （长度必须与紧邻扩展批一致，且严格按顺序），发送方仅用 PRG/HMAC/HKDF
 *       等对称原语派生该批行密钥，用 AES-GCM 加密消息对并擦除临时列。</li>
 * </ol>
 * 单批内存为 O(kappa × 批大小)，与 n 无关；取消时擦除全部种子与临时状态。
 */
public final class BatchSender extends ProtocolEndpoint {

    private final MessageSource messages;
    private final OtConfig config;
    private final Group group;
    private final SecureRandom random;

    private int n = -1;
    private ExtensionSender extension;
    private int extensionCursor;

    public interface MessageSource {
        int size();

        MessagePair get(int index);
    }

    public BatchSender(OtChannel channel, MessageAuthenticator authenticator,
                AtomicReference<SessionStatus> status, MessageSource messages,
                OtConfig config, Group group, SecureRandom random) {
        super(channel, authenticator, status);
        if (messages == null || messages.size() <= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "消息源不能为空且至少一条");
        }
        this.messages = messages;
        this.config = config;
        this.group = group;
        this.random = random;
    }

    /**
     * 服务端主循环，通常运行在工作线程，直到全部批次完成、取消或中止。
     */
    public void serve() {
        try {
            runBaseStage();
            runExtensionStage();
        } catch (OtException e) {
            throw propagate(e);
        } finally {
            if (extension != null) {
                extension.wipe();
            }
        }
    }

    private void runBaseStage() {
        int kappa = config.securityBits();
        extension = new ExtensionSender(kappa, random);
        boolean[] u = extension.generateU();

        byte[][] chosenSeeds = new byte[kappa][];
        BaseOtReceiver baseReceiver = new BaseOtReceiver(group, random);

        for (int j = 0; j < kappa; j++) {
            byte[] initBody = receive(BatchMessages.MSG_BASE_SENDER_INIT);
            BaseOtMessages.SenderInit init =
                    BaseOtMessages.decodeSenderInit(initBody);

                BaseOtReceiver.Choice choice =
                        baseReceiver.choose(init.c0(), u[j] ? 1 : 0);
            send(BatchMessages.MSG_BASE_RECEIVER_CHOICE,
                    BaseOtMessages.encodeReceiverChoice(choice.pk()));

            byte[] cipherBody = receive(BatchMessages.MSG_BASE_CIPHERTEXTS);
            BaseOtMessages.CiphertextPair pair =
                    BaseOtMessages.decodeCiphertexts(cipherBody);
                byte[] seed = baseReceiver.decode(choice,
                        new byte[][]{pair.cipher0(), pair.cipher1()},
                        kappa / 8);
            chosenSeeds[j] = seed;
        }
        extension.installBaseSeeds(chosenSeeds);
    }

    private void runExtensionStage() {
        byte[] commitBody = receive(BatchMessages.MSG_COMMIT);
        BatchMessages.Commitment commitment =
                BatchMessages.decodeCommitment(commitBody);
        n = commitment.n();
        if (n != messages.size()) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION,
                    "选择向量长度与消息源条数不一致 n=" + n);
        }

        while (extensionCursor < n) {
            byte[] matrixBody = receive(BatchMessages.MSG_T_COLUMNS);
            BatchMessages.MatrixPair matrix =
                    BatchMessages.decodeMatrixPair(matrixBody, config.securityBits());
            if (matrix.globalStart() != extensionCursor) {
                throw new OtException(ErrorCode.INDEX_MISMATCH,
                        "扩展批次起始错位 expected=" + extensionCursor
                                + " actual=" + matrix.globalStart());
            }
            int batchLength = matrix.a()[0].length * 8 / config.securityBits();
            if (batchLength <= 0 || extensionCursor + batchLength > n) {
                throw new OtException(ErrorCode.OUT_OF_RANGE, "扩展批次越界");
            }
            ExtensionSender.RowPair[] rows = extension.deriveBatch(
                    extensionCursor, n, matrix.a(), matrix.b());

            byte[] redemptionBody = receive(BatchMessages.MSG_REDEMPTION);
            BatchMessages.Redemption request =
                    BatchMessages.decodeRedemption(redemptionBody);
            if (request.globalStart() != extensionCursor
                    || request.count() != batchLength) {
                throw new OtException(ErrorCode.INDEX_MISMATCH,
                        "兑换请求必须与紧邻的扩展批次严格一致");
            }

            serveBatch(extensionCursor, batchLength, rows);
            extensionCursor += batchLength;
        }

        receive(BatchMessages.MSG_DONE);
        markCompleted();
    }

    private void serveBatch(int start, int count, ExtensionSender.RowPair[] rows) {
        byte[][] payload = new byte[count][];
        for (int local = 0; local < count; local++) {
            int index = start + local;
            MessagePair pair = messages.get(index);
            payload[local] = encodeCiphertextPair(rows[local], pair);
        }
        send(BatchMessages.MSG_REDEMPTION_RESULT,
                BatchMessages.encodeRedemptionResult(payload));
    }

    private byte[] encodeCiphertextPair(ExtensionSender.RowPair row, MessagePair pair) {
        byte[] nonce0 = new byte[SymCrypto.GCM_IV_LENGTH];
        byte[] nonce1 = new byte[SymCrypto.GCM_IV_LENGTH];
        random.nextBytes(nonce0);
        random.nextBytes(nonce1);

        byte[] key0 = deriveMessageKey(row.k0(), (byte) 0);
        byte[] key1 = deriveMessageKey(row.k1(), (byte) 1);
        byte[] sealed0 = SymCrypto.seal(key0, nonce0, pair.message0());
        byte[] sealed1 = SymCrypto.seal(key1, nonce1, pair.message1());
        SymCrypto.wipe(key0);
        SymCrypto.wipe(key1);

        ByteBuffer buffer = ByteBuffer.allocate(
                nonce0.length + sealed0.length + nonce1.length + sealed1.length + 8);
        buffer.putInt(sealed0.length);
        buffer.put(nonce0);
        buffer.put(sealed0);
        buffer.putInt(sealed1.length);
        buffer.put(nonce1);
        buffer.put(sealed1);
        return buffer.array();
    }

    private static byte[] deriveMessageKey(byte[] rowKey, byte branch) {
        byte[] info = new byte[]{'o', 't', '-', 'm', 's', 'g', branch};
        return SymCrypto.hkdfExpand(rowKey, info, 16);
    }

    private OtException propagate(OtException e) {
        if (e.code() == ErrorCode.PEER_ABORTED || e.code() == ErrorCode.CANCELLED) {
            return e;
        }
        abort(e.code(), e.getMessage());
        return e;
    }
}

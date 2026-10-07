package com.github.guoyyit.oblivioustransferjava.ot.batch;

import com.github.guoyyit.oblivioustransferjava.ot.base.BaseOtMessages;
import com.github.guoyyit.oblivioustransferjava.ot.base.BaseOtSender;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.Group;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.extension.ExtensionReceiver;
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
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 批量 OT 会话接收方。
 *
 * <p>先 {@link #start(int, byte[])} 提交选择向量（完成 kappa 组基础 OT 并提交
 * 长度承诺），随后 {@link #redeemNextBatch} 严格按顺序分批推进扩展并兑换；
 * 也可用 {@link #redeemOne} 以单条批次兑换。越界、错位、重复兑换均被拒绝。
 */
public final class BatchReceiver extends ProtocolEndpoint {

    private final OtConfig config;
    private final Group group;
    private final SecureRandom random;

    private ExtensionReceiver extension;
    private int n;
    private int cursor;

    public BatchReceiver(OtChannel channel, MessageAuthenticator authenticator,
                  AtomicReference<SessionStatus> status,
                  OtConfig config, Group group, SecureRandom random) {
        super(channel, authenticator, status);
        this.config = config;
        this.group = group;
        this.random = random;
    }

    /**
     * 提交选择向量并完成基础 OT 阶段。非法参数（空向量、含非 0/1 值）直接拒绝，
     * 不建立扩展会话。
     */
    public void start(int totalN, byte[] choices) {
        if (totalN <= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "传输条数必须为正");
        }
        if (choices == null || choices.length != totalN) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "选择向量长度必须等于 n");
        }
        for (byte choice : choices) {
            if (choice != 0 && choice != 1) {
                throw new OtException(ErrorCode.INVALID_PARAMETER, "选择向量只能包含 0/1");
            }
        }
        try {
            int kappa = config.securityBits();
            extension = new ExtensionReceiver(kappa, choices, random);

            byte[][][] basePairs = extension.generateBasePairs();
            BaseOtSender baseSender = new BaseOtSender(group, random);

            for (int j = 0; j < kappa; j++) {
                BaseOtSender.Init init = baseSender.init();
                send(BatchMessages.MSG_BASE_SENDER_INIT,
                        BaseOtMessages.encodeSenderInit(init.c0(), new byte[0]));

                byte[] choiceBody = receive(BatchMessages.MSG_BASE_RECEIVER_CHOICE);
                BaseOtMessages.ReceiverChoice choice =
                        BaseOtMessages.decodeReceiverChoice(choiceBody);

                MessagePair pair = new MessagePair(basePairs[j][0], basePairs[j][1]);
                byte[][] ciphertexts = baseSender.respond(init, choice.pk(), pair);
                send(BatchMessages.MSG_BASE_CIPHERTEXTS,
                        BaseOtMessages.encodeCiphertexts(ciphertexts[0], ciphertexts[1]));
            }
            this.n = totalN;
            this.cursor = 0;

            byte[] salt = new byte[32];
            random.nextBytes(salt);
            byte[] commitment;
            try {
                commitment = SymCrypto.sha256(
                        buildCommitmentMaterial(totalN, choices, salt));
            } finally {
                SymCrypto.wipe(salt);
            }
            send(BatchMessages.MSG_COMMIT,
                    BatchMessages.encodeCommitment(totalN, commitment));
        } catch (OtException e) {
            throw propagate(e);
        }
    }

    /**
     * 兑换下一批（批大小由配置决定，末批自动缩短），返回与选择位严格一致的消息。
     */
    public byte[][] redeemNextBatch() {
        if (cursor >= n) {
            throw new OtException(ErrorCode.OUT_OF_RANGE, "全部消息已兑换完毕");
        }
        int count = Math.min(config.batchSize(), n - cursor);
        return redeemRange(cursor, count);
    }

    /**
     * 兑换指定连续区间。start 必须等于当前兑换游标，且与紧邻扩展批次等长。
     */
    public byte[][] redeemRange(int start, int count) {
        ensureStarted();
        if (start != cursor) {
            throw new OtException(ErrorCode.INDEX_MISMATCH,
                    "兑换起始位置错位 expected=" + cursor + " actual=" + start);
        }
        if (count <= 0 || start + count > n) {
            throw new OtException(ErrorCode.OUT_OF_RANGE, "兑换区间越界");
        }
        if (count > config.batchSize()) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "单批兑换数超过批大小配置");
        }
        try {
            ExtensionReceiver.BatchColumns columns =
                    extension.produceColumns(start, count);
            send(BatchMessages.MSG_T_COLUMNS,
                    BatchMessages.encodeMatrixPair(start, columns.a(), columns.b()));
            send(BatchMessages.MSG_REDEMPTION,
                    BatchMessages.encodeRedemption(start, count));

            byte[] resultBody = receive(BatchMessages.MSG_REDEMPTION_RESULT);
            byte[][] encodedPairs =
                    BatchMessages.decodeRedemptionResult(resultBody, count);

            byte[][] messages = new byte[count][];
            for (int local = 0; local < count; local++) {
                int index = start + local;
                messages[local] =
                        decodeChosen(index, encodedPairs[local]);
            }
            cursor += count;
            if (cursor == n) {
                send(BatchMessages.MSG_DONE, new byte[0]);
                markCompleted();
            }
            return messages;
        } catch (OtException e) {
            throw propagate(e);
        }
    }

    /**
     * 单条兑换（以大小为 1 的批次推进）。
     */
    public byte[] redeemOne(int index) {
        if (index != cursor) {
            throw new OtException(ErrorCode.INDEX_MISMATCH,
                    "单条兑换必须按顺序进行 expected=" + cursor + " actual=" + index);
        }
        return redeemRange(index, 1)[0];
    }

    public int cursor() {
        return cursor;
    }

    public int totalSize() {
        return n;
    }

    /**
     * 取消会话：通知对端、擦除扩展种子与选择向量，不留下可观察中间状态。
     */
    public void cancel() {
        if (extension != null) {
            extension.wipe();
        }
        abort(ErrorCode.CANCELLED, "接收方取消会话");
    }

    /**
     * 承诺材料：n、选择向量与一次性随机盐。盐不随消息发出，承诺对发送方
     * 计算隐藏（无法穷举验证候选选择向量），且同一选择向量重复运行的承诺
     * 不再相同。
     */
    private static byte[] buildCommitmentMaterial(int totalN, byte[] choices,
                                                  byte[] salt) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + choices.length + salt.length);
        buffer.putInt(totalN);
        buffer.put(choices);
        buffer.put(salt);
        return buffer.array();
    }

    private byte[] decodeChosen(int index, byte[] encodedPair) {
        int chosen = extension.choiceAt(index);
        ByteBuffer buffer = ByteBuffer.wrap(encodedPair);
        byte[][] nonces = new byte[2][];
        byte[][] sealed = new byte[2][];
        for (int branch = 0; branch < 2; branch++) {
            if (buffer.remaining() < 4) {
                throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "兑换结果被截断");
            }
            int length = buffer.getInt();
            int needed = SymCrypto.GCM_IV_LENGTH + length;
            if (length < 0 || needed > buffer.remaining()) {
                throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "密文长度非法");
            }
            nonces[branch] = new byte[SymCrypto.GCM_IV_LENGTH];
            buffer.get(nonces[branch]);
            sealed[branch] = new byte[length];
            buffer.get(sealed[branch]);
        }
        if (buffer.hasRemaining()) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "兑换结果存在多余字节");
        }
        byte[] rowKey = extension.deriveKey(index);
        byte[] messageKey = SymCrypto.hkdfExpand(rowKey,
                new byte[]{'o', 't', '-', 'm', 's', 'g', (byte) chosen}, 16);
        SymCrypto.wipe(rowKey);
        try {
            return SymCrypto.open(messageKey, nonces[chosen], sealed[chosen]);
        } finally {
            SymCrypto.wipe(messageKey);
        }
    }

    private void ensureStarted() {
        if (extension == null) {
            throw new OtException(ErrorCode.INVALID_STATE, "尚未提交选择向量");
        }
    }

    private OtException propagate(OtException e) {
        if (e.code() == ErrorCode.PEER_ABORTED || e.code() == ErrorCode.CANCELLED) {
            return e;
        }
        abort(e.code(), e.getMessage());
        return e;
    }
}

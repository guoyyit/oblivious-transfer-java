package com.github.guoyyit.oblivioustransferjava.ot.base;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.Group;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.SessionStatus;
import com.github.guoyyit.oblivioustransferjava.ot.transport.InProcessChannelPair;
import com.github.guoyyit.oblivioustransferjava.ot.transport.MessageAuthenticator;
import com.github.guoyyit.oblivioustransferjava.ot.transport.OtChannel;
import com.github.guoyyit.oblivioustransferjava.ot.transport.ProtocolEndpoint;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 单次 1-out-of-2 基础 OT 会话（进程内，含会话标识与完整性校验）。
 *
 * <p>通过 {@link #create(byte[], Duration)} 创建一对端点；两端共享同一会话标识与
 * 相反方向的信封密钥。非法参数（选择位、消息对、会话标识）在建立前直接拒绝。
 */
public final class BaseOtSession {

    static final int MSG_SENDER_INIT = 1;
    static final int MSG_RECEIVER_CHOICE = 2;
    static final int MSG_CIPHERTEXTS = 3;

    private BaseOtSession() {
    }

    /**
     * 建立一对基础 OT 会话端点。
     *
     * @param sessionId 全局唯一会话标识（由会话注册表签发，不可重用）
     * @param timeout   单步等待超时
     */
    public static Pair create(byte[] sessionId, Duration timeout) {
        if (sessionId == null || sessionId.length == 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "会话标识不能为空");
        }
        long timeoutMillis = timeout == null ? 30_000L : timeout.toMillis();
        InProcessChannelPair channels =
        new InProcessChannelPair(8, timeoutMillis);

        SecureRandom random = SymCrypto.secureRandom();
        Group group = Group.modp2048();

        byte[] senderEncKey = new byte[16];
        byte[] receiverEncKey = new byte[16];
        random.nextBytes(senderEncKey);
        random.nextBytes(receiverEncKey);

        AtomicReference<SessionStatus> status =
                new AtomicReference<>(SessionStatus.ACTIVE);

        MessageAuthenticator senderAuth =
                new MessageAuthenticator(sessionId, senderEncKey, receiverEncKey);
        MessageAuthenticator receiverAuth =
                new MessageAuthenticator(sessionId, receiverEncKey, senderEncKey);

        Sender sender = new Sender(channels.sender(), senderAuth, status, group, random);
        Receiver receiver =
                new Receiver(channels.receiver(), receiverAuth, status, group, random);
        return new Pair(sender, receiver);
    }

    public record Pair(Sender sender, Receiver receiver) {
    }

    public static final class Sender extends ProtocolEndpoint {

        private final Group group;
        private final SecureRandom random;

        Sender(OtChannel channel, MessageAuthenticator authenticator,
               AtomicReference<SessionStatus> status, Group group, SecureRandom random) {
            super(channel, authenticator, status);
            this.group = group;
            this.random = random;
        }

        /**
         * 运行完整基础 OT：发送 C0，接收选择公钥，返回两条密文。
         * 任一步骤校验失败都会中止会话并抛出可区分错误。
         */
        public void run(MessagePair messages) {
            if (messages == null) {
                throw new OtException(ErrorCode.INVALID_PARAMETER, "消息对不能为空");
            }
            try {
                BaseOtSender sender = new BaseOtSender(group, random);
                BaseOtSender.Init init = sender.init();
                send(MSG_SENDER_INIT,
                        BaseOtMessages.encodeSenderInit(init.c0(), new byte[0]));

                byte[] choiceBody = receive(MSG_RECEIVER_CHOICE);
                BaseOtMessages.ReceiverChoice choice =
                        BaseOtMessages.decodeReceiverChoice(choiceBody);

                byte[][] ciphertexts = sender.respond(init, choice.pk(), messages);
                send(MSG_CIPHERTEXTS, BaseOtMessages.encodeCiphertexts(
                        ciphertexts[0], ciphertexts[1]));
                markCompleted();
            } catch (OtException e) {
                if (e.code() == ErrorCode.PEER_ABORTED) {
                    throw e;
                }
                abort(e.code(), e.getMessage());
                throw e;
            }
        }
    }

    public static final class Receiver extends ProtocolEndpoint {

        private final Group group;
        private final SecureRandom random;

        Receiver(OtChannel channel, MessageAuthenticator authenticator,
                 AtomicReference<SessionStatus> status, Group group, SecureRandom random) {
            super(channel, authenticator, status);
            this.group = group;
            this.random = random;
        }

        /**
         * 运行完整基础 OT 并取回选择位指定的消息。
         *
         * @param choiceBit             必须为 0 或 1，否则会话不建立
         * @param expectedMessageLength 期望消息长度；-1 表示不校验（长度不必一致）
         */
        public byte[] run(int choiceBit, int expectedMessageLength) {
            if (choiceBit != 0 && choiceBit != 1) {
                throw new OtException(ErrorCode.INVALID_PARAMETER, "选择位必须为 0 或 1");
            }
            try {
                byte[] initBody = receive(MSG_SENDER_INIT);
                BaseOtMessages.SenderInit init =
                        BaseOtMessages.decodeSenderInit(initBody);

                BaseOtReceiver receiver = new BaseOtReceiver(group, random);
                BaseOtReceiver.Choice choice =
                        receiver.choose(init.c0(), choiceBit);
                send(MSG_RECEIVER_CHOICE,
                        BaseOtMessages.encodeReceiverChoice(choice.pk()));

                byte[] cipherBody = receive(MSG_CIPHERTEXTS);
                BaseOtMessages.CiphertextPair pair =
                        BaseOtMessages.decodeCiphertexts(cipherBody);
                byte[] message = receiver.decode(choice,
                        new byte[][]{pair.cipher0(), pair.cipher1()},
                        expectedMessageLength);
                markCompleted();
                return message;
            } catch (OtException e) {
                if (e.code() == ErrorCode.PEER_ABORTED) {
                    throw e;
                }
                abort(e.code(), e.getMessage());
                throw e;
            }
        }
    }
}

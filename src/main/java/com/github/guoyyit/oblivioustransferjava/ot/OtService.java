package com.github.guoyyit.oblivioustransferjava.ot;

import com.github.guoyyit.oblivioustransferjava.ot.base.BaseOtSession;
import com.github.guoyyit.oblivioustransferjava.ot.batch.BatchReceiver;
import com.github.guoyyit.oblivioustransferjava.ot.batch.BatchSender;
import com.github.guoyyit.oblivioustransferjava.ot.batch.SessionRegistry;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.Group;
import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtConfig;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.SessionStatus;
import com.github.guoyyit.oblivioustransferjava.ot.transport.InProcessChannelPair;
import com.github.guoyyit.oblivioustransferjava.ot.transport.MessageAuthenticator;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 本地运行的不经意传输服务入口。
 *
 * <p>协议双方在单个进程内通过有界阻塞队列交互，不依赖外部网络或第三方服务。
 * 每个会话拥有独立通道、独立信封密钥与独立状态；共享线程池、SecureRandom 与
 * 会话注册表均为线程安全。某个会话线程抛出的异常只结束该会话，不影响其他会话。
 */
public final class OtService {

    private static final int ENC_KEY_LENGTH = 16;

    private final OtConfig config;
    private final SessionRegistry registry;
    private final ExecutorService senderExecutor;
    private final SecureRandom random;
    private final Group group;
    private final AtomicInteger sessionCounter = new AtomicInteger();

    public OtService() {
        this(OtConfig.defaults());
    }

    public OtService(OtConfig config) {
        if (config == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "配置不能为空");
        }
        config.validate();
        this.config = config;
        this.registry = new SessionRegistry();
        this.random = SymCrypto.secureRandom();
        this.group = Group.modp2048();
        this.senderExecutor = Executors.newCachedThreadPool(new SenderThreadFactory());
    }

    /**
     * 创建一个批量 OT 会话。非法参数（空消息源、非法选择向量）在此直接拒绝，
     * 不会分配会话标识或启动协议。
     *
     * @return 会话句柄；发送方已在独立线程开始运行基础阶段，
     *         接收方随后调用 start/redeem* 推进
     */
    public BatchSession createBatchSession(BatchSender.MessageSource messages, byte[] choices) {
        validateBatchArguments(messages, choices);

        byte[] sessionId = registry.newSessionId();
        long timeoutMillis = config.stepTimeout().toMillis();
        InProcessChannelPair channels =
                new InProcessChannelPair(config.channelCapacity(), timeoutMillis);

        byte[] senderEncKey = new byte[ENC_KEY_LENGTH];
        byte[] receiverEncKey = new byte[ENC_KEY_LENGTH];
        random.nextBytes(senderEncKey);
        random.nextBytes(receiverEncKey);

        AtomicReference<SessionStatus> status =
                new AtomicReference<>(SessionStatus.CREATED);

        MessageAuthenticator senderAuth =
                new MessageAuthenticator(sessionId, senderEncKey, receiverEncKey);
        MessageAuthenticator receiverAuth =
                new MessageAuthenticator(sessionId, receiverEncKey, senderEncKey);

        BatchSender sender = new BatchSender(channels.sender(), senderAuth, status,
                messages, config, group, random);
        BatchReceiver receiver = new BatchReceiver(channels.receiver(), receiverAuth,
                status, config, group, random);

        registry.register(sessionId, new SessionHandle(sender, receiver, status));
        int sessionIndex = sessionCounter.incrementAndGet();
        Future<?> future = senderExecutor.submit(() ->
                runSession(sessionId, status, sender, sessionIndex));
        attachFuture(sessionId, future);

        return new BatchSession(sessionId, sender, receiver);
    }

    /**
     * 创建一对基础 1-out-of-2 OT 端点（可直接并发运行）。
     */
    public BaseTransfer createBaseTransfer() {
        byte[] sessionId = registry.newSessionId();
        BaseOtSession.Pair pair =
                BaseOtSession.create(sessionId, Duration.ofMillis(config.stepTimeout().toMillis()));
        registry.register(sessionId, pair);
        return new BaseTransfer(sessionId, pair.sender(), pair.receiver());
    }

    public SessionStatus sessionStatus(byte[] sessionId) {
        return registry.status(sessionId);
    }

    public int activeSessionCount() {
        return registry.activeCount();
    }

    /**
     * 关闭服务：停止接收新任务并中断所有发送方工作线程。
     */
    public void shutdown() {
        senderExecutor.shutdownNow();
    }

    private void validateBatchArguments(BatchSender.MessageSource messages, byte[] choices) {
        if (messages == null || messages.size() <= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "消息源不能为空且至少一条");
        }
        if (choices == null || choices.length != messages.size()) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "选择向量长度必须与消息条数一致");
        }
        for (byte choice : choices) {
            if (choice != 0 && choice != 1) {
                throw new OtException(ErrorCode.INVALID_PARAMETER, "选择向量只能包含 0/1");
            }
        }
    }

    private void runSession(byte[] sessionId, AtomicReference<SessionStatus> status,
                            BatchSender sender, int sessionIndex) {
        String oldName = Thread.currentThread().getName();
        Thread.currentThread().setName("ot-sender-" + sessionIndex);
        try {
            sender.serve();
        } catch (OtException e) {
            SessionStatus next = switch (e.code()) {
                case CANCELLED -> SessionStatus.CANCELLED;
                case PEER_ABORTED, SESSION_ABORTED -> SessionStatus.ABORTED;
                default -> SessionStatus.FAILED;
            };
            status.compareAndSet(SessionStatus.ACTIVE, next);
            registry.updateStatus(sessionId, status.get());
        } catch (RuntimeException e) {
            status.set(SessionStatus.FAILED);
            registry.updateStatus(sessionId, SessionStatus.FAILED);
        } finally {
            if (status.get() == SessionStatus.COMPLETED) {
                registry.updateStatus(sessionId, SessionStatus.COMPLETED);
            }
            Thread.currentThread().setName(oldName);
        }
    }

    private void attachFuture(byte[] sessionId, Future<?> future) {
        SessionHandle handle = (SessionHandle) registry.lookup(sessionId);
        handle.future = future;
    }

    private static final class SenderThreadFactory implements ThreadFactory {
        private final AtomicInteger counter = new AtomicInteger();

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "ot-sender-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }

    private static final class SessionHandle {
        private final BatchSender sender;
        private final BatchReceiver receiver;
        private final AtomicReference<SessionStatus> status;
        private volatile Future<?> future;

        private SessionHandle(BatchSender sender, BatchReceiver receiver,
                              AtomicReference<SessionStatus> status) {
            this.sender = sender;
            this.receiver = receiver;
            this.status = status;
        }
    }

    public record BatchSession(byte[] sessionId, BatchSender sender, BatchReceiver receiver) {
    }

    public record BaseTransfer(byte[] sessionId,
                               BaseOtSession.Sender sender,
                               BaseOtSession.Receiver receiver) {
    }
}

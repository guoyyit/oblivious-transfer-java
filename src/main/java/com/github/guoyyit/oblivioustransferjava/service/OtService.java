package com.github.guoyyit.oblivioustransferjava.service;

import com.github.guoyyit.oblivioustransferjava.config.OtProperties;
import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.protocol.ProtocolChannel;
import com.github.guoyyit.oblivioustransferjava.session.SessionId;
import com.github.guoyyit.oblivioustransferjava.session.SessionRecord;
import com.github.guoyyit.oblivioustransferjava.session.SessionRegistry;
import com.github.guoyyit.oblivioustransferjava.transport.LocalTransport;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * Local, single-process OT service: creates isolated session pairs and
 * orchestrates the two parties on dedicated threads. All interaction happens
 * over authenticated in-memory channels; there is no network or third party.
 */
public final class OtService {

    private final OtProperties properties;
    private final SessionRegistry registry;

    public OtService() {
        this(OtProperties.defaults(), new SessionRegistry());
    }

    public OtService(OtProperties properties, SessionRegistry registry) {
        this.properties = properties;
        this.registry = registry;
    }

    public record BaseSession(SenderSession sender, ReceiverSession receiver) {
    }

    public record ExtensionSession(SenderSession sender,
                                   ReceiverSession receiver,
                                   SessionId sessionId,
                                   int pairCount,
                                   int batchSize) {
    }

    public BaseSession createBaseSession(int pairCount) {
        validatePairCount(pairCount);
        SessionRecord record = registry.register(false, pairCount);
        LocalTransport.Pair transports = LocalTransport.create(properties.queueCapacity());
        ProtocolChannel.Pair channels = ProtocolChannel.create(record.id(), transports);
        SenderSession sender = new SenderSession(record, registry, channels.sender(),
                pairCount, pairCount, false);
        ReceiverSession receiver = new ReceiverSession(record, registry, channels.receiver(),
                pairCount, pairCount, false);
        return new BaseSession(sender, receiver);
    }

    public ExtensionSession createExtensionSession(int pairCount, int requestedBatchSize) {
        validatePairCount(pairCount);
        int batchSize = properties.resolveBatchSize(requestedBatchSize);
        SessionRecord record = registry.register(true, pairCount);
        LocalTransport.Pair transports = LocalTransport.create(properties.queueCapacity());
        ProtocolChannel.Pair channels = ProtocolChannel.create(record.id(), transports);
        SenderSession sender = new SenderSession(record, registry, channels.sender(),
                pairCount, batchSize, true);
        ReceiverSession receiver = new ReceiverSession(record, registry, channels.receiver(),
                pairCount, batchSize, true);
        return new ExtensionSession(sender, receiver, record.id(), pairCount, batchSize);
    }

    /** Convenience: runs messagePairs.size() base OTs and returns chosen messages. */
    public byte[][] executeBase(List<byte[][]> messagePairs, boolean[] choices) {
        if (messagePairs == null || choices == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "null input");
        }
        if (choices.length != messagePairs.size()) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "choices length must equal message pair count");
        }
        BaseSession session = createBaseSession(messagePairs.size());
        return runPair(() -> session.sender().runBase(messagePairs),
                () -> session.receiver().runBaseBulk(choices));
    }

    /**
     * Runs the sender of an extension session while the caller drives the
     * receiver (submitChoices/redeem...). Returns a future completed when the
     * sender has answered every redemption.
     */
    public static Future<?> startExtensionSender(ExtensionSession session,
                                                 SenderSession.MessageProvider provider) {
        Runnable task = () -> session.sender().runExtension(provider);
        return SESSION_POOL.submit(task);
    }

    /**
     * Convenience: runs a full extension OT, returning all chosen messages in
     * order. The caller supplies message pairs by global index.
     */
    public byte[][] executeExtension(Function<Integer, byte[][]> messagePairs,
                                     boolean[] choices,
                                     int batchSize) {
        if (messagePairs == null || choices == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "null input");
        }
        ExtensionSession session = createExtensionSession(choices.length, batchSize);
        return runPair(() -> session.sender().runExtension(messagePairs::apply), () -> {
            session.receiver().submitChoices(choices);
            byte[][] results = new byte[choices.length][];
            int offset = 0;
            while (offset < choices.length) {
                int batchIndex = offset / session.batchSize();
                int end = Math.min((batchIndex + 1) * session.batchSize(), choices.length);
                byte[][] part = session.receiver().redeemRange(offset, end - offset);
                System.arraycopy(part, 0, results, offset, part.length);
                offset = end;
            }
            return results;
        });
    }

    /**
     * Drives one sender and one receiver action on two worker threads and
     * returns the receiver result. A failure on either side aborts both.
     */
    public static <T> T runPair(ThrowingRunnable senderAction,
                                ThrowingSupplier<T> receiverAction) {
        ExecutorService executor = Executors.newFixedThreadPool(2, namedFactory());
        try {
            Callable<Void> senderCall = () -> {
                senderAction.run();
                return null;
            };
            Future<?> sf = executor.submit(senderCall);
            Callable<T> receiverCall = receiverAction::get;
            Future<T> receiverFuture = executor.submit(receiverCall);
            try {
                T result = receiverFuture.get();
                sf.get();
                return result;
            } catch (Exception failure) {
                throw rewrap(failure);
            }
        } finally {
            executor.shutdownNow();
        }
    }

    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Exception;
    }

    @FunctionalInterface
    public interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    public SessionRegistry registry() {
        return registry;
    }

    public OtProperties properties() {
        return properties;
    }

    private static void validatePairCount(int pairCount) {
        if (pairCount <= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "pair count must be positive");
        }
    }

    private static OtException rewrap(Exception failure) {
        Throwable cause = failure.getCause() != null ? failure.getCause() : failure;
        if (cause instanceof OtException ot) {
            return ot;
        }
        return new OtException(ErrorCode.INTERNAL_ERROR, "OT execution failed", cause);
    }

    private static final ExecutorService SESSION_POOL =
            Executors.newCachedThreadPool(namedFactory());

    private static ThreadFactory namedFactory() {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, "ot-session-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}

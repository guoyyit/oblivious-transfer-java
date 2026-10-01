package com.github.guoyyit.oblivioustransferjava.ot.transport;

import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.Envelope;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 一对互相连接的进程内通道（发送方视图与接收方视图）。
 */
public final class InProcessChannelPair {

    private final OtChannel senderView;
    private final OtChannel receiverView;

    public InProcessChannelPair(int capacity, long pollTimeoutMillis) {
        if (capacity <= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "通道容量必须为正");
        }
        LinkedBlockingQueue<Object> senderToReceiver = new LinkedBlockingQueue<>(capacity);
        LinkedBlockingQueue<Object> receiverToSender = new LinkedBlockingQueue<>(capacity);
        AtomicBoolean senderClosed = new AtomicBoolean(false);
        AtomicBoolean receiverClosed = new AtomicBoolean(false);
        this.senderView = new QueueChannel(receiverToSender, senderToReceiver,
                senderClosed, receiverClosed, pollTimeoutMillis);
        this.receiverView = new QueueChannel(senderToReceiver, receiverToSender,
                receiverClosed, senderClosed, pollTimeoutMillis);
    }

    public OtChannel sender() {
        return senderView;
    }

    public OtChannel receiver() {
        return receiverView;
    }

    private static final Object POISON = new Object();

    private static final class QueueChannel implements OtChannel {

        private final LinkedBlockingQueue<Object> inbound;
        private final LinkedBlockingQueue<Object> outbound;
        private final AtomicBoolean selfClosed;
        private final AtomicBoolean peerClosed;
        private final long pollTimeoutMillis;

        private QueueChannel(LinkedBlockingQueue<Object> inbound,
                             LinkedBlockingQueue<Object> outbound,
                             AtomicBoolean selfClosed,
                             AtomicBoolean peerClosed,
                             long pollTimeoutMillis) {
            this.inbound = inbound;
            this.outbound = outbound;
            this.selfClosed = selfClosed;
            this.peerClosed = peerClosed;
            this.pollTimeoutMillis = pollTimeoutMillis;
        }

        @Override
        public void send(Envelope envelope) throws InterruptedException {
            if (selfClosed.get()) {
                throw new OtException(ErrorCode.SESSION_CLOSED, "本端已关闭");
            }
            long remainingMillis = pollTimeoutMillis;
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(pollTimeoutMillis);
            while (true) {
                if (outbound.offer(envelope, remainingMillis, TimeUnit.MILLISECONDS)) {
                    return;
                }
                if (peerClosed.get()) {
                    throw new OtException(ErrorCode.PEER_ABORTED, "对端已中止");
                }
                remainingMillis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
                if (remainingMillis <= 0) {
                    throw new OtException(ErrorCode.TIMEOUT, "发送等待超时");
                }
            }
        }

        @Override
        public Envelope receive() throws InterruptedException {
            long remainingMillis = pollTimeoutMillis;
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(pollTimeoutMillis);
            while (true) {
                Object item = inbound.poll(remainingMillis, TimeUnit.MILLISECONDS);
                if (item instanceof Envelope envelope) {
                    return envelope;
                }
                if (item == POISON) {
                    throw new OtException(ErrorCode.PEER_ABORTED, "对端已中止会话");
                }
                if (selfClosed.get()) {
                    throw new OtException(ErrorCode.SESSION_CLOSED, "本端已关闭");
                }
                remainingMillis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
                if (remainingMillis <= 0) {
                    throw new OtException(ErrorCode.TIMEOUT, "接收等待超时");
                }
            }
        }

        @Override
        public void close() {
            if (selfClosed.compareAndSet(false, true)) {
                outbound.offer(POISON);
            }
        }

        @Override
        public boolean isClosed() {
            return selfClosed.get() || peerClosed.get();
        }
    }
}

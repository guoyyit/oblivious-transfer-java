package com.github.guoyyit.oblivioustransferjava.transport;

import com.github.guoyyit.oblivioustransferjava.protocol.Envelope;
import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Pair of in-memory bounded transports connecting two parties of one session.
 *
 * <p>The pair exposes two independent directed queues: {@code senderSide} is
 * the sender-to-receiver queue and {@code receiverSide} is the
 * receiver-to-sender queue. {@link ProtocolChannel} passes each peer's
 * outgoing and incoming queue explicitly, so both directions stay independent
 * and a failure in one direction never corrupts the other.
 */
public final class LocalTransport {

    private static final long POLL_MILLIS = 200;

    private LocalTransport() {
    }

    public static Pair create(int queueCapacity) {
        return new Pair(new QueueTransport(queueCapacity),
                new QueueTransport(queueCapacity));
    }

    /** Two directed queues: sender->receiver and receiver->sender. */
    public record Pair(EnvelopeTransport senderSide, EnvelopeTransport receiverSide) {
    }

    private static final class QueueTransport implements EnvelopeTransport {

        private final LinkedBlockingQueue<Envelope> queue;
        private volatile boolean closed;

        private QueueTransport(int capacity) {
            this.queue = new LinkedBlockingQueue<>(capacity);
        }

        @Override
        public void send(Envelope envelope) {
            if (closed) {
                throw new OtException(ErrorCode.SESSION_ABORTED, "channel closed");
            }
            try {
                while (!closed) {
                    if (queue.offer(envelope, POLL_MILLIS, TimeUnit.MILLISECONDS)) {
                        return;
                    }
                }
                throw new OtException(ErrorCode.SESSION_ABORTED, "channel closed while sending");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new OtException(ErrorCode.CANCELLED, "send interrupted", e);
            }
        }

        @Override
        public Envelope receive() {
            while (!closed || !queue.isEmpty()) {
                try {
                    Envelope envelope = queue.poll(POLL_MILLIS, TimeUnit.MILLISECONDS);
                    if (envelope != null) {
                        return envelope;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new OtException(ErrorCode.CANCELLED, "receive interrupted", e);
                }
            }
            throw new OtException(ErrorCode.SESSION_ABORTED, "peer closed the channel");
        }

        @Override
        public void close() {
            closed = true;
        }
    }
}

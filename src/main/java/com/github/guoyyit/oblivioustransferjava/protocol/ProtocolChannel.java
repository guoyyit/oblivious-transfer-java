package com.github.guoyyit.oblivioustransferjava.protocol;

import com.github.guoyyit.oblivioustransferjava.crypto.CryptoRandom;
import com.github.guoyyit.oblivioustransferjava.crypto.Kdf;
import com.github.guoyyit.oblivioustransferjava.crypto.MacUtil;
import com.github.guoyyit.oblivioustransferjava.session.SessionId;
import com.github.guoyyit.oblivioustransferjava.transport.EnvelopeTransport;
import com.github.guoyyit.oblivioustransferjava.transport.LocalTransport;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Authenticated, ordered in-process channel for one party of one session.
 *
 * <p>Every envelope binds the session id, a per-direction strictly increasing
 * sequence number, the message type and payload under a direction-specific
 * HMAC-SHA256 key. Direction-specific keys defeat reflection, and the sequence
 * check rejects replays and reordering.
 */
public final class ProtocolChannel {

    private final SessionId sessionId;
    private final EnvelopeTransport outgoing;
    private final EnvelopeTransport incoming;
    private final byte[] macSend;
    private final byte[] macReceive;
    private final String role;
    private final AtomicLong sendSequence = new AtomicLong(0);
    private final AtomicLong receiveSequence = new AtomicLong(0);
    private volatile boolean closed;

    private ProtocolChannel(SessionId sessionId,
                            EnvelopeTransport outgoing,
                            EnvelopeTransport incoming,
                            byte[] macSend,
                            byte[] macReceive,
                            String role) {
        this.sessionId = sessionId;
        this.outgoing = outgoing;
        this.incoming = incoming;
        this.macSend = macSend;
        this.macReceive = macReceive;
        this.role = role;
    }

    /** Creates the two peer channels over a local transport pair. */
    public static Pair create(SessionId sessionId, LocalTransport.Pair transports) {
        byte[] master = CryptoRandom.randomBytes(Kdf.KEY_LEN);
        byte[] kSenderToReceiver = Kdf.hkdf(master,
                "mac/sender->receiver/v1".getBytes(StandardCharsets.UTF_8), MacUtil.TAG_LEN);
        byte[] kReceiverToSender = Kdf.hkdf(master,
                "mac/receiver->sender/v1".getBytes(StandardCharsets.UTF_8), MacUtil.TAG_LEN);
        ProtocolChannel sender = new ProtocolChannel(sessionId,
                transports.senderSide(), transports.receiverSide(),
                kSenderToReceiver, kReceiverToSender, "sender");
        ProtocolChannel receiver = new ProtocolChannel(sessionId,
                transports.receiverSide(), transports.senderSide(),
                kReceiverToSender, kSenderToReceiver, "receiver");
        return new Pair(sender, receiver);
    }

    public record Pair(ProtocolChannel sender, ProtocolChannel receiver) {
    }

    public SessionId sessionId() {
        return sessionId;
    }

    public void send(MessageType type, byte[] payload) {
        if (closed) {
            throw new OtException(ErrorCode.SESSION_ABORTED, role + " channel closed");
        }
        long sequence = sendSequence.getAndIncrement();
        byte[] tag = MacUtil.hmacSha256(macSend,
                sessionId.value(), longBytes(sequence), new byte[]{(byte) type.ordinal()}, payload);
        outgoing.send(new Envelope(sessionId, sequence, type, payload, tag));
    }

    /** Receives and fully validates the next envelope. */
    public Envelope receive() {
        Envelope envelope = incoming.receive();
        long expected = receiveSequence.get();
        if (!envelope.sessionId().equals(sessionId)) {
            throw new OtException(ErrorCode.CROSS_SESSION_MESSAGE,
                    role + " rejected envelope bound to another session");
        }
        if (envelope.sequence() < expected) {
            throw new OtException(ErrorCode.REPLAY_DETECTED,
                    role + " rejected replay sequence " + envelope.sequence());
        }
        if (envelope.sequence() > expected) {
            throw new OtException(ErrorCode.OUT_OF_ORDER,
                    role + " rejected out-of-order sequence " + envelope.sequence());
        }
        byte[] expectedTag = MacUtil.hmacSha256(macReceive,
                envelope.sessionId().value(), longBytes(envelope.sequence()),
                new byte[]{(byte) envelope.type().ordinal()}, envelope.payload());
        if (!MacUtil.constantTimeEquals(expectedTag, envelope.tag())) {
            throw new OtException(ErrorCode.MESSAGE_TAMPERED,
                    role + " rejected envelope with invalid integrity tag");
        }
        receiveSequence.incrementAndGet();
        if (envelope.type() == MessageType.ERROR) {
            WireCodec.ErrorPayload error = WireCodec.decodeError(envelope.payload());
            throw new OtException(error.code(), "peer error: " + error.reason());
        }
        if (envelope.type() == MessageType.ABORT) {
            throw new OtException(ErrorCode.SESSION_ABORTED, "peer aborted the session");
        }
        return envelope;
    }

    /** Receives the next envelope, requiring the given message type. */
    public byte[] receive(MessageType expectedType) {
        Envelope envelope = receive();
        if (envelope.type() != expectedType) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION,
                    role + " expected " + expectedType + " but got " + envelope.type());
        }
        return envelope.payload();
    }

    public void sendError(ErrorCode code, String reason) {
        sendUnchecked(MessageType.ERROR, WireCodec.encode(new WireCodec.ErrorPayload(code, reason)));
    }

    public void sendAbort() {
        sendUnchecked(MessageType.ABORT, new byte[0]);
    }

    public void close() {
        closed = true;
        outgoing.close();
        incoming.close();
    }

    private void sendUnchecked(MessageType type, byte[] payload) {
        try {
            long sequence = sendSequence.getAndIncrement();
            byte[] tag = MacUtil.hmacSha256(macSend,
                    sessionId.value(), longBytes(sequence), new byte[]{(byte) type.ordinal()}, payload);
            outgoing.send(new Envelope(sessionId, sequence, type, payload, tag));
        } catch (OtException ignored) {
            // closing notifications are best-effort
        }
    }

    private static byte[] longBytes(long value) {
        return new byte[]{
                (byte) (value >>> 56), (byte) (value >>> 48),
                (byte) (value >>> 40), (byte) (value >>> 32),
                (byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value
        };
    }
}

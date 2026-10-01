package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.protocol.Envelope;
import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.MessageType;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.protocol.ProtocolChannel;
import com.github.guoyyit.oblivioustransferjava.protocol.WireCodec;
import com.github.guoyyit.oblivioustransferjava.session.SessionId;
import com.github.guoyyit.oblivioustransferjava.transport.EnvelopeTransport;
import com.github.guoyyit.oblivioustransferjava.transport.LocalTransport;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Envelope integrity: tampering, truncation, replay and cross-session messages
 * must be rejected with distinguishable error codes.
 */
class OtMessageIntegrityTest {

    /** Records every envelope the sender emits and lets the test decide delivery. */
    private static final class RecordingTransport implements EnvelopeTransport {
        private final EnvelopeTransport downstream;
        final List<Envelope> recorded = new ArrayList<>();
        boolean recordEnabled;

        private RecordingTransport(EnvelopeTransport downstream, boolean recordEnabled) {
            this.downstream = downstream;
            this.recordEnabled = recordEnabled;
        }

        @Override
        public void send(Envelope envelope) {
            if (recordEnabled) {
                recorded.add(envelope);
                return;
            }
            downstream.send(envelope);
        }

        @Override
        public Envelope receive() {
            return downstream.receive();
        }

        @Override
        public void close() {
            downstream.close();
        }
    }

    private record Harness(SessionId id,
                           ProtocolChannel sender,
                           ProtocolChannel receiver,
                           RecordingTransport senderOut,
                           EnvelopeTransport receiverIn) {
        /** Drops every sender envelope so a modified one can be injected. */
        void intercept() {
            senderOut.recordEnabled = true;
        }

        void inject(Envelope envelope) {
            receiverIn.send(envelope);
        }

        Envelope recorded(int index) {
            return senderOut.recorded.get(index);
        }
    }

    private Harness harness() {
        SessionId id = SessionId.random();
        LocalTransport.Pair transports = LocalTransport.create(8);
        // Wrap the sender->receiver queue so sent envelopes can be captured.
        RecordingTransport senderOut = new RecordingTransport(transports.senderSide(), false);
        ProtocolChannel sender = new ProtocolChannelAccess().sender(id, senderOut,
                transports.receiverSide());
        ProtocolChannel receiver = new ProtocolChannelAccess().receiver(id,
                transports.receiverSide(), transports.senderSide());
        return new Harness(id, sender, receiver, senderOut, transports.senderSide());
    }

    @Test
    void validEnvelopeRoundTrips() {
        Harness h = harness();
        h.sender.send(MessageType.INIT, new byte[]{1, 2, 3});
        Envelope envelope = h.receiver.receive();
        assertEquals(MessageType.INIT, envelope.type());
        assertEquals(3, envelope.payload().length);
    }

    @Test
    void tamperedPayloadIsRejected() {
        Harness h = harness();
        h.intercept();
        h.sender.send(MessageType.INIT, new byte[]{1, 2, 3});
        Envelope captured = h.recorded(0);
        byte[] changed = captured.payload().clone();
        changed[0] ^= 1;
        h.inject(new Envelope(captured.sessionId(), captured.sequence(),
                captured.type(), changed, captured.tag()));
        OtException error = assertThrows(OtException.class, h.receiver::receive);
        assertEquals(ErrorCode.MESSAGE_TAMPERED, error.errorCode());
    }

    @Test
    void forgedTagIsRejected() {
        Harness h = harness();
        h.intercept();
        h.sender.send(MessageType.INIT, new byte[]{1});
        Envelope captured = h.recorded(0);
        byte[] tag = captured.tag().clone();
        tag[0] ^= 0xFF;
        h.inject(new Envelope(captured.sessionId(), captured.sequence(),
                captured.type(), captured.payload(), tag));
        OtException error = assertThrows(OtException.class, h.receiver::receive);
        assertEquals(ErrorCode.MESSAGE_TAMPERED, error.errorCode());
    }

    @Test
    void replayedEnvelopeIsRejected() {
        Harness h = harness();
        h.sender.send(MessageType.INIT, new byte[]{7});
        Envelope first = h.receiver.receive();
        assertEquals(MessageType.INIT, first.type());
        // Replay the identical, still-valid envelope after sequence advanced.
        h.inject(first);
        OtException error = assertThrows(OtException.class, h.receiver::receive);
        assertEquals(ErrorCode.REPLAY_DETECTED, error.errorCode());
    }

    @Test
    void outOfOrderEnvelopeIsRejected() {
        Harness h = harness();
        h.intercept();
        h.sender.send(MessageType.INIT, new byte[]{1});
        h.sender.send(MessageType.INIT_ACK, new byte[]{2});
        Envelope second = h.recorded(1);
        h.inject(second);
        OtException error = assertThrows(OtException.class, h.receiver::receive);
        assertEquals(ErrorCode.OUT_OF_ORDER, error.errorCode());
    }

    @Test
    void crossSessionEnvelopeIsRejected() {
        Harness h = harness();
        h.intercept();
        h.sender.send(MessageType.INIT, new byte[]{1});
        Envelope captured = h.recorded(0);
        SessionId foreign = SessionId.random();
        h.inject(new Envelope(foreign, captured.sequence(),
                captured.type(), captured.payload(), captured.tag()));
        OtException error = assertThrows(OtException.class, h.receiver::receive);
        assertEquals(ErrorCode.CROSS_SESSION_MESSAGE, error.errorCode());
    }

    @Test
    void truncatedPayloadIsRejected() {
        assertThrows(OtException.class,
                () -> WireCodec.decodeInit(new byte[]{0, 0, 0}));
        OtException error = assertThrows(OtException.class,
                () -> WireCodec.decodeRedeemRequest(new byte[]{0, 0}));
        assertEquals(ErrorCode.TRUNCATED_MESSAGE, error.errorCode());
    }

    @Test
    void peerErrorCarriesDistinguishableCode() {
        Harness h = harness();
        h.sender.sendError(ErrorCode.RANGE_OUT_OF_BOUNDS, "bad range");
        OtException error = assertThrows(OtException.class, h.receiver::receive);
        assertEquals(ErrorCode.RANGE_OUT_OF_BOUNDS, error.errorCode());
        assertTrue(error.getMessage().contains("bad range"));
    }

    /** Test-only access to package-private direction binding of channels. */
    private static final class ProtocolChannelAccess {
        ProtocolChannel sender(SessionId id, EnvelopeTransport out, EnvelopeTransport in) {
            return ProtocolChannelTestAccess.newSender(id, out, in);
        }

        ProtocolChannel receiver(SessionId id, EnvelopeTransport out, EnvelopeTransport in) {
            return ProtocolChannelTestAccess.newReceiver(id, out, in);
        }
    }
}

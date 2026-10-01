package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.crypto.CryptoRandom;
import com.github.guoyyit.oblivioustransferjava.crypto.Kdf;
import com.github.guoyyit.oblivioustransferjava.crypto.MacUtil;
import com.github.guoyyit.oblivioustransferjava.protocol.ProtocolChannel;
import com.github.guoyyit.oblivioustransferjava.session.SessionId;
import com.github.guoyyit.oblivioustransferjava.transport.EnvelopeTransport;

import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;

/**
 * Builds {@link ProtocolChannel} instances over test-controlled transports and
 * independently derives the same direction MAC keys the production code uses,
 * letting tests inject tampered or replayed envelopes.
 */
final class ProtocolChannelTestAccess {

    private ProtocolChannelTestAccess() {
    }

    static ProtocolChannel newSender(SessionId id,
                                     EnvelopeTransport outgoing,
                                     EnvelopeTransport incoming) {
        byte[] master = master(id);
        byte[] send = Kdf.hkdf(master,
                "mac/sender->receiver/v1".getBytes(StandardCharsets.UTF_8), MacUtil.TAG_LEN);
        byte[] receive = Kdf.hkdf(master,
                "mac/receiver->sender/v1".getBytes(StandardCharsets.UTF_8), MacUtil.TAG_LEN);
        return construct(id, outgoing, incoming, send, receive, "sender");
    }

    static ProtocolChannel newReceiver(SessionId id,
                                       EnvelopeTransport outgoing,
                                       EnvelopeTransport incoming) {
        byte[] master = master(id);
        byte[] send = Kdf.hkdf(master,
                "mac/receiver->sender/v1".getBytes(StandardCharsets.UTF_8), MacUtil.TAG_LEN);
        byte[] receive = Kdf.hkdf(master,
                "mac/sender->receiver/v1".getBytes(StandardCharsets.UTF_8), MacUtil.TAG_LEN);
        return construct(id, outgoing, incoming, send, receive, "receiver");
    }

    private static byte[] master(SessionId id) {
        // Deterministic per-session master for the test pair.
        return Kdf.hkdf(id.value(), "test-channel".getBytes(StandardCharsets.UTF_8),
                Kdf.KEY_LEN);
    }

    private static ProtocolChannel construct(SessionId id,
                                             EnvelopeTransport outgoing,
                                             EnvelopeTransport incoming,
                                             byte[] macSend,
                                             byte[] macReceive,
                                             String role) {
        try {
            Constructor<ProtocolChannel> c = ProtocolChannel.class.getDeclaredConstructor(
                    SessionId.class, EnvelopeTransport.class, EnvelopeTransport.class,
                    byte[].class, byte[].class, String.class);
            c.setAccessible(true);
            return c.newInstance(id, outgoing, incoming, macSend, macReceive, role);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }
}

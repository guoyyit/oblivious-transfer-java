package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.protocol.Envelope;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.ot.transport.MessageAuthenticator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MessageIntegrityTest {

    private byte[] key(int seed) {
        byte[] key = new byte[16];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (seed + i);
        }
        return key;
    }

    private MessageAuthenticator authenticator(byte[] sessionId, int a, int b) {
        return new MessageAuthenticator(sessionId, key(a), key(b));
    }

    @Test
    void roundTripsPlaintext() {
        byte[] sessionId = {1, 2, 3, 4};
        var sender = authenticator(sessionId, 1, 2);
        var receiver = authenticator(sessionId, 2, 1);
        Envelope envelope = sender.seal(7, "hello".getBytes());
        assertArrayEquals("hello".getBytes(), receiver.open(envelope));
    }

    @Test
    void tamperedCiphertextIsRejected() {
        byte[] sessionId = {1, 2, 3, 4};
        var sender = authenticator(sessionId, 1, 2);
        var receiver = authenticator(sessionId, 2, 1);
        Envelope envelope = sender.seal(7, "hello".getBytes());
        byte[] broken = envelope.sealedBody().clone();
        broken[0] ^= 1;
        Envelope tampered = new Envelope(envelope.sessionId(), envelope.seq(),
                envelope.messageType(), envelope.nonce(), broken);
        OtException error = assertThrows(OtException.class, () -> receiver.open(tampered));
        assertEquals(ErrorCode.MESSAGE_TAMPERED, error.code());
    }

    @Test
    void truncatedCiphertextIsRejected() {
        byte[] sessionId = {1, 2, 3, 4};
        var sender = authenticator(sessionId, 1, 2);
        var receiver = authenticator(sessionId, 2, 1);
        Envelope envelope = sender.seal(7, "hello".getBytes());
        byte[] truncated = new byte[envelope.sealedBody().length - 2];
        System.arraycopy(envelope.sealedBody(), 0, truncated, 0, truncated.length);
        Envelope bad = new Envelope(envelope.sessionId(), envelope.seq(),
                envelope.messageType(), envelope.nonce(), truncated);
        assertEquals(ErrorCode.MESSAGE_TAMPERED,
                assertThrows(OtException.class, () -> receiver.open(bad)).code());
    }

    @Test
    void replayedMessageIsRejected() {
        byte[] sessionId = {1, 2, 3, 4};
        var sender = authenticator(sessionId, 1, 2);
        var receiver = authenticator(sessionId, 2, 1);
        Envelope first = sender.seal(1, "a".getBytes());
        Envelope second = sender.seal(1, "b".getBytes());
        receiver.open(first);
        receiver.open(second);
        assertEquals(ErrorCode.MESSAGE_REPLAY,
                assertThrows(OtException.class, () -> receiver.open(first)).code());
    }

    @Test
    void crossSessionMessageIsRejected() {
        var senderA = authenticator(new byte[]{1}, 1, 2);
        var receiverB = authenticator(new byte[]{2}, 2, 1);
        Envelope envelope = senderA.seal(1, "a".getBytes());
        assertEquals(ErrorCode.CROSS_SESSION_MESSAGE,
                assertThrows(OtException.class, () -> receiverB.open(envelope)).code());
    }

    @Test
    void forgedSessionIdInsideAadIsRejected() {
        byte[] sessionId = {9};
        var sender = authenticator(sessionId, 1, 2);
        var receiver = authenticator(sessionId, 2, 1);
        Envelope envelope = sender.seal(1, "a".getBytes());
        Envelope forged = new Envelope(new byte[]{8}, envelope.seq(),
                envelope.messageType(), envelope.nonce(), envelope.sealedBody());
        assertEquals(ErrorCode.CROSS_SESSION_MESSAGE,
                assertThrows(OtException.class, () -> receiver.open(forged)).code());
    }
}

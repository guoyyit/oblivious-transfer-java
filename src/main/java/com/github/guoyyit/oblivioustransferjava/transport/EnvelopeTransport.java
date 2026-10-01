package com.github.guoyyit.oblivioustransferjava.transport;

import com.github.guoyyit.oblivioustransferjava.protocol.Envelope;

/**
 * One direction of an authenticated in-process channel between two peers.
 */
public interface EnvelopeTransport {

    void send(Envelope envelope);

    /** Blocks until the next envelope is available or the peer aborts. */
    Envelope receive();

    /** Releases any blocked receiver with no message. */
    void close();
}

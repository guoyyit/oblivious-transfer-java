package com.github.guoyyit.oblivioustransferjava.protocol;

import com.github.guoyyit.oblivioustransferjava.session.SessionId;

/**
 * Wire envelope: every protocol message carries a session id, a per-direction
 * strictly increasing sequence number, a type, a payload and an HMAC tag.
 */
public record Envelope(SessionId sessionId,
                       long sequence,
                       MessageType type,
                       byte[] payload,
                       byte[] tag) {
}

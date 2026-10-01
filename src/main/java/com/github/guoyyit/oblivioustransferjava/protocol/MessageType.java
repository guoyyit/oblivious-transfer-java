package com.github.guoyyit.oblivioustransferjava.protocol;

/**
 * Types of protocol messages carried inside an {@link Envelope}.
 */
public enum MessageType {
    INIT,
    INIT_ACK,
    OT_INIT,
    OT_REPLY,
    OT_PAYLOAD,
    EXT_BATCH,
    REDEEM_REQUEST,
    REDEEM_RESPONSE,
    ERROR,
    ABORT
}

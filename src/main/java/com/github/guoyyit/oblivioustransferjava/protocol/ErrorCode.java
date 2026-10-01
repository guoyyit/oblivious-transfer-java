package com.github.guoyyit.oblivioustransferjava.protocol;

/**
 * Distinguishable failure reasons reported by both parties.
 */
public enum ErrorCode {
    UNKNOWN_SESSION,
    CROSS_SESSION_MESSAGE,
    INVALID_PARAMETER,
    MESSAGE_TAMPERED,
    REPLAY_DETECTED,
    OUT_OF_ORDER,
    TRUNCATED_MESSAGE,
    SESSION_ABORTED,
    SESSION_CLOSED,
    PROTOCOL_VIOLATION,
    RANGE_OUT_OF_BOUNDS,
    REDEMPTION_CONFLICT,
    CHOICE_OUT_OF_RANGE,
    CANCELLED,
    INTERNAL_ERROR
}

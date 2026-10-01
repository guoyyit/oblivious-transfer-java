package com.github.guoyyit.oblivioustransferjava.ot.protocol;

/**
 * 会话生命周期状态。
 */
public enum SessionStatus {
    CREATED,
    ACTIVE,
    COMMITTED,
    COMPLETED,
    ABORTED,
    CANCELLED,
    FAILED
}

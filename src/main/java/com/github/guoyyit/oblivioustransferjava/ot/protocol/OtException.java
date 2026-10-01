package com.github.guoyyit.oblivioustransferjava.ot.protocol;

/**
 * 协议执行过程中的可区分错误。
 */
public class OtException extends RuntimeException {

    private final ErrorCode code;

    public OtException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public OtException(ErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ErrorCode code() {
        return code;
    }
}

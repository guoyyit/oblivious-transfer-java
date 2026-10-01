package com.github.guoyyit.oblivioustransferjava.protocol;

/**
 * Failure carrying a distinguishable {@link ErrorCode}.
 */
public class OtException extends RuntimeException {

    private final ErrorCode errorCode;

    public OtException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public OtException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }
}

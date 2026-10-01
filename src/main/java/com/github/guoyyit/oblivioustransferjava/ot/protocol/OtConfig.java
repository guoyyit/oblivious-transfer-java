package com.github.guoyyit.oblivioustransferjava.ot.protocol;

import java.time.Duration;

/**
 * OT 服务配置项。
 */
public final class OtConfig {

    private int securityBits = 128;
    private int batchSize = 1024;
    private int channelCapacity = 256;
    private Duration stepTimeout = Duration.ofSeconds(30);

    public static OtConfig defaults() {
        return new OtConfig();
    }

    public void validate() {
        if (securityBits != 128 && securityBits != 192 && securityBits != 256) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "securityBits 仅支持 128/192/256，实际为 " + securityBits);
        }
        if (batchSize <= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "batchSize 必须为正");
        }
        if (channelCapacity <= 0) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "channelCapacity 必须为正");
        }
        if (stepTimeout == null || stepTimeout.isZero() || stepTimeout.isNegative()) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "stepTimeout 必须为正时长");
        }
    }

    public int securityBits() {
        return securityBits;
    }

    public OtConfig securityBits(int value) {
        this.securityBits = value;
        return this;
    }

    public int batchSize() {
        return batchSize;
    }

    public OtConfig batchSize(int value) {
        this.batchSize = value;
        return this;
    }

    public int channelCapacity() {
        return channelCapacity;
    }

    public OtConfig channelCapacity(int value) {
        this.channelCapacity = value;
        return this;
    }

    public Duration stepTimeout() {
        return stepTimeout;
    }

    public OtConfig stepTimeout(Duration value) {
        this.stepTimeout = value;
        return this;
    }
}

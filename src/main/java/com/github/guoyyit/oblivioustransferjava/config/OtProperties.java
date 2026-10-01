package com.github.guoyyit.oblivioustransferjava.config;

import com.github.guoyyit.oblivioustransferjava.crypto.Iknp;
import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;

/**
 * Configurable limits for OT sessions.
 *
 * @param defaultBatchSize messages processed in one extension batch
 * @param maxBatchSize hard upper bound for a single batch
 * @param queueCapacity maximum in-flight envelopes per direction
 */
public record OtProperties(int defaultBatchSize,
                           int maxBatchSize,
                           int queueCapacity) {

    public static final int MIN_BATCH_SIZE = Iknp.BASE_COUNT;
    private static final int DEFAULT_BATCH_SIZE = 8192;
    private static final int MAX_BATCH_SIZE = 1 << 20;
    private static final int QUEUE_CAPACITY = 8;

    public static OtProperties defaults() {
        return new OtProperties(DEFAULT_BATCH_SIZE, MAX_BATCH_SIZE, QUEUE_CAPACITY);
    }

    public OtProperties {
        if (defaultBatchSize < MIN_BATCH_SIZE || defaultBatchSize > maxBatchSize) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "defaultBatchSize must be in [" + MIN_BATCH_SIZE + ", maxBatchSize]");
        }
        if (maxBatchSize < MIN_BATCH_SIZE) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "maxBatchSize must be >= " + MIN_BATCH_SIZE);
        }
        if (queueCapacity < 2) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "queueCapacity must be >= 2");
        }
    }

    /** Validates a requested batch size and returns a usable one. */
    public int resolveBatchSize(int requested) {
        int size = requested <= 0 ? defaultBatchSize : requested;
        if (size < MIN_BATCH_SIZE || size > maxBatchSize) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "batch size must be in [" + MIN_BATCH_SIZE + ", " + maxBatchSize + "]");
        }
        return size;
    }
}

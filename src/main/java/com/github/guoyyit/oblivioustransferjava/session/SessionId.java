package com.github.guoyyit.oblivioustransferjava.session;

import com.github.guoyyit.oblivioustransferjava.crypto.CryptoRandom;

import java.util.Arrays;

/**
 * 128-bit cryptographically random session identifier. The probability of a
 * collision (2^-64 after 2^32 sessions) is negligible, and reused/tombstoned
 * ids are additionally rejected by the registry.
 */
public final class SessionId {

    public static final int LENGTH = 16;

    private final byte[] value;

    public SessionId(byte[] value) {
        if (value == null || value.length != LENGTH) {
            throw new IllegalArgumentException("session id must be " + LENGTH + " bytes");
        }
        this.value = value.clone();
    }

    public static SessionId random() {
        return new SessionId(CryptoRandom.randomBytes(LENGTH));
    }

    public byte[] value() {
        return value.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SessionId id && Arrays.equals(value, id.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(2 * LENGTH);
        for (byte b : value) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}

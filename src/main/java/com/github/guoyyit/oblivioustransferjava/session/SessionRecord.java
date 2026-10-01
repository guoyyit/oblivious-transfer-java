package com.github.guoyyit.oblivioustransferjava.session;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Metadata/lifecycle state held in the process-wide registry.
 * Holds no protocol secret material.
 *
 * <p>Transitions:
 * {@code PENDING -> ACTIVE -> COMPLETED}; any state may enter {@code ABORTED};
 * ABORTED and COMPLETED are terminal.
 */
public final class SessionRecord {

    private final SessionId id;
    private final boolean extension;
    private final int pairCount;
    private final long createdAtMillis;
    private final AtomicReference<SessionState> state;
    private volatile String abortReason;

    public SessionRecord(SessionId id, boolean extension, int pairCount) {
        this.id = id;
        this.extension = extension;
        this.pairCount = pairCount;
        this.createdAtMillis = System.currentTimeMillis();
        this.state = new AtomicReference<>(SessionState.PENDING);
    }

    public SessionId id() {
        return id;
    }

    public boolean extension() {
        return extension;
    }

    public int pairCount() {
        return pairCount;
    }

    public long createdAtMillis() {
        return createdAtMillis;
    }

    public SessionState state() {
        return state.get();
    }

    public String abortReason() {
        return abortReason;
    }

    /** Moves the record to a new state if the transition is legal. */
    public boolean transitionTo(SessionState target) {
        SessionState current = state.get();
        if (!isLegal(current, target)) {
            return false;
        }
        boolean swapped = state.compareAndSet(current, target);
        if (swapped && target == SessionState.ABORTED) {
            this.abortReason = "aborted";
        }
        return swapped;
    }

    /** Records an abort with a reason; terminal if the session was aborted. */
    public boolean markAborted(String reason) {
        this.abortReason = reason;
        SessionState current = state.get();
        if (current == SessionState.ABORTED || current == SessionState.COMPLETED) {
            return false;
        }
        return state.compareAndSet(current, SessionState.ABORTED);
    }

    public boolean isTerminal() {
        SessionState current = state.get();
        return current == SessionState.ABORTED || current == SessionState.COMPLETED;
    }

    private static boolean isLegal(SessionState from, SessionState to) {
        if (from == to) {
            return false;
        }
        if (to == SessionState.ABORTED) {
            return from != SessionState.ABORTED && from != SessionState.COMPLETED;
        }
        return switch (from) {
            case PENDING -> to == SessionState.ACTIVE;
            case ACTIVE -> to == SessionState.COMPLETED;
            case COMPLETED, ABORTED -> false;
        };
    }
}

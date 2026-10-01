package com.github.guoyyit.oblivioustransferjava.session;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Process-wide registry of sessions. Thread-safe; terminal session ids remain
 * tombstoned and are never reused.
 *
 * <p>The registry stores only {@link SessionRecord} metadata; protocol secrets
 * live inside the session objects and are not visible here.
 */
public final class SessionRegistry {

    private final Map<SessionId, SessionRecord> records = new ConcurrentHashMap<>();

    public SessionRegistry() {
    }

    public SessionRecord register(boolean extension, int pairCount) {
        while (true) {
            SessionId id = SessionId.random();
            SessionRecord record = new SessionRecord(id, extension, pairCount);
            if (records.putIfAbsent(id, record) == null) {
                return record;
            }
        }
    }

    public SessionRecord get(SessionId id) {
        SessionRecord record = records.get(id);
        if (record == null) {
            return null;
        }
        return record;
    }

    /** Moves a session to a terminal state and keeps its id tombstoned. */
    public void tombstone(SessionId id) {
        SessionRecord record = records.get(id);
        if (record != null) {
            record.markAborted("tombstoned");
        }
    }

    /** Number of sessions not yet in a terminal state. */
    public int activeCount() {
        int count = 0;
        for (SessionRecord record : records.values()) {
            if (record != null && !record.isTerminal()) {
                count++;
            }
        }
        return count;
    }

    /** Number of registered sessions including tombstones (test support). */
    public int totalCount() {
        return records.size();
    }
}

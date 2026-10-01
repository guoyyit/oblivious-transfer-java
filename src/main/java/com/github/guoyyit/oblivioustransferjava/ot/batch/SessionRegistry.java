package com.github.guoyyit.oblivioustransferjava.ot.batch;

import com.github.guoyyit.oblivioustransferjava.ot.crypto.SymCrypto;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.SessionStatus;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话标识注册表。
 *
 * <p>使用 {@link ConcurrentHashMap} 保证多会话并发注册/查询安全；会话条目一旦创建
 * 永不删除（即使中止/取消），因此 128 位随机标识不可能被重复签发，已中止的
 * 会话标识也不会被复用。
 */
public final class SessionRegistry {

    private static final int SESSION_ID_LENGTH = 16;

    private final Map<Key, Entry> sessions = new ConcurrentHashMap<>();

    public SessionRegistry() {
    }

    /**
     * 生成一个全局唯一的新会话标识（128 位 SecureRandom）。
     */
    public byte[] newSessionId() {
        byte[] sessionId = new byte[SESSION_ID_LENGTH];
        SymCrypto.secureRandom().nextBytes(sessionId);
        Key key = new Key(sessionId);
        if (sessions.putIfAbsent(key, new Entry(SessionStatus.CREATED, null)) != null) {
            throw new OtException(ErrorCode.INTERNAL_ERROR, "会话标识冲突，请重试");
        }
        return sessionId;
    }

    /**
     * 绑定会话句柄；标识不存在时拒绝（只能由 {@link #newSessionId()} 产生）。
     */
    public void register(byte[] sessionId, Object session) {
        Key key = new Key(sessionId);
        Entry entry = sessions.get(key);
        if (entry == null) {
            throw new OtException(ErrorCode.SESSION_NOT_FOUND, "会话标识未注册");
        }
        synchronized (entry) {
            if (entry.session != null) {
                throw new OtException(ErrorCode.SESSION_ID_REUSE, "会话标识已绑定");
            }
            entry.session = session;
            entry.status = SessionStatus.ACTIVE;
        }
    }

    public Object lookup(byte[] sessionId) {
        Entry entry = sessions.get(new Key(sessionId));
        if (entry == null) {
            throw new OtException(ErrorCode.SESSION_NOT_FOUND, "会话不存在或标识非法");
        }
        synchronized (entry) {
            return entry.session;
        }
    }

    public SessionStatus status(byte[] sessionId) {
        Entry entry = sessions.get(new Key(sessionId));
        if (entry == null) {
            throw new OtException(ErrorCode.SESSION_NOT_FOUND, "会话不存在或标识非法");
        }
        synchronized (entry) {
            return entry.status;
        }
    }

    public void updateStatus(byte[] sessionId, SessionStatus status) {
        if (status == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "状态不能为空");
        }
        Entry entry = sessions.get(new Key(sessionId));
        if (entry == null) {
            throw new OtException(ErrorCode.SESSION_NOT_FOUND, "会话不存在或标识非法");
        }
        synchronized (entry) {
            entry.status = status;
        }
    }

    public int activeCount() {
        int count = 0;
        for (Entry entry : sessions.values()) {
            synchronized (entry) {
                if (entry.status == SessionStatus.ACTIVE
                        || entry.status == SessionStatus.CREATED
                        || entry.status == SessionStatus.COMMITTED) {
                    count++;
                }
            }
        }
        return count;
    }

    private static final class Entry {
        private volatile SessionStatus status;
        private Object session;

        private Entry(SessionStatus status, Object session) {
            this.status = status;
            this.session = session;
        }
    }

    private record Key(byte[] id) {

        @Override
        public boolean equals(Object other) {
            return other instanceof Key key && Arrays.equals(id, key.id);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(id);
        }
    }
}

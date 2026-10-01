package com.github.guoyyit.oblivioustransferjava.ot.transport;

import com.github.guoyyit.oblivioustransferjava.ot.protocol.Envelope;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.SessionStatus;

import java.util.concurrent.atomic.AtomicReference;

/**
 * 协议端点公共逻辑：基于已认证信封收消息、发消息、中止与故障传播。
 *
 * <p>任何一方协议失败或主动 {@link #abort} 时，向对端发送 ABORT 消息并关闭通道；
 * 对端下一次收发即可检测到 PEER_ABORTED 并终止，且选择位不会通过错误消息泄漏。
 */
public abstract class ProtocolEndpoint {

    public static final int MSG_ABORT = 0;

    private final OtChannel channel;
    private final MessageAuthenticator authenticator;
    private final AtomicReference<SessionStatus> status;

    protected ProtocolEndpoint(OtChannel channel,
                               MessageAuthenticator authenticator,
                               AtomicReference<SessionStatus> status) {
        this.channel = channel;
        this.authenticator = authenticator;
        this.status = status;
    }

    public SessionStatus status() {
        return status.get();
    }

    public boolean isAlive() {
        SessionStatus current = status.get();
        return current != SessionStatus.ABORTED && current != SessionStatus.CANCELLED
                && current != SessionStatus.FAILED && current != SessionStatus.COMPLETED;
    }

    /**
     * 发送一条业务消息。
     */
    protected void send(int messageType, byte[] body) {
        ensureActive();
        try {
            channel.send(authenticator.seal(messageType, body));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw fail(ErrorCode.SESSION_ABORTED, "发送被中断", e);
        } catch (OtException e) {
            throw fail(e.code(), e.getMessage(), e);
        }
    }

    /**
     * 阻塞等待指定类型的下一条消息；类型不符或对端中止都给出可区分错误。
     */
    protected byte[] receive(int expectedMessageType) {
        ensureActive();
        Envelope envelope;
        try {
            envelope = channel.receive();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw fail(ErrorCode.SESSION_ABORTED, "接收被中断", e);
        }
        if (envelope.messageType() == MSG_ABORT) {
            status.compareAndSet(SessionStatus.ACTIVE, SessionStatus.ABORTED);
            throw new OtException(ErrorCode.PEER_ABORTED, "对端中止了会话");
        }
        if (envelope.messageType() != expectedMessageType) {
            throw fail(ErrorCode.PROTOCOL_VIOLATION,
                    "收到非预期消息类型 expected=" + expectedMessageType
                            + " actual=" + envelope.messageType());
        }
        try {
            return authenticator.open(envelope);
        } catch (OtException e) {
            throw fail(e.code(), e.getMessage(), e);
        }
    }

    /**
     * 主动中止：通知对端并清理本端状态。中止后会话标识不可重用由注册表保证。
     */
    public void abort(ErrorCode reason, String detail) {
        if (!isAlive()) {
            channel.close();
            return;
        }
        status.set(SessionStatus.ABORTED);
        byte[] body = detail == null ? new byte[0] : detail.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        try {
            channel.send(authenticator.seal(MSG_ABORT, body));
        } catch (Exception ignored) {
            // 中止路径上的发送失败不影响本地清理
        }
        channel.close();
    }

    protected OtException fail(ErrorCode code, String detail, Throwable cause) {
        SessionStatus failureStatus = code == ErrorCode.CANCELLED
                ? SessionStatus.CANCELLED : SessionStatus.FAILED;
        status.set(failureStatus);
        channel.close();
        if (cause == null) {
            return new OtException(code, detail);
        }
        return new OtException(code, detail, cause);
    }

    protected OtException fail(ErrorCode code, String detail) {
        return fail(code, detail, null);
    }

    protected void markCompleted() {
        status.set(SessionStatus.COMPLETED);
        channel.close();
    }

    protected void closeQuietly() {
        channel.close();
    }

    private void ensureActive() {
        if (!isAlive()) {
            throw new OtException(ErrorCode.SESSION_CLOSED, "会话已结束: " + status.get());
        }
    }
}

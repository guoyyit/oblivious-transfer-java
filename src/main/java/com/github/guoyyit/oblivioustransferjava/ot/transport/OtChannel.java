package com.github.guoyyit.oblivioustransferjava.ot.transport;

import com.github.guoyyit.oblivioustransferjava.ot.protocol.Envelope;

/**
 * 进程内双工通道，会话间状态完全隔离。
 */
public interface OtChannel {

    void send(Envelope envelope) throws InterruptedException;

    Envelope receive() throws InterruptedException;

    void close();

    boolean isClosed();
}

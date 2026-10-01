package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.OtService;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtConfig;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.SessionStatus;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AbortAndCancelTest {

    @Test
    void receiverCancellationAbortsSenderAndMarksSession() throws Exception {
        OtService service = new OtService(OtConfig.defaults().batchSize(4));
        try {
            int n = 40;
            List<MessagePair> pairs = TestSupport.messages(n);
            byte[] choices = TestSupport.alternatingChoices(n);
            OtService.BatchSession session =
                    service.createBatchSession(TestSupport.source(pairs), choices);
            session.receiver().start(n, choices);
            session.receiver().redeemNextBatch();

            session.receiver().cancel();

            long deadline = System.currentTimeMillis() + 10_000;
            SessionStatus status;
            do {
                status = service.sessionStatus(session.sessionId());
                if (status == SessionStatus.CANCELLED || status == SessionStatus.ABORTED) {
                    break;
                }
                Thread.sleep(50);
            } while (System.currentTimeMillis() < deadline);

            assertTrue(status == SessionStatus.CANCELLED || status == SessionStatus.ABORTED,
                    "取消后服务端应观察到终止，实际=" + status);

            assertThrows(OtException.class, session.receiver()::redeemNextBatch);
            SessionStatus finalStatus = service.sessionStatus(session.sessionId());
            assertTrue(finalStatus == SessionStatus.CANCELLED
                            || finalStatus == SessionStatus.ABORTED
                            || finalStatus == SessionStatus.FAILED,
                    "取消后会话必须处于终止状态: " + finalStatus);
        } finally {
            service.shutdown();
        }
    }

    @Test
    void senderAbortionIsDetectedByReceiver() throws Exception {
        OtService service = new OtService(OtConfig.defaults().batchSize(4));
        try {
            int n = 20;
            List<MessagePair> pairs = TestSupport.messages(n);
            byte[] choices = TestSupport.alternatingChoices(n);
            OtService.BatchSession session =
                    service.createBatchSession(TestSupport.source(pairs), choices);
            session.receiver().start(n, choices);
            session.receiver().redeemNextBatch();

            session.sender().abort(ErrorCode.SESSION_ABORTED, "sender giving up");
            Thread.sleep(100);
            OtException error = assertThrows(OtException.class,
                    session.receiver()::redeemNextBatch);
            assertTrue(error.code() == ErrorCode.PEER_ABORTED
                            || error.code() == ErrorCode.SESSION_CLOSED
                            || error.code() == ErrorCode.SESSION_ABORTED,
                    "接收方必须检测到发送方中止: " + error.code());
        } finally {
            service.shutdown();
        }
    }

    @Test
    void unknownSessionIdIsRejected() {
        OtService service = new OtService();
        try {
            OtException error = assertThrows(OtException.class,
                    () -> service.sessionStatus(new byte[]{1, 2, 3}));
            assertEquals(ErrorCode.SESSION_NOT_FOUND, error.code());
        } finally {
            service.shutdown();
        }
    }
}

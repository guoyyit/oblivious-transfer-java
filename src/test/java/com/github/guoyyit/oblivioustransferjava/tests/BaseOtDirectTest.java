package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.OtService;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class BaseOtDirectTest {

    @Test
    void receiverGetsChosenMessage() throws Exception {
        OtService service = new OtService();
        try {
            OtService.BaseTransfer transfer = service.createBaseTransfer();
            MessagePair pair = new MessagePair(
                    "zero-msg".getBytes(StandardCharsets.UTF_8),
                    "the-other-one".getBytes(StandardCharsets.UTF_8));

            Thread senderThread = new Thread(() -> transfer.sender().run(pair));
            senderThread.start();
            byte[] got = transfer.receiver().run(1, pair.message1().length);
            senderThread.join(5000);

            assertArrayEquals(pair.message1(), got);
        } finally {
            service.shutdown();
        }
    }
}

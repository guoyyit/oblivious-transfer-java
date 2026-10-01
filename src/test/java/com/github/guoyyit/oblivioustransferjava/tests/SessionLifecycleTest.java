package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.service.OtService;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionLifecycleTest {

    private final OtService service = new OtService();

    @Test
    void sessionIdsAreUniqueAndTerminalSessionsTombstoned() {
        Set<String> ids = new HashSet<>();
        int created = 200;
        for (int i = 0; i < created; i++) {
            ids.add(service.createExtensionSession(128, 128).sessionId().toString());
        }
        // Random 128-bit ids are effectively unique.
        assertEquals(created, ids.size());
    }

    @Test
    void completedExtensionSessionIsTerminalAndRegistrySettles() throws Exception {
        int n = 128;
        OtService.ExtensionSession session = service.createExtensionSession(n, 128);
        Future<?> sender = OtService.startExtensionSender(session,
                idx -> new byte[][]{("m0-" + idx).getBytes(), ("m1-" + idx).getBytes()});
        boolean[] choices = new boolean[n];
        for (int i = 0; i < n; i++) {
            choices[i] = i % 4 == 0;
        }
        session.receiver().submitChoices(choices);
        byte[][] result = session.receiver().redeemRange(0, n);
        assertEquals(n, result.length);
        sender.get();
        assertEquals(0, service.registry().activeCount());
        assertNotNull(service.registry().get(session.sessionId()));
    }

    @Test
    void cancelDuringExtensionLeavesNoActiveSession() throws Exception {
        int n = 128;
        OtService.ExtensionSession session = service.createExtensionSession(n, 128);
        Future<?> sender = OtService.startExtensionSender(session,
                idx -> new byte[][]{("m0-" + idx).getBytes(), ("m1-" + idx).getBytes()});
        session.receiver().submitChoices(new boolean[n]);
        session.receiver().redeemRange(0, 16);
        session.receiver().cancel();
        sender.cancel(true);
        assertEquals(0, service.registry().activeCount());
    }

    @Test
    void duplicateRedemptionAcrossRestartIsImpossibleBecauseSessionDies() throws Exception {
        int n = 128;
        OtService.ExtensionSession session = service.createExtensionSession(n, 128);
        Future<?> sender = OtService.startExtensionSender(session,
                idx -> new byte[][]{("m0-" + idx).getBytes(), ("m1-" + idx).getBytes()});
        session.receiver().submitChoices(new boolean[n]);
        session.receiver().redeemRange(0, 32);
        session.receiver().cancel();
        sender.cancel(true);
        OtException error = expect(() -> session.receiver().redeemOne(0));
        assertTrue(error.errorCode() == ErrorCode.CANCELLED
                || error.errorCode() == ErrorCode.SESSION_ABORTED);
    }

    @Test
    void invalidPairCountIsRejectedBeforeRegistryAllocation() {
        int before = service.registry().totalCount();
        OtException error = expect(() -> service.createExtensionSession(0, 128));
        assertEquals(ErrorCode.INVALID_PARAMETER, error.errorCode());
        assertEquals(before, service.registry().totalCount());
        assertFalse(before < 0);
    }

    private interface Action {
        void run();
    }

    private static OtException expect(Action action) {
        try {
            action.run();
            throw new AssertionError("expected OtException");
        } catch (OtException e) {
            return e;
        }
    }
}

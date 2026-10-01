package com.github.guoyyit.oblivioustransferjava.tests;

import com.github.guoyyit.oblivioustransferjava.ot.batch.BatchSender;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.MessagePair;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 测试共用的消息源与选择向量构造工具。
 */
final class TestSupport {

    private TestSupport() {
    }

    static List<MessagePair> messages(int n) {
        List<MessagePair> pairs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            pairs.add(new MessagePair(
                    ("m0-" + i).getBytes(StandardCharsets.UTF_8),
                    ("the-second-message-number-" + i).getBytes(StandardCharsets.UTF_8)));
        }
        return pairs;
    }

    static byte[] alternatingChoices(int n) {
        byte[] choices = new byte[n];
        for (int i = 0; i < n; i++) {
            choices[i] = (byte) (i % 2);
        }
        return choices;
    }

    static InMemoryMessageSource source(List<MessagePair> pairs) {
        return new InMemoryMessageSource(pairs);
    }

    static final class InMemoryMessageSource implements BatchSender.MessageSource {
        private final List<MessagePair> pairs;

        InMemoryMessageSource(List<MessagePair> pairs) {
            this.pairs = pairs;
        }

        @Override
        public int size() {
            return pairs.size();
        }

        @Override
        public MessagePair get(int index) {
            return pairs.get(index);
        }
    }
}

package com.github.guoyyit.oblivioustransferjava.ot.base;

import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

/**
 * 基础 1-out-of-2 OT 的三条协议消息的紧凑编码（位于已认证信封体内部）。
 *
 * <p>所有字节串均采用 2 字节长度前缀；解码时任何截断或长度不一致都
 * 以 MESSAGE_TRUNCATED 拒绝。
 */
public final class BaseOtMessages {

    private BaseOtMessages() {
    }

    public static byte[] encodeSenderInit(byte[] c0, byte[] c1) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBlock(out, c0);
        writeBlock(out, c1);
        return out.toByteArray();
    }

    public static SenderInit decodeSenderInit(byte[] body) {
        Reader reader = new Reader(body);
        byte[] c0 = reader.readBlock();
        byte[] c1 = reader.readBlock();
        reader.requireEnd();
        return new SenderInit(c0, c1);
    }

    public static byte[] encodeReceiverChoice(byte[] pk) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBlock(out, pk);
        return out.toByteArray();
    }

    public static ReceiverChoice decodeReceiverChoice(byte[] body) {
        Reader reader = new Reader(body);
        byte[] pk = reader.readBlock();
        reader.requireEnd();
        return new ReceiverChoice(pk);
    }

    public static byte[] encodeCiphertexts(byte[] cipher0, byte[] cipher1) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBlock(out, cipher0);
        writeBlock(out, cipher1);
        return out.toByteArray();
    }

    public static CiphertextPair decodeCiphertexts(byte[] body) {
        Reader reader = new Reader(body);
        byte[] cipher0 = reader.readBlock();
        byte[] cipher1 = reader.readBlock();
        reader.requireEnd();
        return new CiphertextPair(cipher0, cipher1);
    }

    private static void writeBlock(ByteArrayOutputStream out, byte[] data) {
        if (data == null || data.length > 0xFFFF) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "消息块长度非法");
        }
        out.write(data.length >>> 8);
        out.write(data.length & 0xFF);
        out.writeBytes(data);
    }

    private static final class Reader {
        private final ByteBuffer buffer;

        private Reader(byte[] body) {
            if (body == null) {
                throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "消息体为空");
            }
            this.buffer = ByteBuffer.wrap(body);
        }

        private byte[] readBlock() {
            if (buffer.remaining() < 2) {
                throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "缺少长度前缀");
            }
            int length = Short.toUnsignedInt(buffer.getShort());
            if (buffer.remaining() < length) {
                throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "消息块被截断");
            }
            byte[] block = new byte[length];
            buffer.get(block);
            return block;
        }

        private void requireEnd() {
            if (buffer.hasRemaining()) {
                throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "消息存在多余字节");
            }
        }
    }

    public record SenderInit(byte[] c0, byte[] c1) {
    }

    public record ReceiverChoice(byte[] pk) {
    }

    public record CiphertextPair(byte[] cipher0, byte[] cipher1) {
    }
}

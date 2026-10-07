package com.github.guoyyit.oblivioustransferjava.ot.batch;

import com.github.guoyyit.oblivioustransferjava.ot.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.ot.protocol.OtException;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

/**
 * 批量 OT 会话消息类型与载荷编码（载荷均位于已认证信封内）。
 */
final class BatchMessages {

    private BatchMessages() {
    }

    static final int MSG_BASE_SENDER_INIT = 10;
    static final int MSG_BASE_RECEIVER_CHOICE = 11;
    static final int MSG_BASE_CIPHERTEXTS = 12;

    static final int MSG_COMMIT = 20;
    static final int MSG_T_COLUMNS = 21;

    static final int MSG_REDEMPTION = 30;
    static final int MSG_REDEMPTION_RESULT = 31;

    static final int MSG_DONE = 40;

    static byte[] encodeCommitment(int n, byte[] commitment) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeInt(out, n);
        writeBlock(out, commitment);
        return out.toByteArray();
    }

    static Commitment decodeCommitment(byte[] body) {
        Reader reader = new Reader(body);
        int n = reader.readInt();
        byte[] commitment = reader.readBlock(256);
        reader.requireEnd();
        return new Commitment(n, commitment);
    }

    /**
     * 扩展批次矩阵编码：修复后线上只传输 IKNP 的 U 矩阵（κ 列），
     * 不再发送第二个矩阵，选择位由接收方私有 PRG 种子掩码。
     */
    static byte[] encodeMatrix(int globalStart, byte[][] uColumns) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeInt(out, globalStart);
        writeInt(out, uColumns.length);
        for (byte[] column : uColumns) {
            writeLargeBlock(out, column);
        }
        return out.toByteArray();
    }

    static Matrix decodeMatrix(byte[] body, int expectedKappa) {
        Reader reader = new Reader(body);
        int globalStart = reader.readInt();
        int kappa = reader.readInt();
        if (kappa != expectedKappa) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "矩阵列数与 kappa 不符");
        }
        byte[][] uColumns = new byte[kappa][];
        for (int j = 0; j < kappa; j++) {
            uColumns[j] = reader.readLargeBlock();
        }
        reader.requireEnd();
        return new Matrix(globalStart, uColumns);
    }

    static byte[] encodeRedemption(int globalStart, int count) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeInt(out, globalStart);
        writeInt(out, count);
        return out.toByteArray();
    }

    static Redemption decodeRedemption(byte[] body) {
        Reader reader = new Reader(body);
        int globalStart = reader.readInt();
        int count = reader.readInt();
        reader.requireEnd();
        return new Redemption(globalStart, count);
    }

    static byte[] encodeRedemptionResult(byte[][] messages) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeInt(out, messages.length);
        for (byte[] message : messages) {
            writeLargeBlock(out, message);
        }
        return out.toByteArray();
    }

    static byte[][] decodeRedemptionResult(byte[] body, int expectedCount) {
        Reader reader = new Reader(body);
        int count = reader.readInt();
        if (count != expectedCount) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "兑换结果条数不符");
        }
        byte[][] messages = new byte[count][];
        for (int i = 0; i < count; i++) {
            messages[i] = reader.readLargeBlock();
        }
        reader.requireEnd();
        return messages;
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write(value >>> 24);
        out.write(value >>> 16);
        out.write(value >>> 8);
        out.write(value);
    }

    private static void writeBlock(ByteArrayOutputStream out, byte[] data) {
        if (data == null || data.length > 0xFFFF) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "消息块长度非法");
        }
        out.write(data.length >>> 8);
        out.write(data.length & 0xFF);
        out.writeBytes(data);
    }

    private static void writeLargeBlock(ByteArrayOutputStream out, byte[] data) {
        if (data == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "消息块为空");
        }
        writeInt(out, data.length);
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

        private int readInt() {
            if (buffer.remaining() < 4) {
                throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "缺少整数字段");
            }
            return buffer.getInt();
        }

        private byte[] readBlock(int maxLength) {
            if (buffer.remaining() < 2) {
                throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "缺少长度前缀");
            }
            int length = Short.toUnsignedInt(buffer.getShort());
            return readBytes(length, maxLength);
        }

        private byte[] readLargeBlock() {
            if (buffer.remaining() < 4) {
                throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "缺少长度前缀");
            }
            int length = buffer.getInt();
            return readBytes(length, Integer.MAX_VALUE);
        }

        private byte[] readBytes(int length, int maxLength) {
            if (length < 0 || length > maxLength) {
                throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "消息块长度非法");
            }
            if (buffer.remaining() < length) {
                throw new OtException(ErrorCode.MESSAGE_TRUNCATED, "消息块被截断");
            }
            byte[] data = new byte[length];
            buffer.get(data);
            return data;
        }

        private void requireEnd() {
            if (buffer.hasRemaining()) {
                throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "消息存在多余字节");
            }
        }
    }

    record Commitment(int n, byte[] commitment) {
    }

    record Matrix(int globalStart, byte[][] columns) {
    }

    record Redemption(int globalStart, int count) {
    }
}

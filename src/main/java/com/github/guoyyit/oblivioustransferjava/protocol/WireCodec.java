package com.github.guoyyit.oblivioustransferjava.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Binary encoding of envelope payloads. All variable-length fields use a
 * 4-byte big-endian length prefix; truncated inputs are rejected rather than
 * partially decoded.
 */
public final class WireCodec {

    private WireCodec() {
    }

    /** AES-GCM sealed body. */
    public record Sealed(byte[] nonce, byte[] ciphertext) {
    }

    public record InitPayload(boolean extension, int pairs, int batchSize, int baseCount) {
    }

    public record OtInitPayload(BigInteger publicElement) {
    }

    public record OtReplyPayload(BigInteger publicElement) {
    }

    public record OtDataPayload(Sealed first, Sealed second) {
    }

    public record ExtBatchPayload(int batchIndex, Sealed[][] sealed) {
    }

    public record RedeemRequestPayload(int offset, int length) {
    }

    public record RedeemResponsePayload(OtDataPayload[] items) {
    }

    public record ErrorPayload(ErrorCode code, String reason) {
    }

    public static byte[] encode(InitPayload payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream d = new DataOutputStream(out)) {
            d.writeBoolean(payload.extension());
            d.writeInt(payload.pairs());
            d.writeInt(payload.batchSize());
            d.writeInt(payload.baseCount());
        } catch (IOException e) {
            throw error(e);
        }
        return out.toByteArray();
    }

    public static InitPayload decodeInit(byte[] data) {
        try (DataInputStream in = input(data)) {
            boolean extension = in.readBoolean();
            int pairs = in.readInt();
            int batchSize = in.readInt();
            int baseCount = in.readInt();
            requireFullyConsumed(in);
            return new InitPayload(extension, pairs, batchSize, baseCount);
        } catch (IOException e) {
            throw error(e);
        }
    }

    public static byte[] encode(OtInitPayload payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream d = new DataOutputStream(out)) {
            writeBytes(d, com.github.guoyyit.oblivioustransferjava.crypto
                    .SafePrimeGroup.elementToBytes(payload.publicElement()));
        } catch (IOException e) {
            throw error(e);
        }
        return out.toByteArray();
    }

    public static OtInitPayload decodeOtInit(byte[] data) {
        try (DataInputStream in = input(data)) {
            BigInteger element = readElement(in);
            requireFullyConsumed(in);
            return new OtInitPayload(element);
        } catch (IOException e) {
            throw error(e);
        }
    }

    public static byte[] encode(OtReplyPayload payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream d = new DataOutputStream(out)) {
            writeBytes(d, com.github.guoyyit.oblivioustransferjava.crypto
                    .SafePrimeGroup.elementToBytes(payload.publicElement()));
        } catch (IOException e) {
            throw error(e);
        }
        return out.toByteArray();
    }

    public static OtReplyPayload decodeOtReply(byte[] data) {
        try (DataInputStream in = input(data)) {
            BigInteger element = readElement(in);
            requireFullyConsumed(in);
            return new OtReplyPayload(element);
        } catch (IOException e) {
            throw error(e);
        }
    }

    public static byte[] encode(OtDataPayload payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream d = new DataOutputStream(out)) {
            writeSealed(d, payload.first());
            writeSealed(d, payload.second());
        } catch (IOException e) {
            throw error(e);
        }
        return out.toByteArray();
    }

    public static OtDataPayload decodeOtData(byte[] data) {
        try (DataInputStream in = input(data)) {
            Sealed first = readSealed(in);
            Sealed second = readSealed(in);
            requireFullyConsumed(in);
            return new OtDataPayload(first, second);
        } catch (IOException e) {
            throw error(e);
        }
    }

    public static byte[] encode(ExtBatchPayload payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream d = new DataOutputStream(out)) {
            d.writeInt(payload.batchIndex());
            d.writeInt(payload.sealed().length);
            for (Sealed[] pair : payload.sealed()) {
                if (pair.length != 2) {
                    throw new OtException(ErrorCode.TRUNCATED_MESSAGE, "expected 2 sealed items");
                }
                writeSealed(d, pair[0]);
                writeSealed(d, pair[1]);
            }
        } catch (IOException e) {
            throw error(e);
        }
        return out.toByteArray();
    }

    public static ExtBatchPayload decodeExtBatch(byte[] data) {
        try (DataInputStream in = input(data)) {
            int batchIndex = in.readInt();
            int count = in.readInt();
            if (count < 0) {
                throw new OtException(ErrorCode.TRUNCATED_MESSAGE, "negative batch count");
            }
            Sealed[][] sealed = new Sealed[count][];
            for (int i = 0; i < count; i++) {
                sealed[i] = new Sealed[]{readSealed(in), readSealed(in)};
            }
            requireFullyConsumed(in);
            return new ExtBatchPayload(batchIndex, sealed);
        } catch (IOException e) {
            throw error(e);
        }
    }

    public static byte[] encode(RedeemRequestPayload payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream d = new DataOutputStream(out)) {
            d.writeInt(payload.offset());
            d.writeInt(payload.length());
        } catch (IOException e) {
            throw error(e);
        }
        return out.toByteArray();
    }

    public static RedeemRequestPayload decodeRedeemRequest(byte[] data) {
        try (DataInputStream in = input(data)) {
            int offset = in.readInt();
            int length = in.readInt();
            requireFullyConsumed(in);
            return new RedeemRequestPayload(offset, length);
        } catch (IOException e) {
            throw error(e);
        }
    }

    public static byte[] encode(RedeemResponsePayload payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream d = new DataOutputStream(out)) {
            d.writeInt(payload.items().length);
            for (OtDataPayload item : payload.items()) {
                writeBytes(d, encode(item));
            }
        } catch (IOException e) {
            throw error(e);
        }
        return out.toByteArray();
    }

    public static RedeemResponsePayload decodeRedeemResponse(byte[] data) {
        try (DataInputStream in = input(data)) {
            int count = in.readInt();
            if (count < 0) {
                throw new OtException(ErrorCode.TRUNCATED_MESSAGE, "negative response count");
            }
            OtDataPayload[] items = new OtDataPayload[count];
            for (int i = 0; i < count; i++) {
                items[i] = decodeOtData(readBytes(in));
            }
            requireFullyConsumed(in);
            return new RedeemResponsePayload(items);
        } catch (IOException e) {
            throw error(e);
        }
    }

    public static byte[] encode(ErrorPayload payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream d = new DataOutputStream(out)) {
            d.writeByte(payload.code().ordinal());
            byte[] reason = payload.reason() == null
                    ? new byte[0] : payload.reason().getBytes(StandardCharsets.UTF_8);
            writeBytes(d, reason);
        } catch (IOException e) {
            throw error(e);
        }
        return out.toByteArray();
    }

    public static ErrorPayload decodeError(byte[] data) {
        try (DataInputStream in = input(data)) {
            int ordinal = in.readByte() & 0xFF;
            ErrorCode[] codes = ErrorCode.values();
            if (ordinal >= codes.length) {
                throw new OtException(ErrorCode.TRUNCATED_MESSAGE, "unknown error code");
            }
            byte[] reason = readBytes(in);
            requireFullyConsumed(in);
            return new ErrorPayload(codes[ordinal], new String(reason, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw error(e);
        }
    }

    static BigInteger readElement(DataInput in) throws IOException {
        byte[] encoded = readBytes(in);
        BigInteger element = com.github.guoyyit.oblivioustransferjava.crypto
                .SafePrimeGroup.bytesToElement(encoded);
        if (element == null) {
            throw new OtException(ErrorCode.MESSAGE_TAMPERED, "bad group element encoding");
        }
        return element;
    }

    private static Sealed readSealed(DataInput in) throws IOException {
        byte[] nonce = readBytes(in);
        byte[] ciphertext = readBytes(in);
        return new Sealed(nonce, ciphertext);
    }

    private static void writeSealed(DataOutputStream d, Sealed sealed) throws IOException {
        writeBytes(d, sealed.nonce());
        writeBytes(d, sealed.ciphertext());
    }

    private static void writeBytes(DataOutputStream d, byte[] bytes) throws IOException {
        d.writeInt(bytes.length);
        d.write(bytes);
    }

    private static byte[] readBytes(DataInput in) throws IOException {
        int length = in.readInt();
        if (length < 0) {
            throw new OtException(ErrorCode.TRUNCATED_MESSAGE, "negative length");
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return bytes;
    }

    private static DataInputStream input(byte[] data) {
        if (data == null) {
            throw new OtException(ErrorCode.TRUNCATED_MESSAGE, "null payload");
        }
        return new DataInputStream(new ByteArrayInputStream(data));
    }

    private static void requireFullyConsumed(DataInputStream in) throws IOException {
        if (in.read() != -1) {
            throw new OtException(ErrorCode.MESSAGE_TAMPERED, "trailing payload bytes");
        }
    }

    private static OtException error(IOException e) {
        return new OtException(ErrorCode.TRUNCATED_MESSAGE, "malformed payload", e);
    }
}

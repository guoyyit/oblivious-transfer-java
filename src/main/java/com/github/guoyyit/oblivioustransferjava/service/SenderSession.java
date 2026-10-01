package com.github.guoyyit.oblivioustransferjava.service;

import com.github.guoyyit.oblivioustransferjava.crypto.CryptoRandom;
import com.github.guoyyit.oblivioustransferjava.crypto.DhBaseOt;
import com.github.guoyyit.oblivioustransferjava.crypto.Iknp;
import com.github.guoyyit.oblivioustransferjava.crypto.Kdf;
import com.github.guoyyit.oblivioustransferjava.crypto.SafePrimeGroup;
import com.github.guoyyit.oblivioustransferjava.protocol.Envelope;
import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.MessageType;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.protocol.ProtocolChannel;
import com.github.guoyyit.oblivioustransferjava.protocol.WireCodec;
import com.github.guoyyit.oblivioustransferjava.session.SessionRecord;
import com.github.guoyyit.oblivioustransferjava.session.SessionRegistry;
import com.github.guoyyit.oblivioustransferjava.session.SessionState;

import java.math.BigInteger;
import java.util.List;

/**
 * Sender-side endpoint for one session.
 *
 * <p>Base mode runs {@code pairCount} DDH-based 1-out-of-2 OTs.
 * Extension mode runs k = {@link Iknp#BASE_COUNT} base OTs with reversed roles
 * then advances IKNP batch by batch using only symmetric primitives. Extension
 * materializes correlated random OT keys; real messages are sealed only when
 * the receiver redeems them, so un-redeemed messages never leave the sender.
 */
public final class SenderSession {

    private static final SafePrimeGroup GROUP = SafePrimeGroup.MODP_2048;

    private final SessionRecord record;
    private final SessionRegistry registry;
    private final ProtocolChannel channel;
    private final int pairCount;
    private final int batchSize;
    private final boolean extension;

    public SenderSession(SessionRecord record,
                         SessionRegistry registry,
                         ProtocolChannel channel,
                         int pairCount,
                         int batchSize,
                         boolean extension) {
        this.record = record;
        this.registry = registry;
        this.channel = channel;
        this.pairCount = pairCount;
        this.batchSize = batchSize;
        this.extension = extension;
    }

    /** Supplies message pairs in global index order (extension mode). */
    @FunctionalInterface
    public interface MessageProvider {
        byte[][] supply(int index);
    }

    /** Runs pairCount base 1-out-of-2 OTs on the current thread. */
    public void runBase(List<byte[][]> messagePairs) {
        validateMode(false);
        if (messagePairs == null || messagePairs.size() != pairCount) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "expected " + pairCount + " message pairs");
        }
        begin();
        try {
            sendInit(false);
            for (int i = 0; i < pairCount; i++) {
                DhBaseOt.SenderInit init = DhBaseOt.createSenderInit(GROUP);
                channel.send(MessageType.OT_INIT, WireCodec.encode(
                        new WireCodec.OtInitPayload(init.publicElement())));
                BigInteger receiverPublic = readReplyElement(
                        channel.receive(MessageType.OT_REPLY));
                byte[][] keys = DhBaseOt.deriveSenderKeys(GROUP, init, receiverPublic);
                byte[][] messages = messagePairs.get(i);
                validateMessages(messages);
                channel.send(MessageType.OT_PAYLOAD, WireCodec.encode(
                        sealPair(keys[0], keys[1], messages)));
            }
            complete();
        } catch (OtException failure) {
            throw fail(failure);
        } catch (RuntimeException failure) {
            throw fail(new OtException(ErrorCode.INTERNAL_ERROR, "sender base OT failed", failure));
        }
    }

    /** Runs extension batch-by-batch, then answers redemptions. */
    public void runExtension(MessageProvider provider) {
        validateMode(true);
        if (provider == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER, "null message provider");
        }
        begin();
        try {
            sendInit(true);

            // Base OTs run pair-by-pair to keep the bounded channels live.
            // Receiver is the base-OT sender; sender picks k-bit string s.
            byte[] s = Iknp.randomBitString(Iknp.BASE_COUNT);
            byte[][] baseKeys = new byte[Iknp.BASE_COUNT][];
            for (int j = 0; j < Iknp.BASE_COUNT; j++) {
                BigInteger aElement = readInitElement(channel.receive(MessageType.OT_INIT));
                DhBaseOt.ReceiverReply reply = DhBaseOt.createReceiverReply(
                        GROUP, aElement, Iknp.getBit(s, j));
                baseKeys[j] = reply.key();
                channel.send(MessageType.OT_REPLY, WireCodec.encode(
                        new WireCodec.OtReplyPayload(reply.publicElement())));
            }

            // Phase 1: consume extension batches strictly in order. Only the
            // current batch's correlated rows are retained (bounded memory).
            int batchCount = (pairCount + batchSize - 1) / batchSize;
            for (int batch = 0; batch < batchCount; batch++) {
                processExtensionBatch(batch, s, baseKeys, provider);
            }

            complete();
        } catch (OtException failure) {
            throw fail(failure);
        } catch (RuntimeException failure) {
            throw fail(new OtException(ErrorCode.INTERNAL_ERROR,
                    "sender extension failed", failure));
        }
    }

    /** Aborts the session; the id is tombstoned and never reused. */
    public void abort() {
        channel.sendAbort();
        channel.close();
        record.markAborted("locally aborted");
        registry.tombstone(record.id());
    }

    private void processExtensionBatch(int batch, byte[] s, byte[][] baseKeys,
                                       MessageProvider provider) {
        byte[] data = channel.receive(MessageType.EXT_BATCH);
        WireCodec.ExtBatchPayload payload = WireCodec.decodeExtBatch(data);
        int offset = batch * batchSize;
        int batchCount = (pairCount + batchSize - 1) / batchSize;
        int size = batch == batchCount - 1 ? pairCount - offset : batchSize;
        if (payload.batchIndex() != batch) {
            throw new OtException(ErrorCode.OUT_OF_ORDER,
                    "expected extension batch " + batch + " got " + payload.batchIndex());
        }
        if (payload.sealed().length != Iknp.BASE_COUNT) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION,
                    "batch " + batch + " must carry " + Iknp.BASE_COUNT + " column pairs");
        }
        int columnBytes = Iknp.packedBytes(size);
        byte[][] qColumns = new byte[Iknp.BASE_COUNT][];
        for (int j = 0; j < Iknp.BASE_COUNT; j++) {
            int choice = Iknp.getBit(s, j);
            WireCodec.Sealed sealed = payload.sealed()[j][choice];
            if (sealed == null || sealed.nonce().length != Kdf.nonceLength()) {
                throw new OtException(ErrorCode.TRUNCATED_MESSAGE, "malformed column " + j);
            }
            byte[] column;
            try {
                column = Kdf.open(baseKeys[j], sealed.nonce(), sealed.ciphertext());
            } catch (IllegalArgumentException e) {
                throw new OtException(ErrorCode.MESSAGE_TAMPERED,
                        "extension column " + j + " failed authentication");
            }
            if (column.length != columnBytes) {
                throw new OtException(ErrorCode.TRUNCATED_MESSAGE, "wrong column length " + j);
            }
            qColumns[j] = column;
        }
        byte[][] rows = Iknp.transpose(qColumns, size);

        // Receiver may redeem any contiguous sub-ranges of THIS batch, in
        // increasing order; keys are dropped once the batch is fully redeemed.
        boolean[] batchRedeemed = new boolean[size];
        int remaining = size;
        int redemptionCursor = 0;
        while (remaining > 0) {
            Envelope envelope = channel.receive();
            if (envelope.type() == MessageType.ABORT) {
                throw new OtException(ErrorCode.CANCELLED, "receiver cancelled");
            }
            if (envelope.type() != MessageType.REDEEM_REQUEST) {
                throw new OtException(ErrorCode.PROTOCOL_VIOLATION,
                        "expected redemption request, got " + envelope.type());
            }
            WireCodec.RedeemRequestPayload request =
                    WireCodec.decodeRedeemRequest(envelope.payload());
            int localOffset = request.offset() - offset;
            int length = request.length();
            validateBatchRedemption(localOffset, length, size, batchRedeemed);
            if (localOffset != redemptionCursor) {
                throw new OtException(ErrorCode.REDEMPTION_CONFLICT,
                        "redemption gap detected at local index " + redemptionCursor);
            }
            WireCodec.OtDataPayload[] items = new WireCodec.OtDataPayload[length];
            for (int local = 0; local < length; local++) {
                int globalIndex = offset + localOffset + local;
                int rowLocal = localOffset + local;
                byte[][] messages = provider.supply(globalIndex);
                validateMessages(messages);
                byte[] k0 = Iknp.rowKey(rows[rowLocal], globalIndex, 0);
                byte[] k1 = Iknp.rowKey(Iknp.xorBitStrings(rows[rowLocal], s),
                        globalIndex, 1);
                items[local] = sealPair(k0, k1, messages);
            }
            for (int i = localOffset; i < localOffset + length; i++) {
                batchRedeemed[i] = true;
            }
            remaining -= length;
            redemptionCursor += length;
            channel.send(MessageType.REDEEM_RESPONSE, WireCodec.encode(
                    new WireCodec.RedeemResponsePayload(items)));
        }
        // Batch fully redeemed: acknowledge it. The receiver only advances to
        // the next batch after consuming this confirmation, keeping the
        // strictly alternating message order intact.
        channel.send(MessageType.EXT_BATCH, new byte[0]);
    }

    private void validateBatchRedemption(int localOffset, int length,
                                         int size, boolean[] redeemed) {
        if (localOffset < 0 || length <= 0 || localOffset + length > size) {
            throw new OtException(ErrorCode.RANGE_OUT_OF_BOUNDS,
                    "redemption local range invalid");
        }
        for (int i = localOffset; i < localOffset + length; i++) {
            if (redeemed[i]) {
                throw new OtException(ErrorCode.REDEMPTION_CONFLICT,
                        "message at local index " + i + " already redeemed");
            }
        }
    }

    private WireCodec.Sealed sealMessage(byte[] key, byte[] message) {
        byte[] nonce = CryptoRandom.randomBytes(Kdf.nonceLength());
        return new WireCodec.Sealed(nonce, Kdf.seal(key, nonce, message));
    }

    private WireCodec.OtDataPayload sealPair(byte[] k0, byte[] k1, byte[][] messages) {
        return new WireCodec.OtDataPayload(
                sealMessage(k0, messages[0]), sealMessage(k1, messages[1]));
    }

    private void validateMessages(byte[][] messages) {
        if (messages == null || messages.length != 2
                || messages[0] == null || messages[1] == null) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "message pair must contain two non-null byte strings");
        }
    }

    private void sendInit(boolean ext) {
        channel.send(MessageType.INIT, WireCodec.encode(new WireCodec.InitPayload(
                ext, pairCount, batchSize, Iknp.BASE_COUNT)));
        channel.receive(MessageType.INIT_ACK);
    }

    private void begin() {
        if (!record.transitionTo(SessionState.ACTIVE)) {
            throw new OtException(ErrorCode.SESSION_ABORTED,
                    "session cannot start from state " + record.state());
        }
    }

    private void complete() {
        if (record.transitionTo(SessionState.COMPLETED)) {
            registry.tombstone(record.id());
            channel.close();
        }
    }

    private OtException fail(OtException error) {
        channel.sendError(error.errorCode(), error.getMessage());
        channel.close();
        record.markAborted(error.getMessage());
        registry.tombstone(record.id());
        return error;
    }

    private void validateMode(boolean expectExtension) {
        if (extension != expectExtension) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "wrong session mode");
        }
    }

    private static BigInteger readInitElement(byte[] data) {
        BigInteger element = WireCodec.decodeOtInit(data).publicElement();
        if (!SafePrimeGroup.MODP_2048.isValidElement(element)) {
            throw new OtException(ErrorCode.MESSAGE_TAMPERED, "invalid OT init element");
        }
        return element;
    }

    private static BigInteger readReplyElement(byte[] data) {
        BigInteger element = WireCodec.decodeOtReply(data).publicElement();
        if (!SafePrimeGroup.MODP_2048.isValidElement(element)) {
            throw new OtException(ErrorCode.MESSAGE_TAMPERED, "invalid OT reply element");
        }
        return element;
    }
}

package com.github.guoyyit.oblivioustransferjava.service;

import com.github.guoyyit.oblivioustransferjava.crypto.CryptoRandom;
import com.github.guoyyit.oblivioustransferjava.crypto.DhBaseOt;
import com.github.guoyyit.oblivioustransferjava.crypto.Iknp;
import com.github.guoyyit.oblivioustransferjava.crypto.Kdf;
import com.github.guoyyit.oblivioustransferjava.crypto.SafePrimeGroup;
import com.github.guoyyit.oblivioustransferjava.protocol.ErrorCode;
import com.github.guoyyit.oblivioustransferjava.protocol.MessageType;
import com.github.guoyyit.oblivioustransferjava.protocol.OtException;
import com.github.guoyyit.oblivioustransferjava.protocol.ProtocolChannel;
import com.github.guoyyit.oblivioustransferjava.protocol.WireCodec;
import com.github.guoyyit.oblivioustransferjava.session.SessionRecord;
import com.github.guoyyit.oblivioustransferjava.session.SessionRegistry;
import com.github.guoyyit.oblivioustransferjava.session.SessionState;

import java.math.BigInteger;


/**
 * Receiver-side endpoint for one session.
 *
 * <p>Base mode runs the receiver side of pairCount DDH OTs.
 * Extension mode first commits the whole choice vector, then advances IKNP
 * batch by batch while acting as the base-OT sender: for each batch it encodes
 * the committed choice bits r into the correlation (T_j, T_j XOR r) of
 * k = {@link Iknp#BASE_COUNT} string OTs, delivered with AES-GCM over the
 * reusable DDH base keys (symmetric cryptography only). Only one batch of
 * chosen row keys is retained, and cancellation leaves no residual state.
 */
public final class ReceiverSession {

    private static final SafePrimeGroup GROUP = SafePrimeGroup.MODP_2048;

    private final SessionRecord record;
    private final SessionRegistry registry;
    private final ProtocolChannel channel;
    private final int pairCount;
    private final int batchSize;
    private final boolean extension;
    private final java.util.concurrent.atomic.AtomicBoolean cancelled =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private boolean[] choices;
    private byte[][][] baseOtKeyPairs = new byte[Iknp.BASE_COUNT][][];
    private int currentBatch = -1;
    private byte[][] batchKeys;
    private int batchStart;
    private int batchSizeActual;
    private boolean[] batchRedeemed;
    private int batchCursor;
    private boolean extensionDone;

    public ReceiverSession(SessionRecord record,
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

    /** Runs one base OT and returns the message selected by choiceBit. */
    public byte[] runBase(int choiceBit) {
        return runBaseBulk(new boolean[]{choiceBit == 1})[0];
    }

    /** Runs pairCount base OTs and returns the chosen messages in order. */
    public byte[][] runBaseBulk(boolean[] choiceVector) {
        validateMode(false);
        if (choiceVector == null || choiceVector.length != pairCount) {
            throw new OtException(ErrorCode.INVALID_PARAMETER,
                    "expected " + pairCount + " choice bits");
        }
        try {
            receiveInit(false);
            byte[][] results = new byte[pairCount][];
            for (int i = 0; i < pairCount; i++) {
                BigInteger senderPublic = readInitElement(
                        channel.receive(MessageType.OT_INIT));
                DhBaseOt.ReceiverReply reply = DhBaseOt.createReceiverReply(
                        GROUP, senderPublic, choiceVector[i] ? 1 : 0);
                channel.send(MessageType.OT_REPLY, WireCodec.encode(
                        new WireCodec.OtReplyPayload(reply.publicElement())));
                WireCodec.OtDataPayload data =
                        WireCodec.decodeOtData(channel.receive(MessageType.OT_PAYLOAD));
                results[i] = openChosen(data, reply.key(), choiceVector[i] ? 1 : 0);
            }
            complete();
            return results;
        } catch (OtException failure) {
            throw fail(failure);
        } catch (RuntimeException failure) {
            throw fail(new OtException(ErrorCode.INTERNAL_ERROR,
                    "receiver base OT failed", failure));
        }
    }

    /** Commits the full choice vector; the first extension batch becomes redeemable. */
    public void submitChoices(boolean[] choiceVector) {
        validateMode(true);
        if (choiceVector == null || choiceVector.length != pairCount) {
            throw new OtException(ErrorCode.CHOICE_OUT_OF_RANGE,
                    "expected " + pairCount + " choice bits");
        }
        this.choices = choiceVector.clone();
        try {
            receiveInit(true);
            runExtensionBasePhase();
            currentBatch = 0;
            materializeBatch(0);
        } catch (OtException failure) {
            throw fail(failure);
        } catch (RuntimeException failure) {
            throw fail(new OtException(ErrorCode.INTERNAL_ERROR,
                    "choice submission failed", failure));
        }
    }

    /** Redeems the chosen message at one global index. */
    public byte[] redeemOne(int index) {
        return redeemRange(index, 1)[0];
    }

    /** Redeems a contiguous range [offset, offset + length) of chosen messages. */
    public byte[][] redeemRange(int offset, int length) {
        validateMode(true);
        if (choices == null) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "choices not submitted");
        }
        if (offset < 0 || length <= 0 || offset + length > pairCount) {
            throw new OtException(ErrorCode.RANGE_OUT_OF_BOUNDS,
                    "redemption range out of bounds");
        }
        if (extensionDone || currentBatch < 0) {
            throw new OtException(ErrorCode.SESSION_CLOSED, "session not redeemable");
        }
        int batchIndex = offset / batchSize;
        if (batchIndex != currentBatch) {
            throw new OtException(ErrorCode.REDEMPTION_CONFLICT,
                    "batch " + currentBatch + " must be fully redeemed before batch "
                            + batchIndex);
        }
        int localOffset = offset - batchStart;
        if (localOffset != batchCursor) {
            throw new OtException(ErrorCode.REDEMPTION_CONFLICT,
                    "redemption must continue at local index " + batchCursor
                            + " without gaps, got " + localOffset);
        }
        if (localOffset + length > batchSizeActual) {
            throw new OtException(ErrorCode.RANGE_OUT_OF_BOUNDS,
                    "range crosses the end of the current batch");
        }
        for (int i = localOffset; i < localOffset + length; i++) {
            if (batchRedeemed[i]) {
                throw new OtException(ErrorCode.REDEMPTION_CONFLICT,
                        "message at index " + (batchStart + i) + " already redeemed");
            }
        }
        try {
            channel.send(MessageType.REDEEM_REQUEST, WireCodec.encode(
                    new WireCodec.RedeemRequestPayload(offset, length)));
            WireCodec.RedeemResponsePayload response = WireCodec.decodeRedeemResponse(
                    channel.receive(MessageType.REDEEM_RESPONSE));
            if (response.items().length != length) {
                throw new OtException(ErrorCode.TRUNCATED_MESSAGE, "short redemption response");
            }
            byte[][] messages = new byte[length][];
            for (int i = 0; i < length; i++) {
                int local = localOffset + i;
                messages[i] = openChosen(response.items()[i], batchKeys[local],
                        choices[batchStart + local] ? 1 : 0);
                batchRedeemed[local] = true;
            }
            batchCursor += length;
            if (isBatchFullyRedeemed()) {
                // The last redemption response is consumed first; only now can
                // the next batch's EXT_BATCH exchange begin.
                prepareNextBatch();
            }
            return messages;
        } catch (OtException failure) {
            throw fail(failure);
        } catch (RuntimeException failure) {
            throw fail(new OtException(ErrorCode.INTERNAL_ERROR, "redemption failed", failure));
        }
    }

    /** Cancels an in-progress extension; no observable intermediate state remains. */
    public void cancel() {
        validateMode(true);
        cancelled.set(true);
        channel.sendAbort();
        channel.close();
        clearBatch();
        record.markAborted("cancelled by receiver");
        registry.tombstone(record.id());
    }

    /** Aborts the session explicitly. */
    public void abort() {
        cancelled.set(true);
        channel.sendAbort();
        channel.close();
        clearBatch();
        record.markAborted("locally aborted");
        registry.tombstone(record.id());
    }

    // ------------------------------------------------------------------
    // Extension internals
    // ------------------------------------------------------------------

    /**
     * Runs the k DDH base OTs with reversed roles. The message receiver is the
     * base-OT sender and retains both keys (k0_j, k1_j) of each pair.
     */
    private void runExtensionBasePhase() {
        for (int j = 0; j < Iknp.BASE_COUNT; j++) {
            DhBaseOt.SenderInit init = DhBaseOt.createSenderInit(GROUP);
            channel.send(MessageType.OT_INIT, WireCodec.encode(
                    new WireCodec.OtInitPayload(init.publicElement())));
            BigInteger replyElement = readReplyElement(
                    channel.receive(MessageType.OT_REPLY));
            baseOtKeyPairs[j] = DhBaseOt.deriveSenderKeys(GROUP, init, replyElement);
        }
    }

    /**
     * Materializes one IKNP batch: seals correlated strings (T_j, T_j XOR r)
     * under the reusable base keys and retains the chosen row keys.
     */
    private void materializeBatch(int batch) {
        int offset = batch * batchSize;
        int batchCount = (pairCount + batchSize - 1) / batchSize;
        int size = batch == batchCount - 1 ? pairCount - offset : batchSize;
        byte[] r = packChoices(offset, size);
        byte[][] tColumns = new byte[Iknp.BASE_COUNT][];

        WireCodec.Sealed[][] sealed = new WireCodec.Sealed[Iknp.BASE_COUNT][];
        for (int j = 0; j < Iknp.BASE_COUNT; j++) {
            byte[] t = Iknp.randomBitString(size);
            tColumns[j] = t;
            byte[] u = Iknp.xorBitStrings(t, r);
            sealed[j] = new WireCodec.Sealed[]{
                    sealWith(baseOtKeyPairs[j][0], t),
                    sealWith(baseOtKeyPairs[j][1], u)
            };
        }
        channel.send(MessageType.EXT_BATCH, WireCodec.encode(
                new WireCodec.ExtBatchPayload(batch, sealed)));

        byte[][] tRows = Iknp.transpose(tColumns, size);
        batchKeys = new byte[size][];
        for (int i = 0; i < size; i++) {
            int side = choices[offset + i] ? 1 : 0;
            batchKeys[i] = Iknp.rowKey(tRows[i], offset + i, side);
        }
        batchStart = offset;
        batchSizeActual = size;
        batchRedeemed = new boolean[size];
        batchCursor = 0;
        currentBatch = batch;
    }

    private void prepareNextBatch() {
        channel.receive(MessageType.EXT_BATCH);
        int nextBatch = currentBatch + 1;
        int batchCount = (pairCount + batchSize - 1) / batchSize;
        clearBatch();
        if (nextBatch >= batchCount) {
            extensionDone = true;
            complete();
        } else {
            materializeBatch(nextBatch);
        }
    }

    private boolean isBatchFullyRedeemed() {
        for (boolean redeemed : batchRedeemed) {
            if (!redeemed) {
                return false;
            }
        }
        return true;
    }

    private void clearBatch() {
        batchKeys = null;
        batchRedeemed = null;
    }

    private byte[] packChoices(int offset, int size) {
        byte[] packed = new byte[Iknp.packedBytes(size)];
        for (int i = 0; i < size; i++) {
            if (choices[offset + i]) {
                Iknp.setBit(packed, i, 1);
            }
        }
        return packed;
    }

    private WireCodec.Sealed sealWith(byte[] key, byte[] plaintext) {
        byte[] nonce = CryptoRandom.randomBytes(Kdf.nonceLength());
        return new WireCodec.Sealed(nonce, Kdf.seal(key, nonce, plaintext));
    }

    private byte[] openChosen(WireCodec.OtDataPayload data, byte[] key, int side) {
        WireCodec.Sealed sealed = side == 0 ? data.first() : data.second();
        try {
            return Kdf.open(key, sealed.nonce(), sealed.ciphertext());
        } catch (IllegalArgumentException e) {
            throw new OtException(ErrorCode.MESSAGE_TAMPERED,
                    "chosen message failed authentication", e);
        }
    }

    private void receiveInit(boolean expectExtension) {
        WireCodec.InitPayload init = WireCodec.decodeInit(channel.receive(MessageType.INIT));
        if (init.extension() != expectExtension
                || init.pairs() != pairCount
                || init.batchSize() != batchSize
                || (expectExtension && init.baseCount() != Iknp.BASE_COUNT)) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "init parameters mismatch");
        }
        channel.send(MessageType.INIT_ACK, new byte[0]);
    }

    private void complete() {
        if (record.transitionTo(SessionState.COMPLETED)) {
            baseOtKeyPairs = null;
            clearBatch();
            registry.tombstone(record.id());
            channel.close();
        }
    }

    private OtException fail(OtException error) {
        channel.sendError(error.errorCode(), error.getMessage());
        channel.close();
        baseOtKeyPairs = null;
        clearBatch();
        record.markAborted(error.getMessage());
        registry.tombstone(record.id());
        return error;
    }

    private void validateMode(boolean expectExtension) {
        if (extension != expectExtension) {
            throw new OtException(ErrorCode.PROTOCOL_VIOLATION, "wrong session mode");
        }
        if (cancelled.get()) {
            throw new OtException(ErrorCode.CANCELLED, "session was cancelled");
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

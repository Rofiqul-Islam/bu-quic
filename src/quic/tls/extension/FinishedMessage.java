package quic.tls.extension;

import quic.tls.HandshakeMessage;
import quic.tls.TlsConstants;
import quic.tls.TlsState;

import java.nio.ByteBuffer;

public class FinishedMessage extends HandshakeMessage {
    private byte[] data;

    public FinishedMessage() {}

    public FinishedMessage(TlsState state) {
        byte[] hmac = state.computeHandshakeFinishedHmac(false);
        int remainingLength = hmac.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 + remainingLength);
        buffer.put(TlsConstants.HandshakeType.finished.value);
        buffer.put((byte)0);
        buffer.putShort((short)remainingLength);
        buffer.put(hmac);
        this.data = buffer.array();
        state.setClientFinished(this.data);
    }

    public FinishedMessage parse(ByteBuffer buffer, int length, TlsState state) {
        System.out.println("Got Finished message (" + length + " bytes)");
        byte[] raw = new byte[length];
        buffer.get(raw);
        state.setServerFinished(raw);
        return this;
    }

    public byte[] getBytes() {
        return this.data;
    }
}
package quic.tls.extension;

import quic.tls.HandshakeMessage;
import quic.tls.TlsState;

import java.nio.ByteBuffer;

public class CertificateVerifyMessage extends HandshakeMessage {
    public CertificateVerifyMessage parse(ByteBuffer buffer, int length, TlsState state) {
        System.out.println("Got Certificate Verify message( " + length + " bytes)");
        byte[] raw = new byte[length];
        buffer.get(raw);
        state.setCertificateVerify(raw);
        return this;
    }

    public byte[] getBytes() {
        return new byte[0];
    }
}
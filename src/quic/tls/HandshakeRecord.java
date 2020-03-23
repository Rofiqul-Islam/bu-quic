package quic.tls;


import quic.tls.extension.CertificateVerifyMessage;
import quic.tls.extension.EncryptedExtensions;
import quic.tls.extension.FinishedMessage;

import java.io.EOFException;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class HandshakeRecord {
    private byte[] data;

    private List<HandshakeMessage> messages = new ArrayList<>();

    public HandshakeRecord() {}

    public HandshakeRecord(ClientHello clientHello) {
        byte[] clientHelloData = clientHello.getBytes();
        ByteBuffer buffer = ByteBuffer.allocate(5 + clientHelloData.length);
        buffer.put(TlsConstants.ContentType.handshake.value);
        buffer.putShort((short)769);
        buffer.putShort((short)clientHelloData.length);
        buffer.put(clientHelloData);
        this.data = buffer.array();
    }

    public HandshakeRecord parse(PushbackInputStream input, TlsState state) throws Exception {
        input.read();
        int versionHigh = input.read();
        int versionLow = input.read();
        if (versionHigh != 3 || versionLow != 3)
            throw new EOFException("Invalid version number (should be 0x0303");
        int length = input.read() << 8 | input.read();
        byte[] data = new byte[length];
        int count = input.read(data);
        while (count != length)
            count += input.read(data, count, length - count);
        ByteBuffer buffer = ByteBuffer.wrap(data);
        while (buffer.remaining() > 0) {
            HandshakeMessage message = parseHandshakeMessage(buffer, state);
            this.messages.add(message);
        }
        return this;
    }

    public static HandshakeMessage parseHandshakeMessage(ByteBuffer buffer, TlsState state) throws Exception {
        HandshakeMessage msg;
        buffer.mark();
        int messageType = buffer.get();
        int length = (buffer.get() & 0xFF) << 16 | (buffer.get() & 0xFF) << 8 | buffer.get() & 0xFF;
        buffer.reset();
        if (messageType == TlsConstants.HandshakeType.server_hello.value) {
            msg = (new ServerHello()).parse(buffer, length + 4, state);
        } else if (messageType == TlsConstants.HandshakeType.encrypted_extensions.value) {
            msg = (new EncryptedExtensions()).parse(buffer, length + 4, state);
        } else if (messageType == TlsConstants.HandshakeType.certificate.value) {
            msg = (new CertificateMessage()).parse(buffer, length + 4, state);
        } else if (messageType == TlsConstants.HandshakeType.certificate_verify.value) {
            msg = (new CertificateVerifyMessage()).parse(buffer, length + 4, state);
        } else if (messageType == TlsConstants.HandshakeType.finished.value) {
            msg = (new FinishedMessage()).parse(buffer, length + 4, state);
        } else if (messageType == TlsConstants.HandshakeType.new_session_ticket.value) {
            msg = (new NewSessionTicketMessage()).parse(buffer, length + 4, state);
        } else {
            throw new Exception("Invalid/unsupported handshake message type (" + messageType + ")");
        }
        return msg;
    }

    public byte[] getBytes() {
        return this.data;
    }

    public List<HandshakeMessage> getMessages() {
        return this.messages;
    }
}

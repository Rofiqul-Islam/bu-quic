package quic.tls;

public abstract class HandshakeMessage extends Message {
    public abstract byte[] getBytes();
}
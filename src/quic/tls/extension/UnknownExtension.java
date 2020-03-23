package quic.tls.extension;

import java.nio.ByteBuffer;

public class UnknownExtension extends Extension {
    private byte[] data;

    public UnknownExtension parse(ByteBuffer buffer) {
        buffer.mark();
        buffer.getShort();
        int length = buffer.getShort();
        buffer.reset();
        this.data = new byte[4 + length];
        buffer.get(this.data);
        return this;
    }

    public byte[] getData() {
        return this.data;
    }

    public byte[] getBytes() {
        return new byte[0];
    }
}
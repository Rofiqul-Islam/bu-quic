package quic.tls.extension;

import java.nio.ByteBuffer;

public class ServerPreSharedKeyExtension extends Extension {
    private int selectedIdentity;

    public ServerPreSharedKeyExtension parse(ByteBuffer buffer) {
        buffer.getShort();
        int extensionDataLength = buffer.getShort();
        this.selectedIdentity = buffer.getShort();
        return this;
    }

    public byte[] getBytes() {
        return new byte[0];
    }

    public int getSelectedIdentity() {
        return this.selectedIdentity;
    }
}


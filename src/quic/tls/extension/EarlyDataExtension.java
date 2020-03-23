package quic.tls.extension;

import quic.tls.TlsConstants;

import java.nio.ByteBuffer;

public class EarlyDataExtension extends Extension {
    private Long maxEarlyDataSize;

    public Extension parse(ByteBuffer buffer) {
        int extensionType = buffer.getShort();
        if (extensionType != TlsConstants.ExtensionType.early_data.value)
            throw new RuntimeException();
        int extensionLength = buffer.getShort();
        if (extensionLength == 4)
            this.maxEarlyDataSize = Long.valueOf(buffer.getInt() & 0xFFFFFFFFL);
        return this;
    }

    public byte[] getBytes() {
        int extensionDataLength = (this.maxEarlyDataSize == null) ? 0 : 4;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionDataLength);
        buffer.putShort(TlsConstants.ExtensionType.early_data.value);
        buffer.putShort((short)extensionDataLength);
        if (this.maxEarlyDataSize != null)
            buffer.putInt((int)this.maxEarlyDataSize.longValue());
        return buffer.array();
    }

    public long getMaxEarlyDataSize() {
        return this.maxEarlyDataSize.longValue();
    }

    public String toString() {
        return "EarlyDataExtension " + ((this.maxEarlyDataSize == null) ? "(empty)" : ("[" + this.maxEarlyDataSize + "]"));
    }
}
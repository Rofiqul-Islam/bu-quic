package quic.tls.extension;


import quic.tls.TlsConstants;

import java.nio.ByteBuffer;

public class SupportedVersionsExtension extends Extension {
    private short tlsVersion;

    public SupportedVersionsExtension parse(ByteBuffer buffer) throws Exception {
        buffer.getShort();
        int extensionDataLength = buffer.getShort();
        if (extensionDataLength != 2)
            throw new Exception("Incorrect extension length");
        this.tlsVersion = buffer.getShort();
        return this;
    }

    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(7);
        buffer.putShort(TlsConstants.ExtensionType.supported_versions.value);
        buffer.putShort((short)3);
        buffer.put((byte)2);
        buffer.put(new byte[] { 3, 4 });
        return buffer.array();
    }

    public short getTlsVersion() {
        return this.tlsVersion;
    }
}
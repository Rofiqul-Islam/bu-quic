package quic.tls.extension;

import quic.tls.TlsConstants;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

public class ApplicationLayerProtocolNegotiationExtension extends Extension {
    private final byte[] data;

    private List<String> protocols;

    public ApplicationLayerProtocolNegotiationExtension() {
        this.data = null;
    }

    public ApplicationLayerProtocolNegotiationExtension(String protocol) {
        byte[] protocolName = protocol.getBytes(Charset.forName("UTF-8"));
        ByteBuffer buffer = ByteBuffer.allocate(7 + protocolName.length);
        buffer.putShort(TlsConstants.ExtensionType.application_layer_protocol_negotiation.value);
        buffer.putShort((short)(byte)(3 + protocolName.length));
        buffer.putShort((short)(byte)(1 + protocolName.length));
        buffer.put((byte)protocolName.length);
        buffer.put(protocolName);
        this.data = new byte[buffer.limit()];
        buffer.flip();
        buffer.get(this.data);
    }

    public ApplicationLayerProtocolNegotiationExtension parse(ByteBuffer buffer) {
        int extensionType = buffer.getShort();
        if (extensionType != TlsConstants.ExtensionType.application_layer_protocol_negotiation.value)
            throw new RuntimeException();
        int extensionLength = buffer.getShort();
        int protocolsLength = buffer.getShort();
        this.protocols = new ArrayList<>();
        while (protocolsLength > 0) {
            int protocolNameLength = buffer.get() & 0xFF;
            byte[] protocolBytes = new byte[protocolNameLength];
            buffer.get(protocolBytes);
            this.protocols.add(new String(protocolBytes));
            protocolsLength -= 1 + protocolNameLength;
        }
        return this;
    }

    public byte[] getBytes() {
        return this.data;
    }

    public String toString() {
        return "AlpnExtension " + this.protocols;
    }
}


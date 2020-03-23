package quic.tls.extension;

import quic.tls.TlsConstants;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class ServerNameExtension extends Extension {
    private final String serverName;

    public ServerNameExtension(String serverName) {
        this.serverName = serverName;
    }

    public byte[] getBytes() {
        short hostnameLength = (short)this.serverName.length();
        short extensionLength = (short)(hostnameLength + 2 + 1 + 2);
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.server_name.value);
        buffer.putShort(extensionLength);
        buffer.putShort((short)(hostnameLength + 1 + 2));
        buffer.put((byte)0);
        buffer.putShort(hostnameLength);
        buffer.put(this.serverName.getBytes(Charset.forName("ISO-8859-1")));
        return buffer.array();
    }
}

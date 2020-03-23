package quic.tls.extension;

import quic.tls.TlsConstants;

import java.nio.ByteBuffer;

public class PskKeyExchangeModesExtension extends Extension {
    public byte[] getBytes() {
        short extensionLength = 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.psk_key_exchange_modes.value);
        buffer.putShort(extensionLength);
        buffer.put((byte)1);
        buffer.put(TlsConstants.PskKeyExchangeMode.psk_dhe_ke.value);
        return buffer.array();
    }
}

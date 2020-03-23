package quic.tls.extension;

import quic.tls.HandshakeMessage;
import quic.tls.KeyShareExtension;
import quic.tls.TlsConstants;
import quic.tls.TlsState;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class EncryptedExtensions extends HandshakeMessage {
    private List<Extension> extensions;

    public EncryptedExtensions parse(ByteBuffer buffer, int length, TlsState state) throws Exception {
        System.out.println("Got Encrypted Extensions message (" + length + " bytes)");
        byte[] raw = new byte[length];
        buffer.mark();
        buffer.get(raw);
        state.setEncryptedExtensions(raw);
        buffer.reset();
        buffer.getInt();
        this.extensions = parseExtensions(buffer);
        return this;
    }

    public static List<Extension> parseExtensions(ByteBuffer buffer) throws Exception {
        List<Extension> extensions = new ArrayList<>();
        int extensionsLength = buffer.getShort();
        if (extensionsLength > 0) {
            int startPosition = buffer.position();
            while (buffer.position() - startPosition < extensionsLength) {
                buffer.mark();
                int extensionType = buffer.getShort() & 0xFFFF;
                buffer.reset();
                if (extensionType == TlsConstants.ExtensionType.key_share.value) {
                    extensions.add((new KeyShareExtension()).parse(buffer));
                    continue;
                }
                if (extensionType == TlsConstants.ExtensionType.supported_versions.value) {
                    extensions.add((new SupportedVersionsExtension()).parse(buffer));
                    continue;
                }
                if (extensionType == TlsConstants.ExtensionType.pre_shared_key.value) {
                    extensions.add((new ServerPreSharedKeyExtension()).parse(buffer));
                    continue;
                }
                if (extensionType == TlsConstants.ExtensionType.early_data.value) {
                    extensions.add((new EarlyDataExtension()).parse(buffer));
                    continue;
                }
                if (extensionType == TlsConstants.ExtensionType.application_layer_protocol_negotiation.value) {
                    extensions.add((new ApplicationLayerProtocolNegotiationExtension()).parse(buffer));
                    continue;
                }
                System.out.println("Unsupported extension, type is: " + extensionType);
                extensions.add((new UnknownExtension()).parse(buffer));
            }
        }
        return extensions;
    }

    public List<Extension> getExtensions() {
        return this.extensions;
    }

    public byte[] getBytes() {
        return new byte[0];
    }
}

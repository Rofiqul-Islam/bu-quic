package quic.tls;

import quic.tls.extension.EncryptedExtensions;
import quic.tls.extension.Extension;
import quic.tls.extension.ServerPreSharedKeyExtension;
import quic.tls.extension.SupportedVersionsExtension;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

public class ServerHello extends HandshakeMessage {
    static byte[] HelloRetryRequest_SHA256 = new byte[] {
            -49, 33, -83, 116, -27, -102, 97, 17, -66, 29,
            -116, 2, 30, 101, -72, -111, -62, -94, 17, 22,
            122, -69, -116, 94, 7, -98, 9, -30, -56, -88,
            51, -100 };

    private byte[] raw;

    private byte[] random;

    private String cipherSuite;

    private String keyGroup;

    private byte[] serverSharedKey;

    private short tlsVersion;

    public ServerHello parse(ByteBuffer buffer, int length, TlsState state) throws Exception {
        buffer.getInt();
        int versionHigh = buffer.get();
        int versionLow = buffer.get();
        if (versionHigh != 3 || versionLow != 3)
            throw new Exception("Invalid version number (should be 0x0303");
        this.random = new byte[32];
        buffer.get(this.random);
        if (Arrays.equals(this.random, HelloRetryRequest_SHA256))
            System.out.println("HelloRetryRequest!");
        int sessionIdLength = buffer.get();
        byte[] legacySessionIdEcho = new byte[sessionIdLength];
        buffer.get(legacySessionIdEcho);
        int cipherSuiteCode = buffer.getShort();
        switch (cipherSuiteCode) {
            case 4865:
                this.cipherSuite = "TLS_AES_128_GCM_SHA256";
                break;
            case 4866:
                this.cipherSuite = "TLS_AES_256_GCM_SHA384";
                break;
            case 4867:
                this.cipherSuite = "TLS_CHACHA20_POLY1305_SHA256";
                break;
            case 4868:
                this.cipherSuite = "TLS_AES_128_CCM_SHA256";
                break;
            case 4869:
                this.cipherSuite = "TLS_AES_128_CCM_8_SHA256";
                break;
            default:
                throw new Exception("Unknown cipher suite (" + cipherSuiteCode + ")");
        }
        int legacyCompressionMethod = buffer.get();
        List<Extension> extensions = EncryptedExtensions.parseExtensions(buffer);
        extensions.stream().forEach(extension -> {
            if (extension instanceof KeyShareExtension) {
                this.serverSharedKey = ((KeyShareExtension)extension).getServerSharedKey();
            } else if (extension instanceof SupportedVersionsExtension) {
                this.tlsVersion = ((SupportedVersionsExtension)extension).getTlsVersion();
            } else if (extension instanceof ServerPreSharedKeyExtension) {
                state.setPskSelected(((ServerPreSharedKeyExtension)extension).getSelectedIdentity());
            }
        });
        if (this.tlsVersion != 772)
            throw new Exception("Invalid TLS version");
        this.raw = new byte[length];
        buffer.rewind();
        buffer.get(this.raw);
        state.setServerSharedKey(this.raw, this.serverSharedKey);
        return this;
    }

    public byte[] getBytes() {
        return new byte[0];
    }
}

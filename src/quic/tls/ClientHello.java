package quic.tls;


import quic.tls.extension.*;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class ClientHello extends HandshakeMessage {
    private static final int MAX_CLIENT_HELLO_SIZE = 3000;

    public static final byte[][] SUPPORTED_CIPHERS = new byte[][] { TlsConstants.TLS_AES_128_GCM_SHA256, TlsConstants.TLS_AES_256_GCM_SHA384 };

    private static Random random = new Random();

    private static SecureRandom secureRandom = new SecureRandom();

    private final byte[] data;

    private byte[] clientRandom;

    public ClientHello(String serverName, ECPublicKey publicKey) {
        this(serverName, publicKey, true, SUPPORTED_CIPHERS, Collections.emptyList());
    }

    public ClientHello(String serverName, ECPublicKey publicKey, boolean compatibilityMode, List<Extension> extraExtensions) {
        this(serverName, publicKey, compatibilityMode, SUPPORTED_CIPHERS, extraExtensions);
    }

    public ClientHello(String serverName, ECPublicKey publicKey, boolean compatibilityMode, byte[][] supportedCiphers, List<Extension> extraExtensions) {
        byte[] sessionId;
        ByteBuffer buffer = ByteBuffer.allocate(3000);
        buffer.put((byte)1);
        byte[] length = new byte[3];
        buffer.put(length);
        buffer.put((byte)3);
        buffer.put((byte)3);
        this.clientRandom = new byte[32];
        secureRandom.nextBytes(this.clientRandom);
        buffer.put(this.clientRandom);
        if (compatibilityMode) {
            sessionId = new byte[32];
            random.nextBytes(sessionId);
        } else {
            sessionId = new byte[0];
        }
        buffer.put((byte)sessionId.length);
        if (sessionId.length > 0)
            buffer.put(sessionId);
        buffer.putShort((short)(supportedCiphers.length * 2));
        for (byte[] cipher : supportedCiphers)
            buffer.put(cipher);
        buffer.put(new byte[] { 1, 0 });
        Extension[] defaultExtensions = { new ServerNameExtension(serverName), new SupportedVersionsExtension(), new SupportedGroupsExtension(), new SignatureAlgorithmsExtension(), new KeyShareExtension(publicKey, "secp256r1"), new PskKeyExchangeModesExtension() };
        List<Extension> extensions = new ArrayList<>();
        extensions.addAll(List.of(defaultExtensions));
        extensions.addAll(extraExtensions);
        int pskExtensionStartPosition = 0;
        ClientHelloPreSharedKeyExtension pskExtension = null;
        int extensionsLength = extensions.stream().mapToInt(ext -> (ext.getBytes()).length).sum();
        buffer.putShort((short)extensionsLength);
        for (Extension extension : extensions) {
            if (extension instanceof ClientHelloPreSharedKeyExtension) {
                pskExtension = (ClientHelloPreSharedKeyExtension)extension;
                pskExtensionStartPosition = buffer.position();
            }
            buffer.put(extension.getBytes());
        }
        buffer.limit(buffer.position());
        int clientHelloLength = buffer.position() - 4;
        buffer.putShort(2, (short)clientHelloLength);
        this.data = new byte[clientHelloLength + 4];
        buffer.rewind();
        buffer.get(this.data);
        if (pskExtension != null) {
            pskExtension.calculateBinder(this.data, pskExtensionStartPosition);
            buffer.position(pskExtensionStartPosition);
            buffer.put(pskExtension.getBytes());
            buffer.rewind();
            buffer.get(this.data);
        }
    }

    public byte[] getBytes() {
        return this.data;
    }

    public byte[] getClientRandom() {
        return this.clientRandom;
    }
}


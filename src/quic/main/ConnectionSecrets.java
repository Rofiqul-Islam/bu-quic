
package quic.main;

import at.favre.lib.crypto.HKDF;

import net.luminis.tls.ByteUtils;
import quic.log.Logger;
import net.luminis.tls.TlsState;
import quic.util.Util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

public class ConnectionSecrets {

    enum NodeRole {
        Client,
        Server
    }

    // https://tools.ietf.org/html/draft-ietf-quic-tls-23#section-5.2
    public static final byte[] STATIC_SALT_DRAFT_23 = new byte[] {
            (byte) 0xc3, (byte) 0xee, (byte) 0xf7, (byte) 0x12, (byte) 0xc7, (byte) 0x2e, (byte) 0xbb, (byte) 0x5a,
            (byte) 0x11, (byte) 0xa7, (byte) 0xd2, (byte) 0x43, (byte) 0x2b, (byte) 0xb4, (byte) 0x63, (byte) 0x65,
            (byte) 0xbe, (byte) 0xf9, (byte) 0xf5, (byte) 0x02 };

    private final Version quicVersion;
    private Logger log;
    private byte[] clientRandom;
    private Keys[] clientSecrets = new Keys[quic.main.EncryptionLevel.values().length];
    private Keys[] serverSecrets = new Keys[quic.main.EncryptionLevel.values().length];
    private boolean writeSecretsToFile;
    private Path wiresharkSecretsFile;


    public ConnectionSecrets(Version quicVersion, Path wiresharksecrets, Logger log) {
        this.quicVersion = quicVersion;
        this.log = log;

        if (wiresharksecrets != null) {
            wiresharkSecretsFile = wiresharksecrets;
            try {
                Files.deleteIfExists(wiresharkSecretsFile);
                Files.createFile(wiresharkSecretsFile);
                writeSecretsToFile = true;
            } catch (IOException e) {
                log.error("Initializing (creating/truncating) secrets file '" + wiresharkSecretsFile + "' failed", e);
            }
        }
    }

    /**
     * Generate the initial secrets
     *
     * @param destConnectionId
     */
    public synchronized void computeInitialKeys(byte[] destConnectionId) {

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.2:
        // "The hash function for HKDF when deriving initial secrets and keys is SHA-256"
        HKDF hkdf = HKDF.fromHmacSha256();

        byte[] initialSalt = STATIC_SALT_DRAFT_23;
        byte[] initialSecret = hkdf.extract(initialSalt, destConnectionId);

        log.secret("Initial secret", initialSecret);

        clientSecrets[quic.main.EncryptionLevel.Initial.ordinal()] = new Keys(quicVersion, initialSecret, NodeRole.Client, log);
        serverSecrets[EncryptionLevel.Initial.ordinal()] = new Keys(quicVersion, initialSecret, NodeRole.Server, log);
    }

    public synchronized void computeHandshakeSecrets(TlsState tlsState) {
        Keys handshakeSecrets = new Keys(quicVersion, NodeRole.Client, log);
        handshakeSecrets.computeHandshakeKeys(tlsState);
        clientSecrets[EncryptionLevel.Handshake.ordinal()] = handshakeSecrets;

        handshakeSecrets = new Keys(quicVersion, NodeRole.Server, log);
        handshakeSecrets.computeHandshakeKeys(tlsState);
        serverSecrets[EncryptionLevel.Handshake.ordinal()] = handshakeSecrets;

        if (writeSecretsToFile) {
            appendToFile("HANDSHAKE_TRAFFIC_SECRET", EncryptionLevel.Handshake);
        }
    }

    public synchronized void computeApplicationSecrets(TlsState tlsState) {
        Keys applicationSecrets = new Keys(quicVersion, NodeRole.Client, log);
        applicationSecrets.computeApplicationKeys(tlsState);
        clientSecrets[EncryptionLevel.App.ordinal()] = applicationSecrets;

        applicationSecrets = new Keys(quicVersion, NodeRole.Server, log);
        applicationSecrets.computeApplicationKeys(tlsState);
        serverSecrets[EncryptionLevel.App.ordinal()] = applicationSecrets;
        
        if (writeSecretsToFile) {
            appendToFile("TRAFFIC_SECRET_0", EncryptionLevel.App);
        }
    }

    private void appendToFile(String label, EncryptionLevel level) {
        List<String> content = new ArrayList<>();
        content.add("CLIENT_" + label + " "
                + ByteUtils.bytesToHex(clientRandom) + " "
                + ByteUtils.bytesToHex(clientSecrets[level.ordinal()].getTrafficSecret()));
        content.add("SERVER_" + label + " "
                + ByteUtils.bytesToHex(clientRandom) + " "
                + ByteUtils.bytesToHex(serverSecrets[level.ordinal()].getTrafficSecret()));

        try {
            Files.write(wiresharkSecretsFile, content, StandardOpenOption.APPEND);
        } catch (IOException e) {
            log.error("Writing secrets to file '" + wiresharkSecretsFile + "' failed", e);
            writeSecretsToFile = false;
        }
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    public synchronized Keys getClientSecrets(EncryptionLevel encryptionLevel) {
        return clientSecrets[encryptionLevel.ordinal()];
    }

    public synchronized Keys getServerSecrets(EncryptionLevel encryptionLevel) {
        return serverSecrets[encryptionLevel.ordinal()];
    }
}

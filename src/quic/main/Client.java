package quic.main;
import net.luminis.tls.*;
import quic.exception.QuicException;
import quic.frame.QuicCryptoFrame;
import quic.frame.QuicFrame;
import quic.log.Logger;
import quic.packet.QuicInitialPacket;
import quic.packet.QuicPacket;
import quic.util.Util;

import java.io.IOException;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import quic.log.*;

import javax.crypto.spec.SecretKeySpec;

import static net.luminis.tls.Tls13.generateKeys;

/**
 *
 *
 * @author Rofiqul Islam
 */

public class Client {
    public static ECPrivateKey privateKey;
    public static ECPublicKey publicKey=null;
    public static ConnectionSecrets connectionSecrets = null;
    private static Logger log;
    private static String applicationProtocol = null;
    public static String connectionId="104.17.209.9";
    // public static String connectionId="185.92.221.97";
    public static int port = 443;
    private static Version quicVersion= Version.IETF_draft_25;
    public static TlsState tlsState;
    public static NewSessionTicket sessionTicket;
    public static String destianation = "bd22d8d0e964c1add9f75fb9303567b3002b654b";
    public static DatagramSocket ds;
    public static void main(String args[]) throws IOException, QuicException {

        try {
            SysOutLogger logger = new SysOutLogger();
            logger.logInfo(true);
            logger.logCongestionControl(true);
            logger.logRecovery(true);
            Path path = Paths.get("C:\\Datacom\\qq\\quic\\src\\quic\\secrets\\");
            connectionSecrets = new ConnectionSecrets(Version.IETF_draft_25, path, logger);
            ECKey[] keys = generateKeys("secp256r1");
            //ECKey[] keys = generateKeys("X25519");
            privateKey = (ECPrivateKey) keys[0];
            publicKey = (ECPublicKey) keys[1];
            tlsState = new QuicTlsState(quicVersion);
            System.out.println("Created client public key and private key");
            ds = new DatagramSocket();
        } catch (Exception e) {
            throw new QuicException(0,0,"Runtime exception");
        }
        connect(1000, null);

    }
    public static synchronized void connect(int connectionTimeout, String applicationProtocol) throws IOException, QuicException {

        connectionSecrets.computeInitialKeys(Util.hexStringToByteArray(destianation,0));

        if(applicationProtocol == null){
            applicationProtocol = "h3-" + quicVersion.toString().substring(quicVersion.toString().length() - 2);

        }
        System.out.println("-----------handsahke-------------");
        startHandshake(applicationProtocol);
    }

    public static void startHandshake(String applicationProtocol) throws QuicException, IOException {
        TransportParameters transportParameters = new TransportParameters(30,250_000,3,3);
        byte[] clientHello = createClientHello(connectionId, publicKey, applicationProtocol,transportParameters);
        SecretKeySpec secretKey = new SecretKeySpec(connectionSecrets.getServerSecrets(EncryptionLevel.Initial).getWriteKey(), "AES");

        tlsState.clientHelloSend(privateKey, clientHello);
        QuicFrame cryptoFrame = new QuicCryptoFrame(0,clientHello);
        QuicInitialPacket clientHelloPacket = (QuicInitialPacket) Util.createPacket(EncryptionLevel.Initial, cryptoFrame,Util.hexStringToByteArray(destianation,0),1,4278190080L+25,"12".getBytes());
        System.out.println("Created Client Hello");

       // InetAddress ip = InetAddress.getByName("216.155.158.183");
        InetAddress ip  = InetAddress.getByName(connectionId);
        byte buf[] = clientHelloPacket.specialEncode();
        Sender sender = new Sender(ip,port,buf);
        Thread sendThread  = new Thread(sender);
        Reciever reciever = new Reciever();
        Thread recieveThread = new Thread(reciever);
        sendThread.start();
        recieveThread.start();

    }

    public static byte[] createClientHello(String host, ECPublicKey publicKey, String alpnProtocol, TransportParameters transportParams) {
        boolean compatibilityMode = true;
        byte[][] supportedCiphers = new byte[][]{ TlsConstants.TLS_AES_256_GCM_SHA384 };

        List<Extension> quicExtensions = new ArrayList<>();
        quicExtensions.add(new QuicTransportParametersExtension(Version.IETF_draft_25, transportParams));
        quicExtensions.add(new ApplicationLayerProtocolNegotiationExtension(alpnProtocol));

        if (sessionTicket != null) {
            quicExtensions.add(new ClientHelloPreSharedKeyExtension(tlsState, sessionTicket));
        }

        ClientHello clientHello = new ClientHello(host, publicKey, compatibilityMode, supportedCiphers, quicExtensions);
        connectionSecrets.setClientRandom(clientHello.getClientRandom());
        return clientHello.getBytes();
    }
}

package quic.tls;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TlsState {
    private static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

    private static byte[] P256_HEAD = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE");

    private final MessageDigest hashFunction;

    private final HKDF hkdf;

    private final byte[] emptyHash;

    private Status status;

    private String labelPrefix;

    private boolean pskSelected;

    private byte[] serverHello;

    private byte[] serverSharedKey;

    private PrivateKey clientPrivateKey;

    private byte[] clientHello;

    private byte[] psk;

    private byte[] earlySecret;

    private byte[] binderKey;

    private byte[] resumptionMasterSecret;

    private byte[] serverHandshakeTrafficSecret;

    private byte[] serverHandshakeKey;

    private byte[] serverHandshakeIV;

    private byte[] clientEarlyTrafficSecret;

    private byte[] clientHandshakeTrafficSecret;

    private byte[] encryptedExtensionsMessage;

    private byte[] certificateMessage;

    private byte[] certificateVerifyMessage;

    private byte[] serverFinishedMessage;

    private byte[] clientFinishedMessage;

    private byte[] clientHandshakeKey;

    private byte[] clientHandshakeIV;

    private byte[] handshakeSecret;

    private byte[] handshakeServerFinishedHash;

    private byte[] handshakeClientFinishedHash;

    private byte[] clientApplicationTrafficSecret;

    private byte[] serverApplicationTrafficSecret;

    private byte[] serverKey;

    private byte[] serverIv;

    private byte[] clientKey;

    private byte[] clientIv;

    enum Status {
        keyExchangeClient, keyExchangeServer, ServerParams, AuthServer, AuthServerFinished, AuthClient, AuthClientFinished, ApplicationData;
    }

    private int serverRecordCount = 0;

    private int clientRecordCount = 0;

    public TlsState(byte[] psk) {
        this("tls13 ", psk);
    }

    public TlsState(String alternativeLabelPrefix, byte[] psk) {
        this.labelPrefix = alternativeLabelPrefix;
        this.psk = psk;
        try {
            this.hashFunction = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing sha-256 support");
        }
        this.hkdf = HKDF.fromHmacSha256();
        this.emptyHash = this.hashFunction.digest(new byte[0]);
        System.out.println("Empty hash: " + ByteUtils.bytesToHex(this.emptyHash));
        if (psk == null)
            psk = new byte[32];
        computeEarlySecret(psk);
    }

    public TlsState() {
        this("tls13 ", null);
    }

    private byte[] computeEarlySecret(byte[] ikm) {
        byte[] zeroSalt = new byte[32];
        this.earlySecret = this.hkdf.extract(zeroSalt, ikm);
        System.out.println("Early secret: " + ByteUtils.bytesToHex(this.earlySecret));
        this.binderKey = hkdfExpandLabel(this.earlySecret, "res binder", this.emptyHash, (short)32);
        System.out.println("Binder key: " + ByteUtils.bytesToHex(this.binderKey));
        return this.earlySecret;
    }

    private byte[] computeClientHelloMessageHash(byte[] clientHello) {
        ByteBuffer helloData = ByteBuffer.allocate(clientHello.length);
        helloData.put(clientHello, 0, clientHello.length);
        this.hashFunction.reset();
        byte[] helloHash = this.hashFunction.digest(helloData.array());
        System.out.println("Hello hash: " + ByteUtils.bytesToHex(helloHash));
        return helloHash;
    }

    private byte[] computeHandshakeMessagesHash(byte[] clientHello, byte[] serverHello) {
        ByteBuffer helloData = ByteBuffer.allocate(clientHello.length + serverHello.length);
        helloData.put(clientHello, 0, clientHello.length);
        helloData.put(serverHello, 0, serverHello.length);
        this.hashFunction.reset();
        byte[] helloHash = this.hashFunction.digest(helloData.array());
        System.out.println("Hello hash: " + ByteUtils.bytesToHex(helloHash));
        return helloHash;
    }

    public byte[] computeHandshakeFinishedHmac(boolean withClientFinished) {
        this.hashFunction.reset();
        this.hashFunction.update(this.clientHello);
        this.hashFunction.update(this.serverHello);
        this.hashFunction.update(this.encryptedExtensionsMessage);
        if (this.certificateMessage != null)
            this.hashFunction.update(this.certificateMessage);
        if (this.certificateVerifyMessage != null)
            this.hashFunction.update(this.certificateVerifyMessage);
        this.hashFunction.update(this.serverFinishedMessage);
        if (withClientFinished)
            this.hashFunction.update(this.clientFinishedMessage);
        byte[] hash = this.hashFunction.digest();
        if (withClientFinished) {
            this.handshakeClientFinishedHash = hash;
        } else {
            this.handshakeServerFinishedHash = hash;
        }
        byte[] finishedKey = hkdfExpandLabel(this.clientHandshakeTrafficSecret, "finished", "", (short)32);
        SecretKeySpec hmacKey = new SecretKeySpec(finishedKey, "HmacSHA256");
        try {
            Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
            hmacSHA256.init(hmacKey);
            hmacSHA256.update(this.handshakeServerFinishedHash);
            byte[] hmac = hmacSHA256.doFinal();
            return hmac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing (hmac) sha-256 support");
        } catch (InvalidKeyException e) {
            throw new RuntimeException();
        }
    }

    byte[] computePskBinder(byte[] partialClientHello) {
        try {
            this.hashFunction.reset();
            this.hashFunction.update(partialClientHello);
            byte[] hash = this.hashFunction.digest();
            byte[] finishedKey = hkdfExpandLabel(this.binderKey, "finished", "", (short)32);
            SecretKeySpec hmacKey = new SecretKeySpec(finishedKey, "HmacSHA256");
            Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
            hmacSHA256.init(hmacKey);
            hmacSHA256.update(hash);
            byte[] hmac = hmacSHA256.doFinal();
            return hmac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing (hmac) sha-256 support");
        } catch (InvalidKeyException e) {
            throw new RuntimeException();
        }
    }

    private byte[] computeSharedSecret(byte[] serverSharedKey) {
        ECPublicKey serverPublicKey = convertP256Key(serverSharedKey);
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(this.clientPrivateKey);
            keyAgreement.doPhase(serverPublicKey, true);
            SecretKey key = keyAgreement.generateSecret("TlsPremasterSecret");
            System.out.println("Shared key: " + ByteUtils.bytesToHex(key.getEncoded()));
            return key.getEncoded();
        } catch (NoSuchAlgorithmException|InvalidKeyException e) {
            throw new RuntimeException("Unsupported crypto: " + e);
        }
    }

    private void computeEarlyTrafficSecret(byte[] clientHelloHash) {
        this.clientEarlyTrafficSecret = hkdfExpandLabel(this.earlySecret, "c e traffic", clientHelloHash, (short)32);
    }

    private void computeHandshakeSecrets(byte[] helloHash, byte[] sharedSecret) {
        byte[] derivedSecret = hkdfExpandLabel(this.earlySecret, "derived", this.emptyHash, (short)32);
        System.out.println("Derived secret: " + ByteUtils.bytesToHex(derivedSecret));
        this.handshakeSecret = this.hkdf.extract(derivedSecret, sharedSecret);
        System.out.println("Handshake secret: " + ByteUtils.bytesToHex(this.handshakeSecret));
        this.clientHandshakeTrafficSecret = hkdfExpandLabel(this.handshakeSecret, "c hs traffic", helloHash, (short)32);
        System.out.println("Client handshake traffic secret: " + ByteUtils.bytesToHex(this.clientHandshakeTrafficSecret));
        this.serverHandshakeTrafficSecret = hkdfExpandLabel(this.handshakeSecret, "s hs traffic", helloHash, (short)32);
        System.out.println("Server handshake traffic secret: " + ByteUtils.bytesToHex(this.serverHandshakeTrafficSecret));
        this.clientHandshakeKey = hkdfExpandLabel(this.clientHandshakeTrafficSecret, "key", "", (short)16);
        System.out.println("Client handshake key: " + ByteUtils.bytesToHex(this.clientHandshakeKey));
        this.clientKey = this.clientHandshakeKey;
        this.serverHandshakeKey = hkdfExpandLabel(this.serverHandshakeTrafficSecret, "key", "", (short)16);
        System.out.println("Server handshake key: " + ByteUtils.bytesToHex(this.serverHandshakeKey));
        this.serverKey = this.serverHandshakeKey;
        this.clientHandshakeIV = hkdfExpandLabel(this.clientHandshakeTrafficSecret, "iv", "", (short)12);
        System.out.println("Client handshake iv: " + ByteUtils.bytesToHex(this.clientHandshakeIV));
        this.clientIv = this.clientHandshakeIV;
        this.serverHandshakeIV = hkdfExpandLabel(this.serverHandshakeTrafficSecret, "iv", "", (short)12);
        System.out.println("Server handshake iv: " + ByteUtils.bytesToHex(this.serverHandshakeIV));
        this.serverIv = this.serverHandshakeIV;
    }

    public void computeApplicationSecrets() {
        computeApplicationSecrets(this.handshakeSecret, this.handshakeServerFinishedHash);
        this.serverRecordCount = 0;
        this.clientRecordCount = 0;
    }

    void computeApplicationSecrets(byte[] handshakeSecret, byte[] handshakeHash) {
        byte[] derivedSecret = hkdfExpandLabel(handshakeSecret, "derived", this.emptyHash, (short)32);
        System.out.println("Derived secret: " + ByteUtils.bytesToHex(derivedSecret));
        byte[] zeroKey = new byte[32];
        byte[] masterSecret = this.hkdf.extract(derivedSecret, zeroKey);
        System.out.println("Master secret: " + ByteUtils.bytesToHex(masterSecret));
        this.clientApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "c ap traffic", handshakeHash, (short)32);
        System.out.println("Client application traffic secret: " + ByteUtils.bytesToHex(this.clientApplicationTrafficSecret));
        this.serverApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "s ap traffic", handshakeHash, (short)32);
        System.out.println("Server application traffic secret: " + ByteUtils.bytesToHex(this.serverApplicationTrafficSecret));
        this.resumptionMasterSecret = hkdfExpandLabel(masterSecret, "res master", this.handshakeClientFinishedHash, (short)32);
        System.out.println("Resumption master secret: " + ByteUtils.bytesToHex(this.resumptionMasterSecret));
        byte[] clientApplicationKey = hkdfExpandLabel(this.clientApplicationTrafficSecret, "key", "", (short)16);
        System.out.println("Client application key: " + ByteUtils.bytesToHex(clientApplicationKey));
        this.clientKey = clientApplicationKey;
        byte[] serverApplicationKey = hkdfExpandLabel(this.serverApplicationTrafficSecret, "key", "", (short)16);
        System.out.println("Server application key: " + ByteUtils.bytesToHex(serverApplicationKey));
        this.serverKey = serverApplicationKey;
        byte[] clientApplicationIv = hkdfExpandLabel(this.clientApplicationTrafficSecret, "iv", "", (short)12);
        System.out.println("Client application iv: " + ByteUtils.bytesToHex(clientApplicationIv));
        this.clientIv = clientApplicationIv;
        byte[] serverApplicationIv = hkdfExpandLabel(this.serverApplicationTrafficSecret, "iv", "", (short)12);
        System.out.println("Server application iv: " + ByteUtils.bytesToHex(serverApplicationIv));
        this.serverIv = serverApplicationIv;
        this.status = Status.ApplicationData;
    }

    byte[] computePSK(byte[] ticketNonce) {
        byte[] psk = hkdfExpandLabel(this.resumptionMasterSecret, "resumption", ticketNonce, (short)32);
        return psk;
    }

    byte[] hkdfExpandLabel(byte[] secret, String label, String context, short length) {
        return hkdfExpandLabel(secret, label, context.getBytes(ISO_8859_1), length);
    }

    byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, short length) {
        ByteBuffer hkdfLabel = ByteBuffer.allocate(3 + this.labelPrefix.length() + (label.getBytes(ISO_8859_1)).length + 1 + context.length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte)(this.labelPrefix.length() + (label.getBytes()).length));
        hkdfLabel.put(this.labelPrefix.getBytes(ISO_8859_1));
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte)context.length);
        hkdfLabel.put(context);
        return this.hkdf.expand(secret, hkdfLabel.array(), length);
    }

    public static ECPublicKey convertP256Key(byte[] w) {
        KeyFactory eckf;
        int keyLength = w.length;
        int startIndex = 0;
        if (w[0] == 4) {
            keyLength--;
            startIndex = 1;
        }
        byte[] encodedKey = new byte[P256_HEAD.length + w.length];
        System.arraycopy(P256_HEAD, 0, encodedKey, 0, P256_HEAD.length);
        System.arraycopy(w, startIndex, encodedKey, P256_HEAD.length, keyLength);
        try {
            eckf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC key factory not present in runtime");
        }
        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);
        try {
            return (ECPublicKey)eckf.generatePublic(ecpks);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    byte[] decrypt(byte[] recordHeader, byte[] payload) {
        int recordSize = (recordHeader[3] & 0xFF) << 8 | recordHeader[4] & 0xFF;
        System.out.println("Payload length: " + payload.length + " bytes, size in record: " + recordSize);
        byte[] encryptedData = new byte[recordSize - 16];
        byte[] authTag = new byte[16];
        System.arraycopy(payload, 0, encryptedData, 0, encryptedData.length);
        System.arraycopy(payload, 0 + recordSize - 16, authTag, 0, authTag.length);
        System.out.println("Record data: " + ByteUtils.bytesToHex(recordHeader));
        System.out.println("Encrypted data: " + ByteUtils.bytesToHex(encryptedData, Math.min(8, encryptedData.length)) + "..." +
                ByteUtils.bytesToHex(encryptedData, Math.max(encryptedData.length - 8, 0), Math.min(8, encryptedData.length)));
        System.out.println("Auth tag: " + ByteUtils.bytesToHex(authTag));
        byte[] wrapped = decryptPayload(payload, recordHeader, this.serverRecordCount);
        this.serverRecordCount++;
        System.out.println("Decrypted data (" + wrapped.length + "): " + ByteUtils.bytesToHex(wrapped, Math.min(8, wrapped.length)) + "..." +
                ByteUtils.bytesToHex(wrapped, Math.max(wrapped.length - 8, 0), Math.min(8, wrapped.length)));
        return wrapped;
    }

    byte[] decryptPayload(byte[] message, byte[] associatedData, int recordNumber) {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong(recordNumber);
        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte)(b ^ this.serverIv[i++]);
        try {
            SecretKeySpec secretKey = new SecretKeySpec(this.serverKey, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);
            aeadCipher.init(2, secretKey, parameterSpec);
            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException|InvalidKeyException|java.security.InvalidAlgorithmParameterException|javax.crypto.IllegalBlockSizeException|javax.crypto.BadPaddingException e) {
            throw new RuntimeException("Crypto error: " + e);
        }
    }

    byte[] encryptPayload(byte[] message, byte[] associatedData) {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong(this.clientRecordCount);
        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte)(b ^ this.clientIv[i++]);
        try {
            SecretKeySpec secretKey = new SecretKeySpec(this.clientKey, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);
            aeadCipher.init(1, secretKey, parameterSpec);
            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException|InvalidKeyException|java.security.InvalidAlgorithmParameterException|javax.crypto.IllegalBlockSizeException|javax.crypto.BadPaddingException e) {
            throw new RuntimeException("Crypto error: " + e);
        }
    }

    public byte[] getClientEarlyTrafficSecret() {
        return this.clientEarlyTrafficSecret;
    }

    public byte[] getClientHandshakeTrafficSecret() {
        return this.clientHandshakeTrafficSecret;
    }

    public byte[] getServerHandshakeTrafficSecret() {
        return this.serverHandshakeTrafficSecret;
    }

    public byte[] getClientApplicationTrafficSecret() {
        return this.clientApplicationTrafficSecret;
    }

    public byte[] getServerApplicationTrafficSecret() {
        return this.serverApplicationTrafficSecret;
    }

    public void clientHelloSend(PrivateKey clientPrivateKey, byte[] sentClientHello) {
        this.clientPrivateKey = clientPrivateKey;
        this.clientHello = sentClientHello;
        computeEarlyTrafficSecret(computeClientHelloMessageHash(sentClientHello));
    }

    public void setPskSelected(int selectedIdentity) {
        this.pskSelected = true;
    }

    public void setServerSharedKey(byte[] serverHello, byte[] serverSharedKey) {
        if (this.psk != null && !this.pskSelected)
            computeEarlySecret(new byte[32]);
        this.serverHello = serverHello;
        this.serverSharedKey = serverSharedKey;
        byte[] handshakeHash = computeHandshakeMessagesHash(this.clientHello, serverHello);
        byte[] sharedSecret = computeSharedSecret(serverSharedKey);
        computeHandshakeSecrets(handshakeHash, sharedSecret);
    }

    public void setEncryptedExtensions(byte[] raw) {
        this.encryptedExtensionsMessage = raw;
    }

    public void setCertificate(byte[] raw) {
        this.certificateMessage = raw;
    }

    public void setCertificateVerify(byte[] raw) {
        this.certificateVerifyMessage = raw;
    }

    public void setServerFinished(byte[] raw) {
        this.serverFinishedMessage = raw;
        this.status = Status.AuthServerFinished;
    }

    public boolean isServerFinished() {
        return (this.status == Status.AuthServerFinished);
    }

    public void setClientFinished(byte[] raw) {
        this.clientFinishedMessage = raw;
        computeHandshakeFinishedHmac(true);
    }
}
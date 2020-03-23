package quic.tls;

import quic.tls.extension.Extension;

import java.nio.ByteBuffer;
import java.security.interfaces.ECPublicKey;
import java.util.stream.Stream;

public class KeyShareExtension extends Extension {
    private ECPublicKey publicKey;

    private String ecCurve;

    private TlsConstants.NamedGroup namedGroup;

    private byte[] serverSharedKey;

    public KeyShareExtension() {}

    public KeyShareExtension(ECPublicKey publicKey, String ecCurve) {
        this.publicKey = publicKey;
        this.ecCurve = ecCurve;
        if (ecCurve != "secp256r1")
            throw new RuntimeException("Only secp256r1 is supported");
    }

    public KeyShareExtension parse(ByteBuffer buffer) throws Exception {
        int extensionType = buffer.getShort();
        if (extensionType != TlsConstants.ExtensionType.key_share.value)
            throw new RuntimeException();
        int extensionLength = buffer.getShort();
        int keyShareEntryPosition = buffer.position();
        parseKeyShareEntry(buffer);
        if (buffer.position() - keyShareEntryPosition != extensionLength)
            throw new Exception("Incorrect length");
        return this;
    }

    protected void parseKeyShareEntry(ByteBuffer buffer) throws Exception {
        int namedGroupValue = buffer.getShort();
        this
                .namedGroup = (TlsConstants.NamedGroup)Stream.<TlsConstants.NamedGroup>of(TlsConstants.NamedGroup.values()).filter(it -> (it.value == namedGroupValue)).findAny().orElseThrow(() -> new Exception("Unknown named group"));
        int keyLength = buffer.getShort();
        this.serverSharedKey = new byte[keyLength];
        buffer.get(this.serverSharedKey);
        System.out.println("Server shared key (" + keyLength + "): " + ByteUtils.bytesToHex(this.serverSharedKey));
    }

    public byte[] getBytes() {
        short rawKeyLength = 65;
        short keyShareEntryLength = (short)(4 + rawKeyLength);
        short extensionLength = (short)(2 + 1 * keyShareEntryLength);
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.key_share.value);
        buffer.putShort(extensionLength);
        buffer.putShort(keyShareEntryLength);
        buffer.putShort(TlsConstants.NamedGroup.secp256r1.value);
        buffer.putShort(rawKeyLength);
        buffer.put((byte)4);
        byte[] affineX = this.publicKey.getW().getAffineX().toByteArray();
        writeAffine(buffer, affineX);
        byte[] affineY = this.publicKey.getW().getAffineY().toByteArray();
        writeAffine(buffer, affineY);
        return buffer.array();
    }

    public byte[] getServerSharedKey() {
        return this.serverSharedKey;
    }

    private void writeAffine(ByteBuffer buffer, byte[] affine) {
        if (affine.length == 32) {
            buffer.put(affine);
        } else if (affine.length < 32) {
            for (int i = 0; i < 32 - affine.length; i++)
                buffer.put((byte)0);
            buffer.put(affine, 0, affine.length);
        } else if (affine.length > 32) {
            for (int i = 0; i < affine.length - 32; i++) {
                if (affine[i] != 0)
                    throw new RuntimeException("W Affine more then 32 bytes, leading bytes not 0 " +
                            ByteUtils.bytesToHex(affine));
            }
            buffer.put(affine, affine.length - 32, 32);
        }
    }
}


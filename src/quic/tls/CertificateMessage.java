package quic.tls;

import java.nio.ByteBuffer;

public class CertificateMessage extends HandshakeMessage {
    public CertificateMessage parse(ByteBuffer buffer, int length, TlsState state) {
        int startPosition = buffer.position();
//        System.out.println("Certificate message:\n" + ByteUtils.byteToHexBlock(buffer, buffer.position(), Math.min(length, buffer.remaining())));
        if (length > buffer.remaining())
            System.out.println("Underflow: expecting " + length + " bytes, but only " + buffer.remaining() + " left!");
        int handshakeType = buffer.get();
        int remainingLength = (buffer.get() & 0xFF) << 16 | (buffer.get() & 0xFF) << 8 | buffer.get() & 0xFF;
        int certificateRequestContextSize = buffer.get();
        if (certificateRequestContextSize > 0) {
            byte[] certificateRequestContext = new byte[certificateRequestContextSize];
            buffer.get(certificateRequestContext);
        }
        int certificateListSize = (buffer.get() & 0xFF) << 16 | (buffer.get() & 0xFF) << 8 | buffer.get() & 0xFF;
        int certCount = parseCertificateEntry(buffer, certificateListSize);
        System.out.println("Got Certificate message (" + length + " bytes), contains " + certCount + " certificate" + ((certCount == 1) ? "." : "s."));
        byte[] raw = new byte[length];
        buffer.position(startPosition);
        buffer.get(raw);
        state.setCertificate(raw);
        return this;
    }

    private int parseCertificateEntry(ByteBuffer buffer, int certificateListSize) {
        int remainingCertificateBytes = certificateListSize;
        int certCount = 0;
        while (remainingCertificateBytes > 0) {
            int certSize = (buffer.get() & 0xFF) << 16 | (buffer.get() & 0xFF) << 8 | buffer.get() & 0xFF;
            byte[] cert_data = new byte[certSize];
            buffer.get(cert_data);
            remainingCertificateBytes -= 3 + certSize;
            certCount++;
            int extensionsSize = buffer.getShort();
            if (extensionsSize > 0)
                buffer.get(new byte[extensionsSize]);
            remainingCertificateBytes -= 2 + extensionsSize;
        }
        return certCount;
    }

    public byte[] getBytes() {
        return new byte[0];
    }
}


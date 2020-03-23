package quic.tls;

import quic.tls.extension.EncryptedExtensions;
import quic.tls.extension.EarlyDataExtension;
import quic.tls.extension.Extension;

import java.nio.ByteBuffer;
import java.util.List;

public class NewSessionTicketMessage extends HandshakeMessage{
    private long ticketAgeAdd;

    private byte[] ticket;

    private byte[] ticketNonce;

    private int ticketLifetime;

    private EarlyDataExtension earlyDataExtension;

    public NewSessionTicketMessage parse(ByteBuffer buffer, int length, TlsState state) throws Exception {
        buffer.getInt();
        this.ticketLifetime = buffer.getInt();
        this.ticketAgeAdd = buffer.getInt() & 0xFFFFFFFFL;
        int ticketNonceSize = buffer.get() & 0xFF;
        this.ticketNonce = new byte[ticketNonceSize];
        buffer.get(this.ticketNonce);
        int ticketSize = buffer.getShort() & 0xFFFF;
        this.ticket = new byte[ticketSize];
        buffer.get(this.ticket);
        List<Extension> extensions = EncryptedExtensions.parseExtensions(buffer);
        if (!extensions.isEmpty())
            if (extensions.get(0) instanceof EarlyDataExtension) {
                this.earlyDataExtension = (EarlyDataExtension)extensions.get(0);
            } else {
                System.out.println("Unexpected extension type in NewSessionTicketMessage: " + extensions.get(0));
            }
        System.out.println("Got New Session Ticket message (" + length + " bytes)");
        return this;
    }

    public byte[] getBytes() {
        return new byte[0];
    }

    public int getTicketLifetime() {
        return this.ticketLifetime;
    }

    public long getTicketAgeAdd() {
        return this.ticketAgeAdd;
    }

    public byte[] getTicket() {
        return this.ticket;
    }

    public byte[] getTicketNonce() {
        return this.ticketNonce;
    }

    public EarlyDataExtension getEarlyDataExtension() {
        return this.earlyDataExtension;
    }
}


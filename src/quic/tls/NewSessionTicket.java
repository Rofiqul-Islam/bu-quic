package quic.tls;

import java.nio.ByteBuffer;
import java.util.Date;

public class NewSessionTicket {
    protected byte[] psk;

    protected Date ticketCreationDate;

    protected long ticketAgeAdd;

    protected byte[] ticket;

    protected int ticketLifeTime;

    protected boolean hasEarlyDataExtension;

    protected long earlyDataMaxSize;

    protected NewSessionTicket() {}

    public NewSessionTicket(TlsState state, NewSessionTicketMessage newSessionTicketMessage) {
        this.psk = state.computePSK(newSessionTicketMessage.getTicketNonce());
        this.ticketCreationDate = new Date();
        this.ticketAgeAdd = newSessionTicketMessage.getTicketAgeAdd();
        this.ticket = newSessionTicketMessage.getTicket();
        this.ticketLifeTime = newSessionTicketMessage.getTicketLifetime();
        this.hasEarlyDataExtension = (newSessionTicketMessage.getEarlyDataExtension() != null);
        if (this.hasEarlyDataExtension)
            this.earlyDataMaxSize = newSessionTicketMessage.getEarlyDataExtension().getMaxEarlyDataSize();
    }

    protected NewSessionTicket(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        this.ticketCreationDate = new Date(buffer.getLong());
        this.ticketAgeAdd = buffer.getLong();
        int ticketSize = buffer.getInt();
        this.ticket = new byte[ticketSize];
        buffer.get(this.ticket);
        int pskSize = buffer.getInt();
        this.psk = new byte[pskSize];
        buffer.get(this.psk);
        if (buffer.remaining() > 0)
            this.ticketLifeTime = buffer.getInt();
        if (buffer.remaining() > 0)
            this.earlyDataMaxSize = buffer.getLong();
    }

    public static NewSessionTicket deserialize(byte[] data) {
        return new NewSessionTicket(data);
    }

    public byte[] serialize() {
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        buffer.putLong(this.ticketCreationDate.getTime());
        buffer.putLong(this.ticketAgeAdd);
        buffer.putInt(this.ticket.length);
        buffer.put(this.ticket);
        buffer.putInt(this.psk.length);
        buffer.put(this.psk);
        buffer.putInt(this.ticketLifeTime);
        if (this.hasEarlyDataExtension) {
            buffer.putLong(this.earlyDataMaxSize);
        } else {
            buffer.putLong(0L);
        }
        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);
        return data;
    }

    int validFor() {
        return Integer.max(0, (int)(this.ticketCreationDate.getTime() + (this.ticketLifeTime * 1000) - (new Date()).getTime()) / 1000);
    }

    public byte[] getPSK() {
        return this.psk;
    }

    public Date getTicketCreationDate() {
        return this.ticketCreationDate;
    }

    public long getTicketAgeAdd() {
        return this.ticketAgeAdd;
    }

    public byte[] getSessionTicketIdentity() {
        return this.ticket;
    }

    public boolean hasEarlyDataExtension() {
        return this.hasEarlyDataExtension;
    }

    public long getEarlyDataMaxSize() {
        return this.earlyDataMaxSize;
    }

    public String toString() {
        return "Ticket, creation date = " + this.ticketCreationDate + ", ticket lifetime = " + this.ticketLifeTime + (
                (validFor() > 0) ? (" (still valid for " + validFor() + " seconds)") : " (not valid anymore)");
    }
}

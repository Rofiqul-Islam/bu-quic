package quic.tls;

import quic.tls.extension.Extension;
import java.nio.ByteBuffer;
import java.util.Date;

public class ClientHelloPreSharedKeyExtension extends Extension {
    private byte[] sessionTicketIdentity;

    private long obfuscatedTicketAge;

    private long ticketAgeAdd;

    private final TlsState tlsState;

    private Date ticketCreationDate;

    private int binderPosition;

    private byte[] binder;

    public ClientHelloPreSharedKeyExtension(TlsState state, NewSessionTicket newSessionTicket) {
        this.tlsState = state;
        this.ticketCreationDate = newSessionTicket.getTicketCreationDate();
        this.ticketAgeAdd = newSessionTicket.getTicketAgeAdd();
        this.sessionTicketIdentity = newSessionTicket.getSessionTicketIdentity();
        this.obfuscatedTicketAge = ((new Date()).getTime() - this.ticketCreationDate.getTime() + this.ticketAgeAdd) % 4294967296L;
    }

    public byte[] getBytes() {
        int extensionLength = 4 + this.sessionTicketIdentity.length + 4 + 2 + 1 + 32;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.pre_shared_key.value);
        buffer.putShort((short)extensionLength);
        buffer.putShort((short)(2 + this.sessionTicketIdentity.length + 4));
        buffer.putShort((short)this.sessionTicketIdentity.length);
        buffer.put(this.sessionTicketIdentity);
        buffer.putInt((int)this.obfuscatedTicketAge);
        this.binderPosition = buffer.position();
        buffer.putShort((short)33);
        buffer.put((byte)32);
        if (this.binder == null) {
            buffer.put(new byte[32]);
        } else {
            buffer.put(this.binder);
        }
        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);
        return data;
    }

    public void calculateBinder(byte[] clientHello, int pskExtensionStartPosition) {
        int partialHelloSize = pskExtensionStartPosition + this.binderPosition;
        byte[] partialHello = new byte[partialHelloSize];
        ByteBuffer.wrap(clientHello).get(partialHello);
        this.binder = this.tlsState.computePskBinder(partialHello);
    }
}

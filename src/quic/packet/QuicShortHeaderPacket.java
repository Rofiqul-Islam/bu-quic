package quic.packet;


import quic.frame.QuicFrame;
import quic.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;

/**
 * Represents a QUIC Short Header Packet.
 * A Short Header Packet can be used after the version and 1-RTT
 * keys are negotiated.
 *
 * @version 1.1
 */
public class QuicShortHeaderPacket extends QuicPacket {

    int headerByte;
    /**
     * Value constructor for QuicShortHeaderPacket class
     *
     * @param dcID         destination connection ID
     * @param packetNumber number of the packet
     */
    public QuicShortHeaderPacket(byte[] dcID, long packetNumber) {
        super(dcID, packetNumber);
        this.setHeaderByte(packetNumber);
    }

    public int getHeaderByte() {
        return headerByte;
    }

    public void setHeaderByte(Long packetNumber) {
        if(packetNumber<Math.pow(2,8)) {
            this.headerByte = 64;
        }
        else if(packetNumber<Math.pow(2,16)){
            this.headerByte = 65;
        }
        if(packetNumber<Math.pow(2,24)) {
            this.headerByte = 66;
        }
        else if(packetNumber<Math.pow(2,32)){
            this.headerByte = 67;
        }
    }

    /**
     * Encodes short header packet
     *
     * @return encoded byte array
     */
    @Override
    public byte[] encode() {
        ByteArrayOutputStream encoding = new ByteArrayOutputStream();
        try {
            encoding.write(headerByte);
            encoding.write(Util.hexStringToByteArray(Util.bytesArrayToHex(this.getDcID()),this.getDcID().length));
            int frameSize = 0;
            Iterator<QuicFrame> iterator1 = this.getFrames().iterator();
            while (iterator1.hasNext()) {
                QuicFrame f = iterator1.next();
                frameSize += f.encode().length;
            }
            ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
            buffer.putLong(this.getPacketNumber());
            byte[] packetNo = buffer.array();
            encoding.write(packetNo.length + frameSize);
            encoding.write(packetNo);
            Iterator<QuicFrame> iterator2 = this.getFrames().iterator();
            while (iterator2.hasNext()) {
                QuicFrame f = iterator2.next();
                encoding.write(f.encode());
            }

        } catch (IOException e) {
            System.out.println(e);
        }
        return encoding.toByteArray();
    }
}

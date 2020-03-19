package quic.packet;

import quic.exception.QuicException;
import quic.frame.QuicFrame;
import quic.main.ConnectionSecrets;
import quic.main.EncryptionLevel;
import quic.util.ConnectionUtil;
import quic.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.Set;

import static quic.main.Client.connectionSecrets;

/**
 * Represents a QUIC Initial Packet. It carries the first CRYPTO frames sent
 * by the client and server to perform key exchange, and carries ACKs in either direction.
 *
 * @version 1.1
 */
public class QuicInitialPacket extends QuicLongHeaderPacket {

    byte headerByte;
    int packetNumberLength;
    int tokenLength;

    /**
     * Value constructor for QuicInitialPacket class
     * @param dcID destination connection ID
     * @param packetNumber number of the packet
     * @param version version of quic
     * @param scID source connections ID
     */
    public QuicInitialPacket(byte[] dcID, long packetNumber, long version, byte[] scID, Set<QuicFrame> frames) {
        super(dcID,packetNumber,version,scID,frames);
        this.setHeaderByte(packetNumber);
        this.setTokenLength(0);

    }

    public int getHeaderByte() {
        return headerByte;
    }

    public void setHeaderByte(Long packetNumber) {
        if(packetNumber<Math.pow(2,8)) {
            this.headerByte = (byte)192;
            this.packetNumberLength =1;
        }
        else if(packetNumber<Math.pow(2,16)){
            this.headerByte = (byte)193;
            this.packetNumberLength = 2;
        }
        else if(packetNumber<Math.pow(2,24)) {
            this.headerByte = (byte)194;
            this.packetNumberLength = 3;
        }
        else if(packetNumber<Math.pow(2,32)){
            this.headerByte = (byte)195;
            this.packetNumberLength = 4;
        }
        else{
            throw new IllegalArgumentException();
        }
    }

    public int getTokenLength() {
        return tokenLength;
    }

    public void setTokenLength(int tokenLength) {
        this.tokenLength = tokenLength;
    }

    /**
     * Encodes initial packet
     * @return encoded byte array
     */
    @Override
    public byte[] encode()
    {
        ByteArrayOutputStream encoding = new ByteArrayOutputStream();
        try {
            encoding.write(Util.hexStringToByteArray(Util.byteToHex(headerByte),1));
            encoding.write(Util.hexStringToByteArray(Long.toHexString(this.getVersion()),4));
            encoding.write(Util.hexStringToByteArray((Util.byteToHex((byte)this.getDcID().length)),1));
            encoding.write(Util.hexStringToByteArray(Util.bytesArrayToHex(this.getDcID()),this.getDcID().length));
            encoding.write(Util.hexStringToByteArray((Util.byteToHex((byte)this.getScID().length)),1));
            encoding.write(Util.hexStringToByteArray(Util.bytesArrayToHex(this.getScID()),this.getScID().length));
            encoding.write(Util.hexStringToByteArray(Util.byteToHex((byte)this.getTokenLength()),1));

            long frameSize = 0;
            Iterator<QuicFrame> iterator1 = this.getFrames().iterator();
            ByteArrayOutputStream temp = new ByteArrayOutputStream();
            while (iterator1.hasNext()) {
                QuicFrame f = iterator1.next();
                frameSize += f.encode().length;
                temp.write(f.encode());
            }
            encoding.write(Util.generateVariableLengthInteger(packetNumberLength + frameSize));
            encoding.write(Util.hexStringToByteArray((Long.toHexString(this.getPacketNumber())),packetNumberLength));
            encoding.write(temp.toByteArray());

            System.out.println("packet size = "+encoding.size());
        } catch (IOException e) {
            System.out.println(e);
        }
        return encoding.toByteArray();
    }

    public byte[] specialEncode() throws IOException, QuicException {
        ByteBuffer packetBuffer = ByteBuffer.allocate(1500);
        packetBuffer.put(Util.hexStringToByteArray(Util.byteToHex(headerByte),1));
        packetBuffer.put(Util.hexStringToByteArray(Long.toHexString(this.getVersion()),4));
        packetBuffer.put(Util.hexStringToByteArray((Util.byteToHex((byte)this.getDcID().length)),1));
        packetBuffer.put(Util.hexStringToByteArray(Util.bytesArrayToHex(this.getDcID()),this.getDcID().length));
        packetBuffer.put(Util.hexStringToByteArray((Util.byteToHex((byte)this.getScID().length)),1));
        packetBuffer.put(Util.hexStringToByteArray(Util.bytesArrayToHex(this.getScID()),this.getScID().length));
        packetBuffer.put(Util.hexStringToByteArray(Util.byteToHex((byte)this.getTokenLength()),1));
        long frameSize = 0;
        Iterator<QuicFrame> iterator1 = this.getFrames().iterator();
        ByteBuffer temp = ByteBuffer.allocate(1500);
        while (iterator1.hasNext()) {
            QuicFrame f = iterator1.next();
            frameSize += f.encode().length;
            temp.put(f.encode());
        }
        temp.flip();
        packetBuffer.put(Util.generateVariableLengthInteger(packetNumberLength + frameSize+16));
        byte[] packetNo = Util.hexStringToByteArray((Long.toHexString(this.getPacketNumber())),packetNumberLength);
        packetBuffer.put(packetNo);
        ConnectionUtil.protectPacketNumberAndPayload(packetBuffer,packetNo,temp,0,connectionSecrets.getClientSecrets(EncryptionLevel.Initial));
       /* byte[] result =  new byte[packetBuffer.capacity()];
        packetBuffer.rewind();
        packetBuffer.get(result,0,result.length);*/
       packetBuffer.limit(packetBuffer.position());
       byte[]result = new byte[packetBuffer.position()];
       packetBuffer.rewind();
       packetBuffer.get(result);
        return result;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        Set<QuicFrame>temp = showFrames();
        for (QuicFrame frame: temp) {
            builder.append(frame.toString());
        }
        return "QuicInitialPacket{version=" + this.getVersion()+ ", scID=" + Util.printConnectionId(this.getScID()) + ", dcID=" + Util.printConnectionId(this.getDcID()) + ", packetNumber=" + this.getPacketNumber() + ", frames=[" + builder.toString() + "]}";
    }



}

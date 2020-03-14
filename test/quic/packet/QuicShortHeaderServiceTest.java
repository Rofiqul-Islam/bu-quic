package quic.packet;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import quic.exception.QuicException;
import quic.frame.*;

public class QuicShortHeaderServiceTest {

    public String convertByteToString(byte[] b){

        String string="";
        for (byte x:b ){
            string+=x;
        }
        return string;
    }
    @Test
    public void testGetDcId(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),123455);
        Assertions.assertEquals(convertByteToString(shortHeaderPacket.getDcID()),convertByteToString("192.168.43.125".getBytes()));
    }

    @Test
    public void testSetDcId(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),123455);
        shortHeaderPacket.setDcID("192.168.43.125".getBytes());
        Assertions.assertEquals(convertByteToString(shortHeaderPacket.getDcID()),convertByteToString("192.168.43.125".getBytes()));

    }

    @Test
    public void testGetPacketNumber(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),123455);
        Assertions.assertEquals(shortHeaderPacket.getPacketNumber(),123455);
    }

    @Test
    public void testSetPacketNumber(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),123455);
        shortHeaderPacket.setPacketNumber(23456);
        Assertions.assertEquals(shortHeaderPacket.getPacketNumber(),23456);

    }

    @Test
    public void testNullDcID(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),123455);
        Assertions.assertNotNull(shortHeaderPacket.getDcID(),"getDcID should not return null");
    }

    @Test
    public void testNullPacketNumber(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),123455);
        Assertions.assertNotNull(shortHeaderPacket.getPacketNumber(),"getPacketNumber should not return null");
    }
    @Test
    public void testMaxDcID(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),123455);
        byte[] dcIDBytes = shortHeaderPacket.getDcID();
        Assertions.assertTrue(dcIDBytes.length <= 20,"Maximum length check of Destianation connection ID is 20 bytes");
    }

    @Test
    public void testMaxPacketNumber(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),5234554532453L);
        Assertions.assertTrue(shortHeaderPacket.getPacketNumber() < Math.pow(2,62), "Maximum value of packet number is (2^62-1)");
    }

    @Test
    public void testAddCryptoFrame(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),523452452343253L);
        QuicCryptoFrame quicCryptoFrame = new QuicCryptoFrame(10,"hello world".getBytes());
        shortHeaderPacket.addFrame(quicCryptoFrame);
        Assertions.assertTrue(shortHeaderPacket.getFrames().contains(quicCryptoFrame),"addFrame() of short header packet should be able to add crypto frame in it's payload");
    }

    @Test
    public void testAddStreamFrame(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),523455453243253L);
        QuicStreamFrame streamFrame = new QuicStreamFrame(123,10,true,"Hello World".getBytes());
        shortHeaderPacket.addFrame(streamFrame);
        Assertions.assertTrue(shortHeaderPacket.getFrames().contains(streamFrame),"addFrame() of short header packet should be able to add stream frame in it's payload");
    }

    @Test
    public void testEmptyFrames(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),5234554533253L);
        QuicCryptoFrame quicCryptoFrame = new QuicCryptoFrame(10,"hello world".getBytes());
        shortHeaderPacket.addFrame(quicCryptoFrame);
        Assertions.assertNotNull(shortHeaderPacket.getFrames(),"set of frames should not be null");
    }

    @Test
    public void testTypeOfFrame(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),5234554533253L);
        QuicCryptoFrame quicCryptoFrame = new QuicCryptoFrame(10,"hello world".getBytes());
        shortHeaderPacket.addFrame(quicCryptoFrame);
        QuicStreamFrame streamFrame = new QuicStreamFrame(123,10,true,"Hello World".getBytes());
        shortHeaderPacket.addFrame(streamFrame);
        QuicAckFrame quicAckFrame = new QuicAckFrame(1000, 100, 100, 10);
        shortHeaderPacket.addFrame(quicAckFrame);
        for(QuicFrame x : shortHeaderPacket.getFrames()){
            Assertions.assertTrue((x instanceof QuicStreamFrame) ||(x instanceof QuicCryptoFrame),"QuicShorHeaderPacker should contain only crypto frames and stream frames");
        }
    }

    @Test
    public void testEncode(){
        QuicShortHeaderPacket shortHeaderPacket = new QuicShortHeaderPacket("192.168.43.125".getBytes(),1234567890L);
        QuicStreamFrame quicStreamFrame = new QuicStreamFrame(0,0,true,"hello".getBytes());
        Assertions.assertTrue(shortHeaderPacket.encode().toString().equals("41c0a82b7d499602d2"+"08000568656c6c6f"),"encode() method should convert the object as stream of hexa bytes");
        /* DcID= c0a82b7d
            packet number = 499602d2
            stream frame = 08000568656c6c6f
        */
    }

    public void testDecode() throws QuicException {
        QuicPacket quicPacket = QuicPacket.decode(("41c0a82b7d499602d2"+"08000568656c6c6f").getBytes());
        Assertions.assertTrue(quicPacket instanceof QuicShortHeaderPacket,"decode() method should decode the string of hexa bytes as quic packet");

    }


}

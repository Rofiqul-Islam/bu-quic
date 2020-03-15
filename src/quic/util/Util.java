package quic.util;

import net.luminis.tls.*;
import quic.exception.QuicException;
import quic.frame.QuicCryptoFrame;
import quic.frame.QuicFrame;
import quic.main.EncryptionLevel;
import quic.main.QuicTransportParametersExtension;
import quic.main.TransportParameters;
import quic.main.Version;
import quic.packet.*;

import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static quic.main.Client.*;

public class Util {

    public static int variableLengthIntegerLength(byte b){
        int temp = (int)b;
        int lenArry[] = new int[2];
        for(int c=7;c>=6;c--){
            int x = (int) Math.pow(2,c);
            if((x&temp)==0){
                lenArry[7-c]=0;
            }
            else{
                lenArry[7-c]=1;
            }
        }
        if(lenArry[0]==0 && lenArry[1]==0){
            return  1;
        }
        else if(lenArry[0]==0 && lenArry[1]==1){
            return 2;
        }
        else if(lenArry[0]==1 && lenArry[1]==0){
            return 4;
        }
        else if(lenArry[0]==1 && lenArry[1]==1){
            return 8;
        }

        return 0;
    }

    public static long variableLengthInteger(byte[] input,int type){
        if(type==0) {
            String s = bytesArrayToHex(input);
            Long result = Long.parseLong(s, 16);
            return result;
        }
        else if(type == 1){
            String s =Util.byteToHex((byte)(input[0]&63));
            byte [] temp = new byte[input.length-1];
            for(int i=1;i<input.length;i++){
                temp[i-1]=input[i];
            }
            s+=bytesArrayToHex(temp);
            //System.out.println("s = "+s);
            Long result = Long.parseLong(s, 16);
            return result;
        }
        return 0;
    }

    public static byte[] generateVariableLengthInteger(Long input){
        if(input<Math.pow(2,6)){              // adding 00 before the length
            byte[] temp = Util.hexStringToByteArray(Long.toHexString(input),1);
            temp[0]+=0;
            return temp;
        }
        else if(input<Math.pow(2,14)){        // adding 01 before the length
            byte[] temp = Util.hexStringToByteArray(Long.toHexString(input),2);
            temp[0]+=64;
            return temp;
        }
        else if(input<Math.pow(2,30)){        // adding 10 before the length
            byte[] temp = Util.hexStringToByteArray(Long.toHexString(input),4);
            temp[0]+=128;
            return temp;
        }
        else if(input<(long)Math.pow(2,62)){     //adding 11 before the integer
            byte[] temp = Util.hexStringToByteArray(Long.toHexString(input),8);
            temp[0]+=192;
            return temp;
        }
        return null;
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesArrayToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


    public static String byteToHex(byte b){
        int v = b & 0xFF;
        String hex_string = HEX_ARRAY[v >>> 4]+"";
        hex_string+= HEX_ARRAY[v & 0x0F];
        return hex_string;
    }

    public static byte[] hexStringToByteArray(String s, int requiredLen) {
        if (requiredLen == 0) {
            int len = s.length();
            byte[] data = new byte[s.length() / 2];
            for (int i = 0; i < s.length(); i += 2) {
                data[i / 2] = (byte) (((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i + 1), 16)));

            }
            return data;
        } else {
            int len = s.length();
            int diff = requiredLen * 2 - len;
            for (int i = 0; i < diff; i++) {
                s = "0" + s;
            }
            byte[] data = new byte[s.length() / 2];
            for (int i = 0; i < s.length(); i += 2) {
                data[i / 2] = (byte) (((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i + 1), 16)));

            }
            return data;
        }
    }

    public static QuicPacket createPacket(EncryptionLevel level, QuicFrame frame, byte[] dcId, long packetNumber,long version, byte[] scId ) throws QuicException {
        QuicPacket packet;
        switch (level) {
            case Initial:
                packet = new QuicInitialPacket(dcId, packetNumber,version, scId,null);
                packet.addFrame(frame);
                break;
           /* case Handshake:
                packet = new HandshakePacket(quicVersion, sourceConnectionIds.getCurrent(), destConnectionIds.getCurrent(), frame);
                break;
            case App:
                packet = new ShortHeaderPacket(quicVersion, destConnectionIds.getCurrent(), frame);
                break;*/
            default:
                throw new QuicException(0,0,"hello");  // Cannot happen, just here to satisfy the compiler.
        }
        return packet;
    }



    public static boolean allZero(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            if (data[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static String printConnectionId(byte[] connectionId) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < connectionId.length; i++) {
            // Only print the last two digits, but add a 0 if we need one
            String b = "0" + Integer.toHexString(connectionId[i]);
            builder.append(b.substring(b.lastIndexOf("") - 2));
        }
        return builder.toString();
    }

    public static QuicPacket quicIntialPacketDecoder(int type, byte[] arr, int headerByte, int headerArry[]) throws QuicException {
        try {
            int p = 1;
            byte[] version_arr = new byte[4];
            int n = p;
            for (; n < p + 4; n++) {
                version_arr[n - p] = arr[n];
            }
            long version = Util.variableLengthInteger(version_arr, 0);
            System.out.println("version = " + version);
            p = n;
            ////////////////////////////
            int dcIdLenD = (int) arr[p];
            System.out.println("dcidlen = " + dcIdLenD);
            p++;
            byte[] dcIdD = new byte[dcIdLenD];
            int i = p;
            for (; i < p + dcIdLenD; i++) {
                dcIdD[i - p] = arr[i];
            }
            System.out.print("dcId = ");
            for (byte x : dcIdD) {
                System.out.print(Util.byteToHex(x) + " ");
            }
            System.out.println();
            p = i;
            ///////////////////////////
            int scIdLenD = (int) arr[p];
            System.out.println("scidlen = " + scIdLenD);
            p++;
            byte[] scIdD = new byte[scIdLenD];
            int j = p;
            for (; j < p + scIdLenD; j++) {
                scIdD[j - p] = arr[j];
            }
            System.out.print("scId = ");
            for (byte x : scIdD) {
                System.out.print(Util.byteToHex(x) + " ");
            }
            System.out.println();
            p = j;
            ////////////////////////////
            int tokenLengthLen = Util.variableLengthIntegerLength(arr[p]);
            byte[] tokenLength_arr = new byte[tokenLengthLen];
            for (int c = p; c < p + tokenLengthLen; c++) {
                tokenLength_arr[c - p] = arr[c];
            }
            p += tokenLengthLen;
            long tokenLength = Util.variableLengthInteger(tokenLength_arr, 1);
            System.out.println("Token length = " + tokenLength);

            byte[] token = new byte[(int) tokenLength];
            for (int c = p; c < p + tokenLength; c++) {
                token[c - p] = arr[c];
            }
            p += tokenLength;
            ////////////////////////////
            int lengthSize = Util.variableLengthIntegerLength(arr[p]);
            byte[] len_arr = new byte[lengthSize];
            for (int c = p; c < lengthSize + p; c++) {
                len_arr[c - p] = arr[c];
            }
            p += lengthSize;
            long length = Util.variableLengthInteger(len_arr, 1);
            System.out.println("length = " + length);
            ///////////////////////////////////////
            int packetNoLen = (headerByte & 3) + 1;

            byte[] packNum_arr = new byte[packetNoLen];
            for (int c = p; c < packetNoLen + p; c++) {
                packNum_arr[c - p] = arr[c];
            }
            p += packetNoLen;
            long packetNum = Util.variableLengthInteger(packNum_arr, 0);
            System.out.println("packetNumber = " + packetNum);
            /////////
            byte[] frameSetD = new byte[(int) (length - packetNoLen)];
            int k = p;

            for (; k < p + (length - (packetNoLen)); k++) {
                frameSetD[k - p] = arr[k];
                System.out.print(k + " ");
            }
            p = k;
            Set<QuicFrame> temp = new HashSet<>();
            temp.add(QuicFrame.decode(frameSetD));
            if (type == 0) {
                QuicPacket initialPacket = new QuicInitialPacket(dcIdD, packetNum, version, scIdD, temp);
                return initialPacket;
            }
        }catch (Exception e){
            throw new QuicException(100,0,"initial packet decode error");
        }

        return null;
    }

    public static QuicPacket quicLongHeaderPacketDecoder(int type, byte[] arr, int headerByte, int headerArry[]) throws QuicException {
        try {
            int p = 1;
            byte[] version_arr = new byte[4];
            int n = p;
            for (; n < p + 4; n++) {
                version_arr[n - p] = arr[n];
            }
            long version = Util.variableLengthInteger(version_arr, 0);
            System.out.println("version = " + version);
            p = n;
            ////////////////////////////
            int dcIdLenD = (int) arr[p];
            System.out.println("dcidlen = " + dcIdLenD);
            p++;
            byte[] dcIdD = new byte[dcIdLenD];
            int i = p;
            for (; i < p + dcIdLenD; i++) {
                dcIdD[i - p] = arr[i];
            }
            System.out.print("dcId = ");
            for (byte x : dcIdD) {
                System.out.print(Util.byteToHex(x) + " ");
            }
            System.out.println();
            p = i;
            ///////////////////////////
            int scIdLenD = (int) arr[p];
            System.out.println("scidlen = " + scIdLenD);
            p++;
            byte[] scIdD = new byte[scIdLenD];
            int j = p;
            for (; j < p + scIdLenD; j++) {
                scIdD[j - p] = arr[j];
            }
            System.out.print("scId = ");
            for (byte x : scIdD) {
                System.out.print(Util.byteToHex(x) + " ");
            }
            System.out.println();
            p = j;
            ////////////////////////////
            int lengthSize = Util.variableLengthIntegerLength(arr[p]);
            byte[] len_arr = new byte[lengthSize];
            for (int c = p; c < lengthSize + p; c++) {
                len_arr[c - p] = arr[c];
            }
            p += lengthSize;
            long length = Util.variableLengthInteger(len_arr, 1);
            System.out.println("length = " + length);
            ///////////////////////////////////////
            int packetNoLen = (headerByte & 3) + 1;

            byte[] packNum_arr = new byte[packetNoLen];
            for (int c = p; c < packetNoLen + p; c++) {
                packNum_arr[c - p] = arr[c];
            }
            p += packetNoLen;
            long packetNum = Util.variableLengthInteger(packNum_arr, 0);
            System.out.println("packetNumber = " + packetNum);
            /////////
            byte[] frameSetD = new byte[(int) (length - packetNoLen)];
            int k = p;

            for (; k < p + (length - (packetNoLen)); k++) {
                frameSetD[k - p] = arr[k];
                System.out.print(k + " ");
            }
            p = k;
            Set<QuicFrame> temp = new HashSet<>();
            temp.add(QuicFrame.decode(frameSetD));

            if (type == 1) {
                QuicPacket zeroRttPacket = new QuicZeroRTTPacket(dcIdD, packetNum, version, scIdD, temp);
                return zeroRttPacket;
            } else if (type == 2) {
                return new QuicHandshakePacket(dcIdD, packetNum, version, scIdD, temp);
            }
        }catch (Exception e){
            throw new QuicException(100,0,"longheader decoder error");
        }

        return null;
    }

    public static QuicPacket quicShortHeaderDecoder(byte[] arr, int dcIdSize) throws QuicException {
        try {
            int p = 0;
            int headerArry[] = new int[8];
            int headerByte = (int) arr[0];;
            for (int c = 7; c >= 0; c--) {
                int x = (int) Math.pow(2, c);
                if ((x & headerByte) == 0) {
                    headerArry[7 - c] = 0;
                } else {
                    headerArry[7 - c] = 1;
                }
            }
            /////////////////////////
            p++;
            int dcIdLenD = dcIdSize;
            System.out.println("dcidlen = " + dcIdLenD);
            byte[] dcIdD = new byte[dcIdLenD];
            int i = p;
            for (; i < p + dcIdLenD; i++) {
                dcIdD[i - p] = arr[i];
            }
            System.out.print("dcId = ");
            for (byte x : dcIdD) {
                System.out.print(Util.byteToHex(x) + " ");
            }
            System.out.println();
            p = i;
            //////////////////////////////
            int packetNoLen = (headerByte & 3) + 1;

            byte[] packNum_arr = new byte[packetNoLen];
            for (int c = p; c < packetNoLen + p; c++) {
                packNum_arr[c - p] = arr[c];
            }
            p += packetNoLen;
            long packetNum = Util.variableLengthInteger(packNum_arr, 0);
            System.out.println("packetNumber = " + packetNum);
            //////////////////////////////////
            byte[] frameSetD = new byte[(int) (arr.length - p)];
            int k = p;

            for (; k < arr.length; k++) {
                frameSetD[k - p] = arr[k];
                System.out.print(k + " ");
            }
            p = k;
            Set<QuicFrame> temp = new HashSet<>();
            temp.add(QuicFrame.decode(frameSetD));
            QuicPacket shortHeaderPacket = new QuicShortHeaderPacket(dcIdD, packetNum, temp);
            return shortHeaderPacket;

        }catch (Exception e){
            throw new QuicException(100,0,"longheader decoder error");
        }
    }

}

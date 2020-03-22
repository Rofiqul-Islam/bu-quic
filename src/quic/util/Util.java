package quic.util;

import net.luminis.tls.*;
import quic.exception.QuicException;
import quic.frame.*;
import quic.main.*;
import quic.packet.*;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static quic.main.Client.*;

public class Util {

    public static long largestPacketNumber =0;

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
        Set<QuicFrame> temp = new HashSet<>();
        temp.add(frame);
        switch (level) {
            case Initial:
                packet = new QuicInitialPacket(dcId, packetNumber,version, scId,temp);
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
    public static QuicPacket changedInitialPacketDecorder(ByteBuffer input) throws QuicException {
        byte[] versionArray = new byte[4];
        input.get(versionArray,0,versionArray.length);
        long version = Util.variableLengthInteger(versionArray,0);
        ////////////////////////
        int dcIdLen = input.get();
        byte[] dcId = new byte[dcIdLen];
        input.get(dcId,0,dcIdLen);
        ////////////////////////////////
        int scIdLen = input.get();
        byte[] scId = new byte[scIdLen];
        input.get(scId,0,scIdLen);
        /////////////////////////////////
        int tokenLength = Util.variableLengthIntegerLength(input.get());
        byte[] token = new byte[tokenLength];
        input.position(input.position()-1);
        input.get(token,0,tokenLength);
        ///////////////////////////////////////////////
        int lengthLen = Util.variableLengthIntegerLength(input.get());
        input.position(input.position()-1);
        byte[] lenghtArray = new byte[lengthLen];
        input.get(lenghtArray,0,lengthLen);
        long length = Util.variableLengthInteger(lenghtArray,1);
        /////////////////////////
        int packetNumberLen =(input.get(0)&3)+1;
        byte[] packetNumberArray = new byte[packetNumberLen];
        input.get(packetNumberArray,0,packetNumberLen);
        long packetNumber = Util.variableLengthInteger(packetNumberArray,0);
        /////////////////////////////////
        byte[] frameSet = new byte[(int)(length - packetNumberLen)];
        input.get(frameSet,0,(int)(length - packetNumberLen));
        System.out.println(input.position()+" "+input.limit());

        Set<QuicFrame> temp = new HashSet<>();
        temp.add(QuicFrame.decode(frameSet));
        QuicPacket initialPacket = new QuicInitialPacket(dcId, packetNumber, version, scId, temp);
        return initialPacket;
    }

    public static QuicPacket specialQuicInitialPacketDecorder(byte[] arr, int headerByte, int headerArray[]) throws QuicException{

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
            byte[] sample = new byte[16];
            for(int c =p+4;c<p+20;c++){
                sample[c-(p+4)] = arr[c];
            }
            byte[] mask  = ConnectionUtil.createHeaderProtectionMask(sample,4,connectionSecrets.getServerSecrets(EncryptionLevel.Initial));
            byte decryptedheaderByte =(byte) (headerByte ^ mask[0] & 0x0f);
            System.out.println("decrypted header byte = "+decryptedheaderByte);

            ///////////////////////////////////////
            int packetNoLen = (decryptedheaderByte & 3) + 1;

            byte[] packNum_arr = new byte[packetNoLen];
            for (int c = p; c < packetNoLen + p; c++) {
                packNum_arr[c - p] = arr[c];
            }
            //------------
            byte[] frame_header = new byte[p+packetNoLen];
            for(int c =0;c<p;c++){
                frame_header[c]=arr[c];
            }
            frame_header[0]=decryptedheaderByte;
            //--------------
            p += packetNoLen;
            byte[] unProcPackNum_arr = new byte[packetNoLen];
            for(int k = 0;k<packetNoLen;k++){
                unProcPackNum_arr[k] = (byte) (packNum_arr[k]^mask[k+1]);
            }
            System.arraycopy(unProcPackNum_arr,0,frame_header,p-packetNoLen,packetNoLen);
            long packetNum = Util.variableLengthInteger(unProcPackNum_arr, 0);
            packetNum = decodePacketNumber(packetNum,largestPacketNumber,packetNoLen*8);
            System.out.println("packetNumber = " + packetNum);
            /////////
            byte[] frameSetD = new byte[(int) (length - packetNoLen)];
            int k = p;

            for (; k < p + (length - (packetNoLen)); k++) {
                frameSetD[k - p] = arr[k];
                //System.out.print(k + " ");
            }
            byte[] frameBytes = decryptPayload(frameSetD, frame_header,packetNum,connectionSecrets.getServerSecrets(EncryptionLevel.Initial));

            ////////////////
            p = k;
            Set<QuicFrame> temp = QuicFrame.specialDecorder(frameBytes);

            QuicPacket initialPacket = new QuicInitialPacket(dcIdD, packetNum, version, scIdD, temp);
            //System.out.println(initialPacket.toString());
            return initialPacket;

        }catch (Exception e){
            e.printStackTrace();
            //throw new QuicException(100,0,"initial packet decode error");
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
    public static QuicPacket changedLongHeaderPacketDecoder(ByteBuffer input,int type) throws QuicException {
        byte[] versionArray = new byte[4];
        input.get(versionArray,0,versionArray.length);
        long version = Util.variableLengthInteger(versionArray,0);
        ////////////////////////
        int dcIdLen = input.get();
        byte[] dcId = new byte[dcIdLen];
        input.get(dcId,0,dcIdLen);
        ////////////////////////////////
        int scIdLen = input.get();
        byte[] scId = new byte[scIdLen];
        input.get(scId,0,scIdLen);
        ///////////////////////////////////////////////
        int lengthLen = Util.variableLengthIntegerLength(input.get());
        input.position(input.position()-1);
        byte[] lenghtArray = new byte[lengthLen];
        input.get(lenghtArray,0,lengthLen);
        long length = Util.variableLengthInteger(lenghtArray,1);
        /////////////////////////
        int packetNumberLen =(input.get(0)&3)+1;
        byte[] packetNumberArray = new byte[packetNumberLen];
        input.get(packetNumberArray,0,packetNumberLen);
        long packetNumber = Util.variableLengthInteger(packetNumberArray,0);
        /////////////////////////////////
        byte[] frameSet = new byte[(int)(length - packetNumberLen)];
        input.get(frameSet,0,(int)(length - packetNumberLen));
        System.out.println(input.position()+" "+input.limit());

        Set<QuicFrame> temp = new HashSet<>();
        temp.add(QuicFrame.decode(frameSet));
        if (type == 1) {
            QuicPacket zeroRttPacket = new QuicZeroRTTPacket(dcId, packetNumber, version, scId, temp);
            return zeroRttPacket;
        } else if (type == 2) {
            return new QuicHandshakePacket(dcId, packetNumber, version, scId, temp);
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
    //////////////////////////

    public static DecodedFrame quicAckFrameDecoder(byte[] arr, int index){

        System.out.println("----------------- Ack frame---------------");

        int p=index+1;
        int largestAckLen = Util.variableLengthIntegerLength(arr[p]);
        byte[] largestAck_arr = new byte[largestAckLen];
        for(int n = p;n<p+largestAckLen;n++){
            largestAck_arr[n-p] = arr[n];
        }
        long largestAck = Util.variableLengthInteger(largestAck_arr,1);
        p=p+largestAckLen;
        System.out.println("largest Ack = "+largestAck);
        ///////////////////////////////////////////////////////

        int ackDelayLen = Util.variableLengthIntegerLength(arr[p]);
        byte[] ackDelay_arr = new byte[ackDelayLen];
        for(int n = p;n<p+ackDelayLen;n++){
            ackDelay_arr[n-p] = arr[n];
        }
        long ackDelay = Util.variableLengthInteger(ackDelay_arr,1);
        p=p+ackDelayLen;
        System.out.println("Ack delay = "+ackDelay);
        ///////////////////////////////////////
        int ackRangeCountLen = Util.variableLengthIntegerLength(arr[p]);
        byte[]  ackRangeCount_arr = new byte[ackRangeCountLen];
        for(int n= p; n<p+ackRangeCountLen;n++){
            ackRangeCount_arr[n-p] = arr[n];
        }
        long ackRangeCount = Util.variableLengthInteger(ackRangeCount_arr, 1);
        p=p+ackRangeCountLen;
        System.out.println("Ack Range Count  = "+ackRangeCount);
        //////////////////////////////////////////////////////////
        int firstAckRangeLen = Util.variableLengthIntegerLength(arr[p]);
        byte[] firstAckRange_arr = new byte[firstAckRangeLen];
        for(int n= p;n<p+firstAckRangeLen;n++){
            firstAckRange_arr[n-p]= arr[n];
        }
        long firstAckRange = Util.variableLengthInteger(firstAckRange_arr,1);
        p=p+firstAckRangeLen;
        System.out.println("first ACK range = "+firstAckRange);
        ////////////////////////////////////////////////////
        ArrayList<QuicAckRange> tempAckRanges = new ArrayList<>();
        for(long i=0;i<ackRangeCount;i++){
            int gapLen = Util.variableLengthIntegerLength(arr[p]);
            byte[] gap_arr = new byte[gapLen];
            for (int n = p;n<p+gapLen;n++){
                gap_arr[n-p]=arr[n];
            }
            long gap = Util.variableLengthInteger(gap_arr,1);
            p=p+gapLen;

            int ackRangeLen = Util.variableLengthIntegerLength(arr[p]);
            byte[] ackRange_arr = new byte[ackRangeLen];
            for (int n = p;n<p+ackRangeLen;n++){
                ackRange_arr[n-p]=arr[n];
            }
            long ackRange = Util.variableLengthInteger(ackRange_arr,1);
            p=p+ackRangeLen;


            tempAckRanges.add(new QuicAckRange(gap,ackRange));
        }

        QuicAckFrame quicAckFrame = new QuicAckFrame(largestAck,ackDelay,ackRangeCount,firstAckRange);
        for(QuicAckRange x : tempAckRanges){
            quicAckFrame.addAckRange(x);
        }
        return new DecodedFrame(quicAckFrame,p);


    }

    public static DecodedFrame quicStreamFrameDecoder(byte[] arr, byte headerByte,int index){
        boolean offbit=false;
        boolean lenBit = false;
        boolean finBit = false;
        if((headerByte & 4)>0){
            offbit = true;
        }
        if((headerByte & 2)>0){
            lenBit = true;
        }
        if((headerByte & 1)>0){
            finBit = true;
        }
        int p = index+1;
        int streamIdLen = Util.variableLengthIntegerLength(arr[p]);
        byte[] streamId_arr = new byte[streamIdLen];
        for(int n = p;n<p+streamIdLen;n++){
            streamId_arr[n-p] = arr[n];
        }
        long streamId = Util.variableLengthInteger(streamId_arr,1);
        p=p+streamIdLen;
        ///////////////////////////////////////
        long offset=0;
        if(offbit){
            int offsetLen = Util.variableLengthIntegerLength(arr[p]);
            byte[] offset_arr = new byte[offsetLen];
            for(int n = p;n<p+offsetLen;n++){
                offset_arr[n-p] = arr[n];
            }
            offset = Util.variableLengthInteger(offset_arr,1);
            p=p+offsetLen;
        }
        //////////////////////////////////////
        long streamDataLength = 0;
        if(lenBit){
            int streamDataLengthLen = Util.variableLengthIntegerLength(arr[p]);
            byte[] streamDataLength_arr = new byte[streamDataLengthLen];
            for(int n = p;n<p+streamDataLengthLen;n++){
                streamDataLength_arr[n-p] = arr[n];
            }
            streamDataLength = Util.variableLengthInteger(streamDataLength_arr,1);
            p=p+streamDataLengthLen;
        }else{
            streamDataLength = arr.length - p;
        }
        byte[] streamData = new byte[(int)streamDataLength];
        for(int n=p;n<p+streamDataLength;n++){
            streamData[n-p]=arr[n];
        }
        p=p+(int)streamDataLength;

        return new DecodedFrame(new QuicStreamFrame(streamId,offset,finBit,streamData),p);
    }

    public static DecodedFrame quicCryptoFrameDecoder(byte[] arr,int index){
        System.out.println("-------------Crypto frame--------------");
        int p = index+1;
        int offsetLen =  Util.variableLengthIntegerLength(arr[p]);
        byte[] offset_arr = new byte[offsetLen];
        for (int n=p;n<p+offsetLen;n++){
            offset_arr[n-p]=arr[n];
        }
        long offset = Util.variableLengthInteger(offset_arr,1);
        p=p+offsetLen;
        System.out.println("offset "+offset);
        //////////////////////////////////////////////
        int tempCryptoDataLen = Util.variableLengthIntegerLength(arr[p]);
        byte[] length_arr = new byte[tempCryptoDataLen];
        for(int n=p;n<p+tempCryptoDataLen;n++){
            length_arr[n-p]=arr[n];
        }
        long cryptoDataLength = Util.variableLengthInteger(length_arr,1);
        p=p+tempCryptoDataLen;
        System.out.println("cryptoDtaLength "+cryptoDataLength);
        ///////////////////////////////////
        byte[] cryptoData = new byte[(int) cryptoDataLength];
        for(int i=p;i<p+cryptoDataLength;i++){
            cryptoData[i-p]=arr[i];
            //System.out.println("cryptoData "+cryptoData[]);
        }
        p=p+(int)cryptoDataLength;


        return new DecodedFrame(new QuicCryptoFrame(offset,cryptoData),p);

    }

    public static DecodedFrame quicConnectionCloseFrameDecoder(byte[] arr, int index){
        int p = index+1;
        int errorCodeLen =  Util.variableLengthIntegerLength(arr[p]);
        byte[] errorCode_arr = new byte[errorCodeLen];
        for (int n=p;n<p+errorCodeLen;n++){
            errorCode_arr[n-p]=arr[n];
        }
        long errorCode = Util.variableLengthInteger(errorCode_arr,1);
        p=p+errorCodeLen;
        ///////////////////////////////////////////////
        int frameTypeLen =  Util.variableLengthIntegerLength(arr[p]);
        byte[] frameType_arr = new byte[frameTypeLen];
        for (int n=p;n<p+frameTypeLen;n++){
            frameType_arr[n-p]=arr[n];
        }
        long frameType = Util.variableLengthInteger(frameType_arr,1);
        p=p+frameTypeLen;

        ///////////////////////////////////////////////
        int tempReasonLength =  Util.variableLengthIntegerLength(arr[p]);
        byte[] reasonLen_arr = new byte[tempReasonLength];
        for (int n=p;n<p+tempReasonLength;n++){
            reasonLen_arr[n-p]=arr[n];
        }
        long reasonLength = Util.variableLengthInteger(frameType_arr,1);
        p=p+tempReasonLength;
        ////////////////////////////////////////
        byte[] reasonPhrase=new byte[0];
        if(reasonLength>0){
            reasonPhrase= new byte[(int) reasonLength];
            for(int i=p;i<p+reasonLength;i++){
                reasonPhrase[i-p]=arr[i];
            }
        }
        p=p+(int)reasonLength;
        String reasonP = null;
        try{
            reasonP = new String(reasonPhrase,"UTF-8");
        }catch (Exception e){

        }

        return new DecodedFrame(new QuicConnectionCloseFrame(errorCode,frameType,reasonP),p);

    }





    ///////////////////////////////////////////

    public static long decodePacketNumber(long truncatedPacketNumber, long largestPacketNumber, int bits) {
        long expectedPacketNumber = largestPacketNumber + 1;
        long pnWindow = 1L << bits;
        long pnHalfWindow = pnWindow / 2;
        long pnMask = ~ (pnWindow - 1);

        long candidatePn = (expectedPacketNumber & pnMask) | truncatedPacketNumber;
        if (candidatePn <= expectedPacketNumber - pnHalfWindow && candidatePn < (1 << 62) - pnWindow) {
            return candidatePn + pnWindow;
        }
        if (candidatePn > expectedPacketNumber + pnHalfWindow && candidatePn >= pnWindow) {
            return candidatePn - pnWindow;
        }

        return candidatePn;
    }

   public static byte[] decryptPayload(byte[] message, byte[] associatedData, long packetNumber, Keys secrets) throws QuicException {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong(packetNumber);

        byte[] writeIV = secrets.getWriteIV();
        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ writeIV[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(secrets.getWriteKey(), "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116  5.3
            aeadCipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicException(0,0,"decrypt payload exception");
        } catch (AEADBadTagException decryptError) {
            throw new QuicException(0,0,"dycrypt payload exception");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }

    }


}

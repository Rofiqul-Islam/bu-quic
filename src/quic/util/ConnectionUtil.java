package quic.util;

import quic.exception.QuicException;
import quic.main.Keys;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ConnectionUtil {

    public static void protectPacketNumberAndPayload(ByteBuffer packetBuffer, byte[] packetNumber, ByteBuffer payload, int paddingSize, Keys clientSecrets) throws QuicException {
        int packetNumberPosition = packetBuffer.position() - packetNumber.length;

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The associated data, A, for the AEAD is the contents of the QUIC
        //   header, starting from the flags octet in either the short or long
        //   header, up to and including the unprotected packet number."
        int additionalDataSize = packetBuffer.position();
        byte[] additionalData = new byte[additionalDataSize];
        packetBuffer.flip();  // Prepare for reading from start
        packetBuffer.get(additionalData);  // Position is now where it was at start of this method.
        packetBuffer.limit(packetBuffer.capacity());  // Ensure we can continue writing

        byte[] paddedPayload = new byte[payload.limit() + paddingSize];
        payload.get(paddedPayload, 0, payload.limit());
        byte[] encryptedPayload = encryptPayload(paddedPayload, additionalData, Util.variableLengthInteger(packetNumber, 0), clientSecrets);
        packetBuffer.put(encryptedPayload);

        byte[] protectedPacketNumber;

        byte[] mask = createHeaderProtectionMask(encryptedPayload, packetNumber.length, clientSecrets);

        protectedPacketNumber = new byte[packetNumber.length];
        for (int i = 0; i < packetNumber.length; i++) {
            protectedPacketNumber[i] = (byte) (packetNumber[i] ^ mask[1+i]);
        }

        byte flags = packetBuffer.get(0);
        if ((flags & 0x80) == 0x80) {
            // Long header: 4 bits masked
            flags ^= mask[0] & 0x0f;
        }
        else {
            // Short header: 5 bits masked
            flags ^= mask[0] & 0x1f;
        }
        packetBuffer.put(0, flags);

        int currentPosition = packetBuffer.position();
        packetBuffer.position(packetNumberPosition);
        packetBuffer.put(protectedPacketNumber);
        packetBuffer.position(currentPosition);
    }



    public  static byte[] encryptPayload(byte[] message, byte[] associatedData, long packetNumber, Keys secrets) throws QuicException {

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The nonce, N, is formed by combining the packet
        //   protection IV with the packet number.  The 64 bits of the
        //   reconstructed QUIC packet number in network byte order are left-
        //   padded with zeros to the size of the IV.  The exclusive OR of the
        //   padded packet number and the IV forms the AEAD nonce"
        byte[] writeIV = secrets.getWriteIV();
        ByteBuffer nonceInput = ByteBuffer.allocate(writeIV.length);
        for (int i = 0; i < nonceInput.capacity() - 8; i++)
            nonceInput.put((byte) 0x00);
        nonceInput.putLong(packetNumber);

        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ writeIV[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(secrets.getWriteKey(), "AES");
            // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
            // "Prior to establishing a shared secret, packets are protected with AEAD_AES_128_GCM"
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116  5.3
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            aeadCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            aeadCipher.updateAAD(associatedData);
            byte[] cipherText = aeadCipher.doFinal(message);
            return cipherText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicException(0,0,"encryption exception");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    byte[] decryptPayload(byte[] message, byte[] associatedData, long packetNumber, Keys secrets) throws  QuicException {
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
            throw new QuicException(0,0,"Decryption exception");
        } catch (AEADBadTagException decryptError) {
            throw new QuicException(0,0,"decryption exception");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }

    }

    public static byte[] createHeaderProtectionMask(byte[] ciphertext, int encodedPacketNumberLength, Keys secrets) throws QuicException {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4
        // "The same number of bytes are always sampled, but an allowance needs
        //   to be made for the endpoint removing protection, which will not know
        //   the length of the Packet Number field.  In sampling the packet
        //   ciphertext, the Packet Number field is assumed to be 4 bytes long
        //   (its maximum possible encoded length)."
        int sampleOffset = 4 - encodedPacketNumberLength;
        byte[] sample = new byte[16];
        System.arraycopy(ciphertext, sampleOffset, sample, 0, 16);
        byte[] mask = encryptAesEcb(secrets.getHp(), sample);
        return mask;
    }

    public static byte[] encryptAesEcb(byte[] key, byte[] value) throws QuicException {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            byte[] encrypted = cipher.doFinal(value);
            return encrypted;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicException(0,0,"encryptAesEcb exception");
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

}

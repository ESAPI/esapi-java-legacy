package org.owasp.esapi.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.UnsupportedEncodingException;
import java.util.Date;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.util.ByteConversionUtil;
import org.owasp.esapi.errors.EncryptionException;

/**
 * Helper class to assist with programming language and platform independent
 * serialization of {@link CipherText} objects. The serialization is done in
 * network-byte order which is the same as big-endian byte order.
 * 
 * @author kevin.w.wall@gmail.com
 *
 */
public class CipherTextSerializer {
    // This should be *same* version as in CipherText. If one changes, the
    // other should as well to accommodate any differences.
    private static final long serialVersionUID = 20100122; // Format: YYYYMMDD

    private static final Logger logger = ESAPI.getLogger("CipherTextSerializer");
    
    private CipherText cipherText_ = null;
    
    public CipherTextSerializer(CipherText cipherTextObj) {
        assert cipherTextObj != null : "CipherText object must not be null.";
        assert serialVersionUID == CipherText.getSerialVersionUID() :
            "Version of CipherText and CipherTextSerializer not compatible.";
        cipherText_ = cipherTextObj;
    }
    
    /**
     * Given byte array in network byte order (i.e., big-endian order), convert
     * it so that a {@code CipherText} can be constructed from it.
     * @param cipherTextSerializedBytes A serialized {@code CipherText} object
     *          with the bytes in network byte order.
     * @throws EncryptionException Thrown if a valid {@code CipherText} object
     *          cannot be reconstructed from the byte array.
     */
    public CipherTextSerializer(byte[] cipherTextSerializedBytes)
        throws EncryptionException /* DISCUSS: Change exception type?? */
    {
        assert serialVersionUID == CipherText.getSerialVersionUID() :
            "Version of CipherText and CipherTextSerializer not compatible.";
        cipherText_ = convertToCipherText(cipherTextSerializedBytes);
    }

    /** Return this {@code CipherText} object as a specialized, portable
     *  serialized byte array.
     * @return A serialization of this object. Note that this is <i>not</i> the
     * Java serialization.
     */
    @SuppressWarnings("static-access")
    public byte[] asSerializedByteArray() {
        long vers = cipherText_.getSerialVersionUID(); // static method
        long timestamp = cipherText_.getEncryptionTimestamp();
        String cipherXform = cipherText_.getCipherTransformation();
        assert cipherText_.getKeySize() < Short.MAX_VALUE :
                            "Key size too large. Max is " + Short.MAX_VALUE;
        short keySize = (short) cipherText_.getKeySize();
        assert cipherText_.getBlockSize() < Short.MAX_VALUE :
                            "Block size too large. Max is " + Short.MAX_VALUE;
        short blockSize = (short) cipherText_.getBlockSize();
        byte[] iv = cipherText_.getIV();
        assert iv.length < Short.MAX_VALUE :
                            "IV size too large. Max is " + Short.MAX_VALUE;
        short ivLen = (short) iv.length;
        byte[] rawCiphertext = cipherText_.getRawCipherText();
        int ciphertextLen = rawCiphertext.length;
        assert ciphertextLen >= 1 : "Raw ciphertext length must be >= 1 byte.";
        byte[] mac = cipherText_.getSeparateMAC();
        assert mac.length < Short.MAX_VALUE :
                            "MAC length too large. Max is " + Short.MAX_VALUE;
        short macLen = (short) mac.length;
        
        byte[] serializedObj = computeSerialization(vers,
                                                    timestamp,
                                                    cipherXform,
                                                    keySize,
                                                    blockSize,
                                                    ivLen,
                                                    iv,
                                                    ciphertextLen,
                                                    rawCiphertext,
                                                    macLen,
                                                    mac
                                                   );
        
        return serializedObj;
    }
    
    public CipherText asCipherText() {
        return cipherText_;
    }
      
    private byte[] computeSerialization(long vers, long timestamp,
                                        String cipherXform, short keySize,
                                        short blockSize,
                                        short ivLen, byte[] iv,
                                        int ciphertextLen, byte[] rawCiphertext,
                                        short macLen, byte[] mac
                                       )
    {
        debug("computeSerialization: vers = " + vers);
        debug("computeSerialization: timestamp = " + new Date(timestamp));
        debug("computeSerialization: cipherXform = " + cipherXform);
        debug("computeSerialization: keySize = " + keySize);
        debug("computeSerialization: blockSize = " + blockSize);
        debug("computeSerialization: ivLen = " + ivLen);
        debug("computeSerialization: ciphertextLen = " + ciphertextLen);
        debug("computeSerialization: macLen = " + macLen);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeLong(baos, vers);
        writeLong(baos, timestamp);
        String[] parts = cipherXform.split("/");
        assert parts.length == 3 : "Malformed cipher transformation";
        writeString(baos, cipherXform); // Size of string is prepended to string
        writeShort(baos, keySize);
        writeShort(baos, blockSize);
        writeShort(baos, ivLen);
        if ( ivLen > 0 ) baos.write(iv, 0, iv.length);
        writeInt(baos, ciphertextLen);
        baos.write(rawCiphertext, 0, rawCiphertext.length);
        writeShort(baos, macLen);
        if ( macLen > 0 ) baos.write(mac, 0, mac.length);
        return baos.toByteArray();
    }
    
    // All strings are written as UTF-8 encoded byte streams with the
    // length prepended before it as a short.
    private void writeString(ByteArrayOutputStream baos, String str) {
        byte[] bytes;
        try {
            assert str != null && str.length() > 0;
            bytes = str.getBytes("UTF8");
            assert bytes.length < Short.MAX_VALUE : "writeString: String exceeds max length";
            writeShort(baos, (short)bytes.length);
            baos.write(bytes, 0, bytes.length);
        } catch (UnsupportedEncodingException e) {
            ; // Should never happen. UTF8 builtin to rt.jar
        }
        return;
    }
    
    private String readString(ByteArrayInputStream bais, short sz)
        throws NullPointerException, IOException
    {
        byte[] bytes = new byte[sz];
        int ret = bais.read(bytes, 0, sz);
        assert ret == sz : "readString: Failed to read " + sz + " bytes.";
        return new String(bytes, "UTF8");
    }
    
    private void writeShort(ByteArrayOutputStream baos, short s) {
        byte[] shortAsByteArray = ByteConversionUtil.fromShort(s);
        assert shortAsByteArray.length == 2;
        baos.write(shortAsByteArray, 0, 2);
        return;
    }
    
    private short readShort(ByteArrayInputStream bais)
        throws NullPointerException, IndexOutOfBoundsException
    {
        byte[] shortAsByteArray = new byte[2];
        int ret = bais.read(shortAsByteArray, 0, 2);
        assert ret == 2 : "readShort: Failed to read 2 bytes.";
        return ByteConversionUtil.toShort(shortAsByteArray);
    }
    
    private void writeInt(ByteArrayOutputStream baos, int i) {
        byte[] intAsByteArray = ByteConversionUtil.fromInt(i);
        baos.write(intAsByteArray, 0, 4);
        return;
    }
    
    private int readInt(ByteArrayInputStream bais)
        throws NullPointerException, IndexOutOfBoundsException
    {
        byte[] intAsByteArray = new byte[4];
        int ret = bais.read(intAsByteArray, 0, 4);
        assert ret == 4 : "readInt: Failed to read 4 bytes.";
        return ByteConversionUtil.toInt(intAsByteArray);
    }
    
    private void writeLong(ByteArrayOutputStream baos, long l) {
        byte[] longAsByteArray = ByteConversionUtil.fromLong(l);
        assert longAsByteArray.length == 8;
        baos.write(longAsByteArray, 0, 8);
        return;
    }
    
    private long readLong(ByteArrayInputStream bais)
        throws NullPointerException, IndexOutOfBoundsException
    {
        byte[] longAsByteArray = new byte[8];
        int ret = bais.read(longAsByteArray, 0, 8);
        assert ret == 8 : "readLong: Failed to read 8 bytes.";
        return ByteConversionUtil.toLong(longAsByteArray);
    }
    
    private CipherText convertToCipherText(byte[] cipherTextSerializedBytes)
        throws EncryptionException
    {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(cipherTextSerializedBytes);
            long vers = readLong(bais);
            debug("convertToCipherText: vers = " + vers);
            if ( vers != CipherText.getSerialVersionUID() ) {
                // NOTE: In future, support backward compatibility via this mechanism. As of now,
                //       this is first version so nothing to be backward compatible with. So any
                //       mismatch at this point is an error.
                throw new InvalidClassException("This serialized byte stream not compatible " +
                            "with loaded CipherText class. Version read = " + vers +
                            "; version from loaded CipherText class = " + CipherText.getSerialVersionUID());
            }
            long timestamp = readLong(bais);
            debug("convertToCipherText: timestamp = " + new Date(timestamp));
            short strSize = readShort(bais);
            debug("convertToCipherText: length of cipherXform = " + strSize);
            String cipherXform = readString(bais, strSize);
            debug("convertToCipherText: cipherXform = " + cipherXform);
            String[] parts = cipherXform.split("/");
            assert parts.length == 3 : "Malformed cipher transformation";
            String cipherMode = parts[1];
            if ( ! CryptoHelper.isAllowedCipherMode(cipherMode) ) {
                String msg = "Cipher mode " + cipherMode + " is not an allowed cipher mode";
                throw new EncryptionException(msg, msg);
            }
            short keySize = readShort(bais);
            debug("convertToCipherText: keySize = " + keySize);
            short blockSize = readShort(bais);
            debug("convertToCipherText: blockSize = " + blockSize);
            short ivLen = readShort(bais);
            debug("convertToCipherText: ivLen = " + ivLen);
            byte[] iv = null;
            if ( ivLen > 0 ) {
                iv = new byte[ivLen];
                bais.read(iv, 0, iv.length);
            }
            int ciphertextLen = readInt(bais);
            debug("convertToCipherText: ciphertextLen = " + ciphertextLen);
            assert ciphertextLen > 0 : "convertToCipherText: Invalid cipher text length";
            byte[] rawCiphertext = new byte[ciphertextLen];
            bais.read(rawCiphertext, 0, rawCiphertext.length);
            short macLen = readShort(bais);
            debug("convertToCipherText: macLen = " + macLen);
            byte[] mac = null;
            if ( macLen > 0 ) {
                mac = new byte[macLen];
                bais.read(mac, 0, mac.length);
            }

            CipherSpec cipherSpec = new CipherSpec(cipherXform, keySize);
            cipherSpec.setBlockSize(blockSize);
            cipherSpec.setIV(iv);
            debug("convertToCipherText: CipherSpec: " + cipherSpec);
            CipherText ct = new CipherText(cipherSpec);
            assert (ivLen > 0 && ct.requiresIV()) :
                    "convertToCipherText: Mismatch between IV length and cipher mode.";
            ct.setCiphertext(rawCiphertext);
              // Set this *AFTER* setting raw ciphertext because setCiphertext()
              // method also sets encryption time.
            ct.setEncryptionTimestamp(timestamp);
            if ( macLen > 0 ) {
                ct.storeSeparateMAC(mac);
            }
            return ct;
        } catch(EncryptionException ex) {
            throw new EncryptionException("Cannot deserialize byte array into CipherText object",
                                          "Cannot deserialize byte array into CipherText object",
                                          ex);
        } catch (IOException e) {
            throw new EncryptionException("Cannot deserialize byte array into CipherText object",
                    "Cannot deserialize byte array into CipherText object", e);
        }
    }
    
    private void debug(String msg) {
        if ( logger.isDebugEnabled() ) {
            logger.debug(Logger.EVENT_SUCCESS, msg);
        }
    }
}

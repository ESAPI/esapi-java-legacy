/*
 * OWASP Enterprise Security API (ESAPI) - Google issue # 306.
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2013 - The OWASP Foundation
 * ESAPI is published by OWASP under the new BSD license. You should read
 * and accept the LICENSE before you use, modify, and/or redistribute this
 * software.
 * 
 * Full credit for this JUnit to illustrate what is now Google Issue # 306
 * goes to Philippe Arteau <philippe.arteau@gmail.com>. Originally
 * published 2013/08/21 to ESAPI-DEV mailing list. Shows that both
 * ESAPI 2.0 and 2.0.1 is vulnerable. Minor tweaks by Kevin W. Wall.
 *
 * Original class name: SignatureByPassTest.
 * 
 * NOTE: If this test fails, your version of ESAPI is vulnerable (or you have
 * 		 it configured not to require a MAC which you should NOT do).
 */

package org.owasp.esapi.crypto;

import org.apache.commons.codec.binary.Hex;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.util.ByteConversionUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;


public class ESAPICryptoMACByPassTest {

    @Before
    public void setUp() throws NoSuchAlgorithmException, InvalidKeySpecException {
    	; // Do any prerequisite setup here.
    }

    @Test
    public void testMacBypass() throws EncryptionException, NoSuchFieldException, IllegalAccessException {

        byte[] bkey = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0xA,0x0B,0x0C,0x0D,0x0E,0x0F}; //Truly random key.
        SecretKey sk = new SecretKeySpec(bkey,"AES");

        //Encryption with MAC
        String originalMessage = "Cryptography!?!?";
        System.out.printf("Encrypting the message '%s'\n", originalMessage);
        	// Until there is a better way to do this. But this is much easier
        	// than having to set up a custom ESAPI.properties file just for
        	// this test.
        	//
        	// NOTE: Philippe Arteau's original exploit used "AES/OFB/NoPadding"
            //       so that one could see that the effect of the decryption would
        	//		 be "Craptography!?!?". However, if you wish to do that, then
        	//		 you must also change the ESAPI.properties file used by ESAPI
        	//		 JUnit tests sp that "OFB" is accepted as an allowed cipher
        	//		 mode. The easiest way to do that (if you are still not convinced)
        	//		 is to add "OFB" mode to Encryptor.cipher_modes.additional_allowed;
        	//		 e.g.,  Encryptor.cipher_modes.additional_allowed=CBC,OFB
        	//
        String origCipherXform =
        	ESAPI.securityConfiguration().setCipherTransformation("AES/CBC/NoPadding");
        CipherText ct = ESAPI.encryptor().encrypt(sk,new PlainText(originalMessage));
        ct.computeAndStoreMAC(sk);

        //Serialize the ciphertext in order to send it over the wire..
        byte[] serializedCt = ct.asPortableSerializedByteArray();

        //Malicious modification
        byte[] modifiedCt = tamperCipherText(serializedCt);

        //Decrypt
        CipherText modifierCtObj = CipherText.fromPortableSerializedBytes(modifiedCt);
        try {
        	ESAPI.securityConfiguration().setCipherTransformation(origCipherXform);
        		// This decryption should fail by throwing an EncryptionException
        		// if ESAPI crypto is NOT vulnerable and you never get to the
        		// subsequent lines in the try block.
            PlainText pt = ESAPI.encryptor().decrypt(sk,modifierCtObj);
            System.out.printf("Decrypting to '%s' (probably will look like garbage!)\n", new String(pt.asBytes()));
            System.out.println("This ESAPI version vulnerable to MAC by-pass described in Google issue # 306! Upgrade to latest version.");
            fail("This ESAPI version is vulnerable to MAC by-pass described in Google issue # 306! Upgrade to latest version.");
        } catch(EncryptionException eex) {
        	String errMsg = eex.getMessage();
        		// See private String DECRYPTION_FAILED in JavaEncryptor.
        	String expectedError = "Decryption failed; see logs for details.";
        	assertTrue( errMsg.equals(expectedError) );
        	System.out.println("testMacByPass(): Attempted decryption after MAC tampering failed.");
            System.out.println("Fix of issue # 306 successful. Crypto MAC by-pass test failed; exception was: [" + eex + "]");
        }
    }

    /**
     * The modification of the ciphertext is done in a separate method to show that only the generate CipherText object is use.
     * @param serializeCt
     */
    private byte[] tamperCipherText(byte[] serializeCt) throws EncryptionException, NoSuchFieldException, IllegalAccessException {
        CipherText ct = CipherText.fromPortableSerializedBytes(serializeCt);

        //Ciphertext metadata
        //System.out.println(ct.toString());

        byte[] cipherTextMod = ct.getRawCipherText();

        System.out.printf("Original ciphertext\t'%s'\n",String.valueOf(Hex.encodeHex(cipherTextMod)));

        cipherTextMod[2] ^= 'y' ^ 'a'; //Alter the 3rd character

        System.out.printf("Modify ciphertext\t'%s'\n",String.valueOf(Hex.encodeHex(cipherTextMod)));

        //MAC ... what MAC ?
        Field f2 = ct.getClass().getDeclaredField("separate_mac_");
        f2.setAccessible(true);
        f2.set(ct,null); //mac byte array set to null

        //Changing CT
        Field f3 = ct.getClass().getDeclaredField("raw_ciphertext_");
        f3.setAccessible(true);
        f3.set(ct,cipherTextMod);

        //return ct.asPortableSerializedByteArray(); //Will complain about missing mac
        //return new CipherTextSerializer(ct).asSerializedByteArray(); //NPE on mac.length
        return serialize(ct); //Modify version of CipherTextSerializer.asSerializedByteArray()
    }

    /////////////////////////////////////////////////////////////////////
    // The following code is a modified version of CipherTextSerializer
    /////////////////////////////////////////////////////////////////////

    private byte[] serialize(CipherText cipherText_) {
        int kdfInfo = cipherText_.getKDFInfo();

        long timestamp = cipherText_.getEncryptionTimestamp();
        String cipherXform = cipherText_.getCipherTransformation();

        short keySize = (short) cipherText_.getKeySize();

        short blockSize = (short)cipherText_.getBlockSize();
        byte[] iv = cipherText_.getIV();

        short ivLen = (short)iv.length;
        byte[] rawCiphertext = cipherText_.getRawCipherText();
        int ciphertextLen = rawCiphertext.length;

        byte[] mac = cipherText_.getSeparateMAC();

        short macLen = 0;//(short)mac.length; //<-------------- The only modification to the serialization

        return computeSerialization(kdfInfo, timestamp, cipherXform, keySize, blockSize, ivLen, iv, ciphertextLen, rawCiphertext, macLen, mac);
    }

    private byte[] computeSerialization(int kdfInfo, long timestamp, String cipherXform, short keySize, short blockSize, short ivLen, byte[] iv, int ciphertextLen, byte[] rawCiphertext, short macLen, byte[] mac)
    {
        debug("computeSerialization: kdfInfo = " + kdfInfo);
        debug("computeSerialization: timestamp = " + new Date(timestamp));
        debug("computeSerialization: cipherXform = " + cipherXform);
        debug("computeSerialization: keySize = " + keySize);
        debug("computeSerialization: blockSize = " + blockSize);
        debug("computeSerialization: ivLen = " + ivLen);
        debug("computeSerialization: ciphertextLen = " + ciphertextLen);
        debug("computeSerialization: macLen = " + macLen);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeInt(baos, kdfInfo);
        writeLong(baos, timestamp);
        String[] parts = cipherXform.split("/");
        assert (parts.length == 3) : "Malformed cipher transformation";
        writeString(baos, cipherXform);
        writeShort(baos, keySize);
        writeShort(baos, blockSize);
        writeShort(baos, ivLen);
        if (ivLen > 0) baos.write(iv, 0, iv.length);
        writeInt(baos, ciphertextLen);
        baos.write(rawCiphertext, 0, rawCiphertext.length);
        writeShort(baos, macLen);
        if (macLen > 0) baos.write(mac, 0, mac.length);
        return baos.toByteArray();
    }

    private static void debug(String msg) {
        // System.err.println(msg);
    }

    private void writeShort(ByteArrayOutputStream baos, short s) {
        byte[] shortAsByteArray = ByteConversionUtil.fromShort(s);
        assert (shortAsByteArray.length == 2);
        baos.write(shortAsByteArray, 0, 2);
    }

    private void writeInt(ByteArrayOutputStream baos, int i) {
        byte[] intAsByteArray = ByteConversionUtil.fromInt(i);
        baos.write(intAsByteArray, 0, 4);
    }

    private void writeLong(ByteArrayOutputStream baos, long l) {
        byte[] longAsByteArray = ByteConversionUtil.fromLong(l);
        assert (longAsByteArray.length == 8);
        baos.write(longAsByteArray, 0, 8);
    }

    private void writeString(ByteArrayOutputStream baos, String str)
    {
        try
        {
            assert ((str != null) && (str.length() > 0));
            byte[] bytes = str.getBytes("UTF8");
            assert (bytes.length < 32767) : "writeString: String exceeds max length";
            writeShort(baos, (short)bytes.length);
            baos.write(bytes, 0, bytes.length);
        }
        catch (UnsupportedEncodingException e)
        {
            System.err.println("writeString: " + e.getMessage());
        }
    }

}
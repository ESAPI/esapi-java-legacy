/*
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 */
package org.owasp.esapi.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.CipherText;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.reference.DefaultCipherText;

/**
 * Class to provide some convenience methods for encryption, decryption, etc.
 * </p><p>
 * All the cryptographic operations use the default cryptographic properties;
 * e.g., default cipher transformation, default key size, default IV type (if
 * applicable), etc.
 * 
 * @author kevin.w.wall@gmail.com
 * @since 2.0
 */
public class CryptoHelper {
	
	private static final Logger logger = ESAPI.getLogger("CryptoHelper");
	
	/**
	 * Convenience method that encrypts plaintext strings the new way (default
	 * is CBC mode and PKCS5 padding).
	 * @param plaintext	A String to be encrypted
	 * @return	A base64-encoded combination of IV + raw ciphertext
	 * @throws EncryptionException	Thrown when something goes wrong with the
	 * 								encryption.
	 * 
	 * @see org.owasp.esapi.Encryptor#encrypt(byte[])
	 */
	public static String encrypt(String plaintext) throws EncryptionException
	{
		CipherText ct = null;
		try {
			ct = ESAPI.encryptor().encrypt(plaintext.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// Should never happen; UTF-8 should be in rt.jar.
			logger.error(Logger.SECURITY_FAILURE, "UTF-8 encoding not available! Encryption failed.", e);
			return null;	// CHECKME: Or re-throw or what? Could also use native encoding, but that's
							// likely to cause unexpected and undesired effects far downstream.
		}
		return ct.getEncodedIVCipherText();
	}

	/**
	 * Convenience method that decrypts previously encrypted plaintext strings
	 * that were encrypted using the new encryption mechanism (with CBC mode and
	 * PKCS5 padding by default).
	 * @param b64IVCiphertext	A base64-encoded representation of the
	 * 							IV + raw ciphertext string to be decrypted with
	 * 							the default master key.
	 * @return	The plaintext string prior to encryption.
	 * @throws EncryptionException When something fails with the decryption.
	 * 
	 * @see org.owasp.esapi.Encryptor#decrypt(CipherText)
	 */
	public static String decrypt(String b64IVCiphertext) throws EncryptionException
	{
		DefaultCipherText ct = null;
		try {
			// We assume that the default cipher transform was used to encrypt this.
			ct = new DefaultCipherText();
			
			// Need to base64 decode the IV+ciphertext and extract the IV to set it in DefaultCipherText object.
			byte[] ivPlusRawCipherText = ESAPI.encoder().decodeFromBase64(b64IVCiphertext);
			int blockSize = ct.getBlockSize();	// Size in bytes.
			byte[] iv = new byte[ blockSize ];
			copyByteArray(ivPlusRawCipherText, iv, blockSize);	// Copy the first blockSize bytes into iv array
			int cipherTextSize = ivPlusRawCipherText.length - blockSize;
			byte[] rawCipherText = new byte[ cipherTextSize ];
			System.arraycopy(ivPlusRawCipherText, blockSize, rawCipherText, 0, cipherTextSize);
			ct.setIVandCiphertext(iv, rawCipherText);
			
			// Now the DefaultCipherText object should be prepared to use it to decrypt.
			byte[] plaintext = ESAPI.encryptor().decrypt(ct);
			return new String(plaintext, "UTF-8");	// Convert back to a Java String using UTF-8 encoding
		} catch (UnsupportedEncodingException e) {
			// Should never happen; UTF-8 should be in rt.jar.
			logger.error(Logger.SECURITY_FAILURE, "UTF-8 encoding not available! Decryption failed.", e);
			return null;	// CHECKME: Or re-throw or what? Could also use native encoding, but that's
							// likely to cause unexpected and undesired effects far downstream.
		} catch (IOException e) {
			logger.error(Logger.SECURITY_FAILURE, "Base64 decoding of IV+ciphertext failed. Decryption failed.", e);
			e.printStackTrace(System.err);
			return null;
		}
	}
	
	/**
	 * Generate a random secret key appropriate to the specified cipher algorithm
	 * and key size.
	 * @param alg	The cipher algorithm or cipher transformation. (If the latter is
	 * 				passed, the cipher algorithm is determined from it.)
	 * @param keySize	The key size, in bits.
	 * @return	A random {@code SecretKey} is returned.
	 * @throws EncryptionException Thrown if cannot create secret key conforming to
	 * 				requested algorithm with requested size.
	 */
	public static SecretKey generateSecretKey(String alg, int keySize)
		throws EncryptionException
	{
		assert( keySize > 0 );	// Usually should be even multiple of 8, but not strictly required by alg.
		
		// Don't use CipherSpec here to get algorithm as this may cause assertion
		// to fail (when enabled) if only algorithm name is passed to us.
		String[] cipherSpec = alg.split("/");
		String cipherAlg = cipherSpec[0];
		try {
			KeyGenerator kgen =
				KeyGenerator.getInstance( cipherAlg );
			kgen.init(keySize);
			return kgen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			throw new EncryptionException("Failed to generate random secret key",
					"Failed to generate secret key for " + alg + " with size of " + keySize + " bits.", e);
		}
	}
	
	/**
	 * Overwrite a byte array with a specified byte. This is frequently done
	 * to a plaintext byte array so the sensitive data is not lying around
	 * exposed in memory.
	 * @param bytes	The byte array to be overwritten.
	 * @param x The byte array {@code bytes} is overwritten with this byte.
	 */
	public static void overwrite(byte[] bytes, byte x)
	{
		for ( int i = 0; i < bytes.length; i++ ) {
			bytes[i] = x;
		}
	}
	
	/**
	 * Overwrite a byte array with the byte containing '*'. That is, call
	 * <pre>
	 * 		overwrite(bytes, (byte)'*');
	 * </pre>
	 * @param bytes The byte array to be overwritten.
	 */
	public static void overwrite(byte[] bytes)
	{
		overwrite(bytes, (byte)'*');
	}
	
	// These provide for a bit more type safety when copying bytes around.
	/**
	 * Same as {@code System.arraycopy(src, 0, dest, 0, length)}.
	 * 
     * @param      src      the source array.
     * @param      dest     the destination array.
     * @param      length   the number of array elements to be copied.
     * @exception  IndexOutOfBoundsException  if copying would cause
     *               access of data outside array bounds.
     * @exception  NullPointerException if either <code>src</code> or
     *               <code>dest</code> is <code>null</code>.
	 */
	public static void copyByteArray(final byte[] src, byte[] dest, int length)
	{
		System.arraycopy(src, 0, dest, 0, length);
	}
	
	/**
	 * Same as {@code copyByteArray(src, dest, src.length)}.
     * @param      src      the source array.
     * @param      dest     the destination array.
     * @exception  IndexOutOfBoundsException  if copying would cause
     *               access of data outside array bounds.
     * @exception  NullPointerException if either <code>src</code> or
     *               <code>dest</code> is <code>null</code>.
	 */
	public static void copyByteArray(final byte[] src, byte[] dest)
	{
		copyByteArray(src, dest, src.length);
	}
}

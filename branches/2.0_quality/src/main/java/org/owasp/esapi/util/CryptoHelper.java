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

import java.io.UnsupportedEncodingException;

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
 *
 */
public class CryptoHelper {
	
	private static final Logger logger = ESAPI.getLogger("CryptoHelper");
	
	/**
	 * Convenience method that encrypts plaintext strings the new way (default
	 * is CBC mode and PKCS5 padding).
	 * @param plaintext	A String to be encrypted
	 * @return	A base64-encoded combination of IV + raw ciphertext
	 * @throws EncryptionException
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
	
	public static String decrypt(String b64IVCiphertext) throws EncryptionException
	{
		CipherText ct = null;
		try {
			// We assume that the default cipher transform was used to encrypt this.
			ct = new DefaultCipherText();
			byte[] plaintext = ESAPI.encryptor().decrypt(ct);
			return new String(plaintext, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// Should never happen; UTF-8 should be in rt.jar.
			logger.error(Logger.SECURITY_FAILURE, "UTF-8 encoding not available! Encryption failed.", e);
			return null;	// CHECKME: Or re-throw or what? Could also use native encoding, but that's
							// likely to cause unexpected and undesired effects far downstream.
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

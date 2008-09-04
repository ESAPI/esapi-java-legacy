/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntegrityException;


/**
 * The Encryptor interface provides a set of methods for performing common
 * encryption, random number, and hashing operations. Implementations should
 * rely on a strong cryptographic implementation, such as JCE or BouncyCastle.
 * Implementors should take care to ensure that they initialize their
 * implementation with a strong "master key", and that they protect this secret
 * as much as possible.
 * <P>
 * <img src="doc-files/Encryptor.jpg" height="600">
 * <P>
 * Possible future enhancements (depending on feedback) might include:
 * <UL>
 * <LI>encryptFile</LI>
 * </UL>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Encryptor {

	/**
	 * Returns a string representation of the hash of the provided plaintext and
	 * salt. The salt helps to protect against a rainbow table attack by mixing
	 * in some extra data with the plaintext. Some good choices for a salt might
	 * be an account name or some other string that is known to the application
	 * but not to an attacker. See <a href="http://www.matasano.com/log/958/enough-with-the-rainbow-tables-what-you-need-to-know-about-secure-password-schemes/">this article</a> for 
	 * more information about hashing as it pertains to password schemes.
	 * 
	 * @param plaintext
	 *            the plaintext String to encrypt
	 * @param salt
	 *            the salt
	 * 
	 * @return the encrypted hash of 'plaintext' stored as a String
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	String hash(String plaintext, String salt) throws EncryptionException;

	/**
	 * Encrypts the provided plaintext and returns a ciphertext string.
	 * 
	 * @param plaintext
	 *            the plaintext String to encrypt
	 * 
	 * @return the encrypted String
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	String encrypt(String plaintext) throws EncryptionException;

	/**
	 * Decrypts the provided ciphertext string (encrypted with the encrypt
	 * method) and returns a plaintext string.
	 * 
	 * @param ciphertext
	 *            the ciphertext
	 * 
	 * @return the decrypted ciphertext
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	String decrypt(String ciphertext) throws EncryptionException;

	/**
	 * Create a digital signature for the provided data and return it in a
	 * string.
	 * 
	 * @param data
	 *            the data to sign
	 * 
	 * @return the digital signature stored as a String
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	String sign(String data) throws EncryptionException;

	/**
	 * Verifies a digital signature (created with the sign method) and returns
	 * the boolean result.
	 * 
	 * @param signature
	 *            the signature to verify
	 * @param data
	 *            the data to verify
	 * 
	 * @return true, if the signature is verified
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	boolean verifySignature(String signature, String data);

	/**
	 * Creates a seal that binds a set of data and includes an expiration timestamp.
	 * 
	 * @param data
	 *            the data to seal
	 * @param timestamp
	 *            the absolute expiration date of the data, expressed as seconds since the epoch
	 * 
	 * @return the seal
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	String seal(String data, long timestamp) throws IntegrityException;

	/**
	 * Unseals data (created with the seal method) and throws an exception
	 * describing any of the various problems that could exist with a seal, such
	 * as an invalid seal format, expired timestamp, or decryption error.
	 * 
	 * @param seal
	 *            the sealed data
	 * 
	 * @return the original data
	 * 
	 * @throws ExcryptionException if the unsealed data cannot be retrieved for any reason
	 */
	String unseal( String seal ) throws EncryptionException;
	
	/**
	 * Verifies a seal (created with the seal method) and throws an exception
	 * describing any of the various problems that could exist with a seal, such
	 * as an invalid seal format, expired timestamp, or data mismatch.
	 * 
	 * @param seal
	 *            the seal
	 * 
	 * @return true, if the seal is valid
	 */
	boolean verifySeal(String seal);

	
	/**
	 * Gets an absolute timestamp representing an offset from the current time to be used by
	 * other functions in the library.
	 * 
	 * @param offset 
	 * 		the offset to add to the current time
	 * 
	 * @return the absolute timestamp
	 */
	public long getRelativeTimeStamp( long offset );
	
	
	/**
	 * Gets a timestamp representing the current date and time to be used by
	 * other functions in the library.
	 * 
	 * @return the timestamp
	 */
	long getTimeStamp();

}

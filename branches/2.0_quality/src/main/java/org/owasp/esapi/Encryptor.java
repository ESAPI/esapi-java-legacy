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

import javax.crypto.SecretKey;

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
 * <img src="doc-files/Encryptor.jpg">
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
	 * but not to an attacker. 
	 * See <a href="http://www.matasano.com/log/958/enough-with-the-rainbow-tables-what-you-need-to-know-about-secure-password-schemes/">
	 * this article</a> for more information about hashing as it pertains to password schemes.
	 * 
	 * @param plaintext
	 * 		the plaintext String to encrypt
	 * @param salt
	 *      the salt to add to the plaintext String before hashing
	 * 
	 * @return 
	 * 		the encrypted hash of 'plaintext' stored as a String
	 * 
	 * @throws EncryptionException
	 *      if the specified hash algorithm could not be found or another problem exists with 
	 *      the hashing of 'plaintext'
	 */
	String hash(String plaintext, String salt) throws EncryptionException;

	/**
	 * Returns a string representation of the hash of the provided plaintext and
	 * salt. The salt helps to protect against a rainbow table attack by mixing
	 * in some extra data with the plaintext. Some good choices for a salt might
	 * be an account name or some other string that is known to the application
	 * but not to an attacker. 
	 * See <a href="http://www.matasano.com/log/958/enough-with-the-rainbow-tables-what-you-need-to-know-about-secure-password-schemes/">
	 * this article</a> for more information about hashing as it pertains to password schemes.
	 * 
	 * @param plaintext
	 * 		the plaintext String to encrypt
	 * @param salt
	 *      the salt to add to the plaintext String before hashing
	 * @param iterations
	 *      the number of times to iterate the hash
	 * 
	 * @return 
	 * 		the encrypted hash of 'plaintext' stored as a String
	 * 
	 * @throws EncryptionException
	 *      if the specified hash algorithm could not be found or another problem exists with 
	 *      the hashing of 'plaintext'
	 */
	String hash(String plaintext, String salt, int iterations) throws EncryptionException;
	
	/**
	 * Encrypts the provided plaintext and returns a ciphertext string.
	 * </p><p>
	 * This method uses the Electronic Code Book (ECB) cipher mode to encrypt,
	 * which in the general case is not secure and usually should be avoided. It
	 * is provided only for backward compatibility with ESAPI Java 1.4 code
	 * and earlier. You should stop using this method an use the newer
	 * encryption method (see deprecation warning) as soon as possible.
	 * </p><p>
	 * This method will likely be removed in some future ESAPI Java release.
	 * 
	 * @param plaintext
	 *      the plaintext String to encrypt
	 * 
	 * @return 
	 * 		the encrypted, base64-encoded String representation of 'plaintext'
	 * 
	 * @throws EncryptionException
	 *      if the specified encryption algorithm could not be found or another problem exists with 
	 *      the encryption of 'plaintext'
	 * 
	 * @see org.owasp.esapi.util.CryptoHelper#encrypt(String)
	 * 
	 * @deprecated As of ESAPI 2.0, replaced by {@link #encrypt(byte[])}
	 */
	@Deprecated String encrypt(String plaintext) throws EncryptionException;

	/**
	 * Encrypts the provided plaintext bytes using the cipher transformation
	 * specified by the property <code>Encryptor.CipherTransformation</code>
	 * and the <i>master encryption key</i> as specified by the property
	 * {@code Encryptor.MasterKey} as defined in the <code>ESAPI.properties</code> file.
	 * </p><p>
	 * This method is preferred over {@link #encrypt(String)} because it also
	 * allows encrypting of general byte streams rather than simply strings and
	 * also because it returns a {@code CipherText} object and thus supports
	 * cipher modes that require an Initialization Vector (IV), such as
	 * Cipher Block Chaining (CBC).
	 * 
	 * @param plaintext	The byte stream to be encrypted. Note if a Java
	 * 				{@code String} is to be encrypted, it should be converted
	 * 				using {@code "some string".getBytes("UTF-8")}.
	 * @return the {@code CipherText} object from which the raw ciphertext, the
	 * 				IV, the cipher transformation, and many other aspects about
	 * 				the encryption detail may be extracted.
	 * @throws EncryptionException Thrown if something should go wrong such as
	 * 				the JCE provider cannot be found, the cipher algorithm,
	 * 				cipher mode, or padding scheme not being supported, specifying
	 * 				an unsupported key size, specifying an IV of incorrect length,
	 * 				etc.
	 * @see #encrypt(SecretKey, byte[], boolean, boolean)
	 */
	 CipherText encrypt(byte[] plaintext) throws EncryptionException;


	 /**
	  * Encrypts the provided plaintext bytes using the cipher transformation
	  * specified by the property <code>Encryptor.CipherTransformation</code>
	  * as defined in the <code>ESAPI.properties</code> file and the
	  * <i>specified secret key</i>.
	  * </p><p>
	  * This method is similar to {@link #encrypt(byte[])} except that it
	  * permits a specific {@code SecretKey} to be used for encryption.
	  *
	  * @param key		The {@code SecretKey} to use for encrypting the plaintext.
	  * @param plaintext	The byte stream to be encrypted. Note if a Java
	  * 				{@code String} is to be encrypted, it should be converted
	  * 				using {@code "some string".getBytes("UTF-8")}.
	  * @param overwriteKey		If {@code true}, the {@code key} is overwritten
	  * 				after the encryption is finished successfully. Only set
	  * 				to true if the key has safely been saved elsewhere or by
	  * 				the intended recipient of the encrypted message.
	  * @param overwritePlaintext	f {@code true}, the {@code plaintext} is
	  * 				overwritten after the encryption has finished successfully.
	  * 				Only set this to true if you have no longer need the plaintext
	  * 				after accessing it. The purpose of this flag is to help protect
	  * 				against an adversary of gleaning sensitive data from memory or
	  * 				a core dump.
	  * @return the {@code CipherText} object from which the raw ciphertext, the
	  * 				IV, the cipher transformation, and many other aspects about
	  * 				the encryption detail may be extracted.
	  * @throws EncryptionException Thrown if something should go wrong such as
	  * 				the JCE provider cannot be found, the cipher algorithm,
	  * 				cipher mode, or padding scheme not being supported, specifying
	  * 				an unsupported key size, specifying an IV of incorrect length,
	  * 				etc.
	  * @see #encrypt(byte[])
	  */
	 CipherText encrypt(SecretKey key, byte[] plaintext, boolean overwriteKey, boolean overwritePlaintext)
	 throws EncryptionException;

	/**
	 * Decrypts the provided ciphertext string (encrypted with the encrypt
	 * method) and returns a plaintext string.
	 * </p><p>
	 * This is the decryption method that corresponds to the deprecated
	 * {@link #encrypt(String)} method. It should only be used if you cannot
	 * remove references to this deprecated encryption method. This method
	 * expects ciphertext that was encrypted using the Electronic Code Book
	 * (ECB) cipher mode which in the general case is not secure and should be
	 * avoided.
	 * </p><p>
	 * This method is provided only for backward compatibility with ESAPI
	 * Java 1.4 code and earlier. You should stop using these deprecated
	 * encryption / decryption methods an use the newer encryption / 
	 * decryption methods (see deprecation warning) as soon as possible.
	 * </p><p>
	 * This method will likely be removed in some future ESAPI Java release.
	 * 
	 * @param ciphertext
	 *      the ciphertext (encrypted plaintext)
	 * 
	 * @return 
	 * 		the decrypted ciphertext
	 * 
	 * @throws EncryptionException
	 *      if the specified encryption algorithm could not be found or another problem exists with 
	 *      the decryption of 'plaintext'
	 * 
	 * @see org.owasp.esapi.util.CryptoHelper#decrypt(String)
	 * 
	 * @deprecated As of ESAPI 2.0, replaced by {@link #decrypt(CipherText)}s
	 */
	@Deprecated String decrypt(String ciphertext) throws EncryptionException;

	/**
	 * Decrypts the provided {@link CipherText} using the information from it
	 * and the <i>master encryption key</i> as specified by the property
	 * {@code Encryptor.MasterKey} as defined in the {@code ESAPI.properties}
	 * file.
	 * </p><p>
	 * This decrypt method is to be preferred over the deprecated
	 * {@link #decrypt(String)} method because this method can handle plaintext
	 * bytes that were encrypted with cipher modes requiring IVs, such as CBC.
	 * </p>
	 * @param ciphertext The {@code CipherText} object to be decrypted.
	 * @return The plaintext byte array resulting from decrypting the specified
	 * 		   ciphertext. Note that it it is desired to convert the returned
	 * 		   plaintext byte array to a Java String is should be done using
	 * 		   {@code new String(byte[], "UTF-8");} rather than simply using
	 * 		   {@code new String(byte[]);} which uses native encoding and may
	 * 		   not be portable across hardware and/or OS platforms.
	 * @throws EncryptionException  Thrown if something should go wrong such as
	 * 				the JCE provider cannot be found, the cipher algorithm,
	 * 				cipher mode, or padding scheme not being supported, specifying
	 * 				an unsupported key size, or incorrect encryption key was
	 * 				specified or a {@code PaddingException} occurs.
	 * @see #decrypt(SecretKey, CipherText)
	 */
	byte[] decrypt(CipherText ciphertext) throws EncryptionException;
	
	/**
	 * Decrypts the provided {@link CipherText} using the information from it
	 * and the <i>specified secret key</i>.
	 * </p><p>
	 * This decrypt method is similar to {@link #decrypt(CipherText)} except that
	 * it allows decrypting with a secret key other than the <i>master secret key</i>.
	 * </p>
	 * @param key		The {@code SecretKey} to use for encrypting the plaintext.
	 * @param ciphertext The {@code CipherText} object to be decrypted.
	 * @return The plaintext byte array resulting from decrypting the specified
	 * 		   ciphertext. Note that it it is desired to convert the returned
	 * 		   plaintext byte array to a Java String is should be done using
	 * 		   {@code new String(byte[], "UTF-8");} rather than simply using
	 * 		   {@code new String(byte[]);} which uses native encoding and may
	 * 		   not be portable across hardware and/or OS platforms.
	 * @throws EncryptionException  Thrown if something should go wrong such as
	 * 				the JCE provider cannot be found, the cipher algorithm,
	 * 				cipher mode, or padding scheme not being supported, specifying
	 * 				an unsupported key size, or incorrect encryption key was
	 * 				specified or a {@code PaddingException} occurs.
	 * @see #decrypt(CipherText)
	 */
	byte[] decrypt(SecretKey key, CipherText ciphertext) throws EncryptionException;
	
	/**
	 * Create a digital signature for the provided data and return it in a
	 * string.
	 * 
	 * @param data
	 *      the data to sign
	 * 
	 * @return 
	 * 		the digital signature stored as a String
	 * 
	 * @throws EncryptionException
	 * 		if the specified signature algorithm cannot be found
	 */
	String sign(String data) throws EncryptionException;

	/**
	 * Verifies a digital signature (created with the sign method) and returns
	 * the boolean result.
	 * 
	 * @param signature
	 *      the signature to verify against 'data'
	 * @param data
	 *      the data to verify against 'signature'
	 * 
	 * @return 
	 * 		true, if the signature is verified, false otherwise
	 * 
	 */
	boolean verifySignature(String signature, String data);

	/**
	 * Creates a seal that binds a set of data and includes an expiration timestamp.
	 * 
	 * @param data
	 *      the data to seal
	 * @param timestamp
	 *      the absolute expiration date of the data, expressed as seconds since the epoch
	 * 
	 * @return 
     * 		the seal
     * @throws IntegrityException
	 * 
	 */
	String seal(String data, long timestamp) throws IntegrityException;

	/**
	 * Unseals data (created with the seal method) and throws an exception
	 * describing any of the various problems that could exist with a seal, such
	 * as an invalid seal format, expired timestamp, or decryption error.
	 * 
	 * @param seal
	 *      the sealed data
	 * 
	 * @return 
	 * 		the original (unsealed) data
	 * 
	 * @throws EncryptionException 
	 * 		if the unsealed data cannot be retrieved for any reason
	 */
	String unseal( String seal ) throws EncryptionException;
	
	/**
	 * Verifies a seal (created with the seal method) and throws an exception
	 * describing any of the various problems that could exist with a seal, such
	 * as an invalid seal format, expired timestamp, or data mismatch.
	 * 
	 * @param seal
	 *      the seal to verify
	 * 
	 * @return 
	 * 		true, if the seal is valid.  False otherwise
	 */
	boolean verifySeal(String seal);
	
	/**
	 * Gets an absolute timestamp representing an offset from the current time to be used by
	 * other functions in the library.
	 * 
	 * @param offset 
	 * 		the offset to add to the current time
	 * 
	 * @return 
	 * 		the absolute timestamp
	 */
	public long getRelativeTimeStamp( long offset );
	
	
	/**
	 * Gets a timestamp representing the current date and time to be used by
	 * other functions in the library.
	 * 
	 * @return 
	 * 		a timestamp representing the current time
	 */
	long getTimeStamp();

}

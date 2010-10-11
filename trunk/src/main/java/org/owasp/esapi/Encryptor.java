/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright &copy; 2007,2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author kevin.w.wall@gmail.com
 * @created 2007
 */
package org.owasp.esapi;

import javax.crypto.SecretKey;

import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.PlainText;
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
	 * Encrypts the provided plaintext and returns a ciphertext string using the
	 * master secret key and default cipher transformation.
	 * </p><p>
	 * <b>Compatibility with earlier ESAPI versions:</b> Unlike ESAPI 1.4 version
	 * of this method which used the Electronic Code Book (ECB)
	 * cipher mode to encrypt, this method uses the default cipher transformation
	 * and IV type (which by default is AES/CBC/PKCS5Padding and a random IV). ECB mode
	 * is not secure for general use and usually should be avoided. If you <b>must</b>
	 * use ECB mode for backward compatibility, you should do so by specifying
	 * <pre>
	 * 		ESAPI.Encryptor=org.owasp.esapi.reference.LegacyJavaEncryptor
	 * </pre>
	 * in your <b>ESAPI.properties</b> file rather than changing the default
	 * cipher transformation. That will make this method and the
	 * {@link #decrypt(String)} method use ECB mode in a manner that is compatible
	 * with ESAPI 1.4 and earlier but not affect the newer encryption / decryption
	 * methods. However, this should only be used for backward compatibility. You
	 * should use it to decrypt data that was previous encrypted using ESAPI 1.4 or
	 * earlier use a newer method that uses the stronger CBC cipher mode
	 * to re-encrypt it. Once all the previously encrypted data has been re-encrypted
	 * using this legacy class, you should stop using this legacy class and start
	 * using the default reference class, as per:
	 * <pre>
	 * 		ESAPI.Encryptor=org.owasp.esapi.reference.LegacyJavaEncryptor
	 * </pre>
	 * in your <b>ESAPI.properties</b> file. 
	 * </p><p>
	 * <b>Why this method is deprecated:</b> Most cryptographers strongly suggest
	 * that if you are creating crypto functionality for general-purpose use,
	 * at a minimum you should ensure that it provides authenticity, integrity,
	 * and confidentiality. This method only provides confidentiality, but not
	 * authenticity or integrity. Therefore, you are encouraged to use
	 * one of the other encryption methods referenced below. Because this
	 * method provides neither authenticity nor integrity, it may be
	 * removed in some future ESAPI Java release. Note: there are some cases
	 * where authenticity / integrity are not that important. For instance, consider
	 * a case where the encrypted data is never out of your application's control. For
	 * example, if you receive data that your application is encrypting itself and then
	 * storing the encrypted data in its own database for later use (and no other
	 * applications can query or update that column of the database), providing
	 * confidentiality alone might be sufficient. However, if there are cases
	 * where your application will be sending or receiving already encrypted data
	 * over an insecure, unauthenticated channel, in such cases authenticity and
	 * integrity of the encrypted data likely is important and this method should
	 * be avoided in favor of one of the other two.
	 * 
	 * @param plaintext
	 *      the plaintext {@code String} to encrypt. Note that if you are encrypting
	 *      general bytes, you should encypt that byte array to a String using
	 *      "UTF-8" encoding.
	 * 
	 * @return 
	 * 		the encrypted, base64-encoded String representation of 'plaintext' plus
	 * 		the random IV used.
	 * 
	 * @throws EncryptionException
	 *      if the specified encryption algorithm could not be found or another problem exists with 
	 *      the encryption of 'plaintext'
	 * 
	 * @see #encrypt(PlainText)
	 * @see #encrypt(SecretKey, PlainText)
	 * 
	 * @deprecated As of 1.4.2; use {@link #encrypt(PlainText)} instead, which
	 *			   also ensures message authenticity. This method will be
	 *             completely removed as of the next major release or point
	 *             release (3.0 or 2.1, whichever comes first) as per OWASP
	 *             deprecation policy.
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
	 * @param plaintext	The {@code PlainText} to be encrypted.
	 * @return the {@code CipherText} object from which the raw ciphertext, the
	 * 				IV, the cipher transformation, and many other aspects about
	 * 				the encryption detail may be extracted.
	 * @throws EncryptionException Thrown if something should go wrong such as
	 * 				the JCE provider cannot be found, the cipher algorithm,
	 * 				cipher mode, or padding scheme not being supported, specifying
	 * 				an unsupported key size, specifying an IV of incorrect length,
	 * 				etc.
	 * @see #encrypt(SecretKey, PlainText)
	 * @since 2.0
	 */
	 CipherText encrypt(PlainText plaintext) throws EncryptionException;


	 /**
	  * Encrypts the provided plaintext bytes using the cipher transformation
	  * specified by the property <code>Encryptor.CipherTransformation</code>
	  * as defined in the <code>ESAPI.properties</code> file and the
	  * <i>specified secret key</i>.
	  * </p><p>
	  * This method is similar to {@link #encrypt(PlainText)} except that it
	  * permits a specific {@code SecretKey} to be used for encryption.
	  *
	  * @param key		The {@code SecretKey} to use for encrypting the plaintext.
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
	  * @see #encrypt(PlainText)
	  * @since 2.0
	  */
	 CipherText encrypt(SecretKey key, PlainText plaintext)
	 		throws EncryptionException;

	/**
	 * Decrypts the provided ciphertext and returns a plaintext string using the
	 * master secret key and default cipher transformation.
	 * </p><p>
	 * <b>Compatibility with earlier ESAPI versions:</b> Unlike ESAPI 1.4 version
	 * of this method which used the Electronic Code Book (ECB)
	 * cipher mode to encrypt, this method uses the default cipher transformation
	 * and IV type (which by default is AES/CBC/PKCS5Padding and a random IV). ECB mode
	 * is not secure for general use and usually should be avoided. If you <b>must</b>
	 * use ECB mode for backward compatibility, you should do so by specifying
	 * <pre>
	 * 		ESAPI.Encryptor=org.owasp.esapi.reference.LegacyJavaEncryptor
	 * </pre>
	 * in your <b>ESAPI.properties</b> file rather than changing the default
	 * cipher transformation. That will make this method and the
	 * {@link #decrypt(String)} method use ECB mode in a manner that is compatible
	 * with ESAPI 1.4 and earlier but not affect the newer encryption / decryption
	 * methods. However, this should only be used for backward compatibility. You
	 * should use it to decrypt data that was previous encrypted using ESAPI 1.4 or
	 * earlier use a newer method that uses the stronger CBC cipher mode
	 * to re-encrypt it. Once all the previously encrypted data has been re-encrypted
	 * using this legacy class, you should stop using this legacy class and start
	 * using the default reference class, as per:
	 * <pre>
	 * 		ESAPI.Encryptor=org.owasp.esapi.reference.LegacyJavaEncryptor
	 * </pre>
	 * in your <b>ESAPI.properties</b> file. 
	 * </p><p>
	 * <b>Why this method is deprecated:</b> Most cryptographers strongly suggest
	 * that if you are creating crypto functionality for general-purpose use,
	 * at a minimum you should ensure that it provides authenticity, integrity,
	 * and confidentiality. This method only provides confidentiality, but not
	 * authenticity or integrity. Therefore, you are encouraged to use
	 * one of the other encryption methods referenced below. Because this
	 * method provides neither authenticity nor integrity, it may be
	 * removed in some future ESAPI Java release. Note: there are some cases
	 * where authenticity / integrity are not that important. For instance, consider
	 * a case where the encrypted data is never out of your application's control. For
	 * example, if you receive data that your application is encrypting itself and then
	 * storing the encrypted data in its own database for later use (and no other
	 * applications can query or update that column of the database), providing
	 * confidentiality alone might be sufficient. However, if there are cases
	 * where your application will be sending or receiving already encrypted data
	 * over an insecure, unauthenticated channel, in such cases authenticity and
	 * integrity of the encrypted data likely is important and this method should
	 * be avoided in favor of one of the other two.
	 *
	 * @param ciphertext
	 *      the ciphertext (the encrypted plaintext) that resulted from
	 *      encrypting using the method {@link #encrypt(String)}.
	 * 
	 * @return 
	 * 		the decrypted ciphertext (i.e., the corresponding plaintext).
	 * 
	 * @throws EncryptionException
	 *      if the specified encryption algorithm could not be found or another problem exists with 
	 *      the decryption of 'plaintext'
	 *
	 * @deprecated As of 1.4.2; use {@link #decrypt(CipherText)} instead, which
     *             also ensures message authenticity. This method will be
     *             completely removed as of the next major release or point
     *             release (3.0 or 2.1, whichever comes first) as per OWASP
     *             deprecation policy.
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
	 * @return The {@code PlainText} object resulting from decrypting the specified
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
	PlainText decrypt(CipherText ciphertext) throws EncryptionException;
	
	/**
	 * Decrypts the provided {@link CipherText} using the information from it
	 * and the <i>specified secret key</i>.
	 * </p><p>
	 * This decrypt method is similar to {@link #decrypt(CipherText)} except that
	 * it allows decrypting with a secret key other than the <i>master secret key</i>.
	 * </p>
	 * @param key		The {@code SecretKey} to use for encrypting the plaintext.
	 * @param ciphertext The {@code CipherText} object to be decrypted.
	 * @return The {@code PlainText} object resulting from decrypting the specified
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
	PlainText decrypt(SecretKey key, CipherText ciphertext) throws EncryptionException;
	
	/**
	 * Create a digital signature for the provided data and return it in a
	 * string.
	 * <p>
	 * <b>Limitations:</b> A new public/private key pair used for ESAPI 2.0 digital
	 * signatures with this method and {@link #verifySignature(String, String)}
	 * are dynamically created when the default reference implementation class,
	 * {@link org.owasp.esapi.reference.crypto.JavaEncryptor} is first created.
	 * Because this key pair is not persisted nor is the public key shared,
	 * this method and the corresponding {@link #verifySignature(String, String)}
	 * can not be used with expected results across JVM instances. This limitation
	 * will be addressed in ESAPI 2.1.
	 * </p>
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
     * <p>
     * <b>Limitations:</b> A new public/private key pair used for ESAPI 2.0 digital
     * signatures with this method and {@link #sign(String)}
     * are dynamically created when the default reference implementation class,
     * {@link org.owasp.esapi.reference.crypto.JavaEncryptor} is first created.
     * Because this key pair is not persisted nor is the public key shared,
     * this method and the corresponding {@link #sign(String)}
     * can not be used with expected results across JVM instances. This limitation
     * will be addressed in ESAPI 2.1.
     * </p>
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
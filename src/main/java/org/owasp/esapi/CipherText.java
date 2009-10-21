/*
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright &copy; 2009 - The OWASP Foundation
 */
package org.owasp.esapi;

import java.io.Serializable;

import javax.crypto.SecretKey;

// DISCUSS: Do we want to treat this as if it should be replaceable too? I.e.,
//			to allow ESAPI users to replace the reference model DefaultCipherText.
//			If so, perhaps we need to define the service provider side and define
//			some appropriate 'setters'. More details in DefaultCipherText.
//			Also, check the method names to see if they make sense / are intuitive.
//			However, I did not do this so it would take some additional work. -kww

/**
 * A {@code Serializable} interface representing the result of encrypting
 * plaintext and some additional information about the encryption algorithm,
 * the IV (if pertinent), and an optional Message Authentication Code (MAC).
 * <p>
 * Copyright &copy; 2009 - The OWASP Foundation
 * </p>
 * @author kevin.w.wall@gmail.com
 * @see PlainText
 * @since 2.0
 */
public interface CipherText extends Serializable {
	
	long serialVersionUID = 20090819;

	/**
	 * Obtain the String representing the cipher transformation used to encrypt
	 * the plaintext. The cipher transformation represents the cipher algorithm,
	 * the cipher mode, and the padding scheme used to do the encryption. An
	 * example would be "AES/CBC/PKCS5Padding". See Appendix A in the
	 * <a href="http://java.sun.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#AppA">
	 * Java Cryptography Architecture Reference Guide</a>
	 * for information about standard supported cipher transformation names.
	 * <p>
	 * The cipher transformation name is usually sufficient to be passed to
	 * {@link javax.crypto.Cipher#getInstance(String)} to create a
	 * <code>Cipher</code> object to decrypt the ciphertext.
	 * 
	 * @return The cipher transformation name used to encrypt the plaintext
	 * 		   resulting in this ciphertext.
	 */
	public String getCipherTransformation();
	
	/**
	 * Obtain the name of the cipher algorithm used for encrypting the
	 * plaintext.
	 * 
	 * @return The name as the cryptographic algorithm used to perform the
	 * 		   encryption resulting in this ciphertext.
	 */
	public String getCipherAlgorithm();
	
	/**
	 * Retrieve the key size used with the cipher algorithm that was used to
	 * encrypt data to produce this ciphertext.
	 * 
	 * @return The key size in bits. We work in bits because that's the crypto way!
	 */
	public int getKeySize();
	
	/**
	 * Retrieve the block size (in bytes!) of the cipher used for encryption.
	 * (Note: If an IV is used, this will also be the IV length.)
	 * 
	 * @return The block size in bytes. (Bits, bytes! It's confusing I know. Blame
	 * 									the cryptographers; we've just following
	 * 									convention.)
	 */
	public int getBlockSize();
	
	/**
	 * Get the name of the cipher mode used to encrypt some plaintext.
	 * 
	 * @return The name of the cipher mode used to encrypt the plaintext
	 *         resulting in this ciphertext. E.g., "CBC" for "cipher block
	 *         chaining", "ECB" for "electronic code book", etc.
	 */
	public String getCipherMode();
	
	/**
	 * Get the name of the padding scheme used to encrypt some plaintext.
	 * 
	 * @return The name of the padding scheme used to encrypt the plaintext
	 * 		   resulting in this ciphertext. Example: "PKCS5Padding". If no
	 * 		   padding was used "None" is returned.
	 */
	public String getPaddingScheme();
	
	/**
	 * Return the initialization vector (IV) used to encrypt the plaintext
	 * if applicable.
	 *  
	 * @return	The IV is returned if the cipher mode used to encrypt the
	 * 			plaintext was not "ECB". ECB mode does not use an IV so in
	 * 			that case, <code>null</code> is returned.
	 */
	public byte[] getIV();
	
	/** 
	 * Return true if the cipher mode used requires an IV. Usually this will
	 * be true unless ECB mode (which should be avoided whenever possible) is
	 * used.
	 */
	public boolean requiresIV();
	
	/**
	 * Get the raw ciphertext byte array resulting from encrypting some
	 * plaintext.
	 * 
	 * @return The raw ciphertext as a byte array.
	 */
	public byte[] getRawCipherText();

	/**
	 * Return a base64-encoded representation of the raw ciphertext alone. Even
	 * in the case where an IV is used, the IV is not prepended before the
	 * base64-encoding is performed.
	 * <p>
	 * If there is a need to store an encrypted value, say in a database, this
	 * is <i>not</i> the method you should use unless you are using a <i>fixed</i>
	 * IV. If you are <i>not</i> using a fixed IV, you should normally use
	 * {@link #getEncodedIVCipherText()} instead.
	 * </p>
	 * @see #getEncodedIVCipherText()
	 */
	public String getBase64EncodedRawCipherText();
	
	/**
	 * Return the ciphertext as a base64-encoded <code>String</code>. If an
	 * IV was used, the IV if first prepended to the raw ciphertext before
	 * base64-encoding. If an IV is not used, then this method returns the same
	 * value as {@link #getBase64EncodedRawCipherText()}.
	 * <p>
	 * Generally, this is the method that you should use unless you only
	 * are using a fixed IV and a storing that IV separately, in which case
	 * using {@link #getBase64EncodedRawCipherText()} can reduce the storage
	 * overhead.
	 * </p>
	 * @return The base64-encoded ciphertext or base64-encoded IV + ciphertext.
	 * @see #getBase64EncodedRawCipherText()
	 */
	public String getEncodedIVCipherText();

	/**
	 * Compute and store the Message Authentication Code (MAC) if the ESAPI property
	 * {@code Encryptor.CipherText.useMAC} is set to {@code true}. If it
	 * is, the MAC is conceptually calculated as:
	 * <pre>
	 * 		authKey = DerivedKey(secret_key, "authenticate")
	 * 		HMAC-SHA1(authKey, IV + secret_key)
	 * </pre>
	 * where derived key is an HMacSHA1, possibly repeated multiple times.
	 * (See {@link org.owasp.esapi.util.CryptoHelper#computeDerivedKey(SecretKey, int, String)}
	 * for details.)
	 * </p><p>
	 * <b>Perceived Benefits</b>: There are certain cases where if an attacker
	 * is able to change the IV. When one uses a authenticity key that is
	 * derived from the "master" key, it also makes it possible to know when
	 * the incorrect key was attempted to be used to decrypt the ciphertext.
	 * </p><p>
	 * <b>NOTE:</b> The purpose of this MAC (which is always computed by the
	 * ESAPI reference model implementing {@code Encryptor}) is to ensure the
	 * authenticity of the IV and ciphertext. Among other things, this prevents
	 * an adversary from substituting the IV with one of their own choosing.
	 * Because we don't know whether or not the recipient of this {@code CipherText}
	 * object will want to validate the authenticity or not, the reference
	 * implementation of {@code Encryptor} always computes it and includes it.
	 * The recipient of the ciphertext can then choose whether or not to validate
	 * it.
	 * 
	 * @param authKey The secret key that is used for proving authenticity of
	 * 				the IV and ciphertext. This key should be derived from
	 * 				the {@code SecretKey} passed to the
	 * 				{@link Encryptor#encrypt(javax.crypto.SecretKey, PlainText)}
	 *				and
	 *				{@link Encryptor#decrypt(javax.crypto.SecretKey, CipherText)}
	 *				methods or the "master" key when those corresponding
	 *				encrypt / decrypt methods are used. This authenticity key
	 *				should be the same length and for the same cipher algorithm
	 *				as this {@code SecretKey}. The method
	 *				{@link org.owasp.esapi.util.CryptoHelper#computeDerivedKey(SecretKey, int, String)}
	 *				is a secure way to produce this derived key.
	 */		// DISCUSS - Cryptographers David Wagner, Ian Grigg, and others suggest
			// computing authenticity using derived key and HmacSHA1 of IV + ciphertext.
			// However they also argue that what should be returned and treated as
			// (i.e., stored as) ciphertext would be something like this:
			//		len_of_raw_ciphertext + IV + raw_ciphertext + MAC
			// I don't really think all that's necessary. If they want the equivalent,
			// then let then serialize this object.
	public void computeAndStoreMAC(SecretKey authKey);
	
	/**
	 * Validate the message authentication code (MAC) associated with the ciphertext.
	 * This is mostly meant to ensure that an attacker has not replaced the IV
	 * or raw ciphertext with something arbitrary. Note however that it will
	 * <i>not</i> detect the case where an attacker simply substitutes one
	 * valid ciphertext with another ciphertext.
	 * 
	 * @param authKey The secret key that is used for proving authenticity of
	 * 				the IV and ciphertext. This key should be derived from
	 * 				the {@code SecretKey} passed to the
	 * 				{@link Encryptor#encrypt(javax.crypto.SecretKey, PlainText)}
	 *				and
	 *				{@link Encryptor#decrypt(javax.crypto.SecretKey, CipherText)}
	 *				methods or the "master" key when those corresponding
	 *				encrypt / decrypt methods are used. This authenticity key
	 *				should be the same length and for the same cipher algorithm
	 *				as this {@code SecretKey}. The method
	 *				{@link org.owasp.esapi.util.CryptoHelper#computeDerivedKey(SecretKey, int, String)}
	 *				is a secure way to produce this derived key.
	 * @return True if the ciphertext has not be tampered with, and false otherwise.
	 */
	public boolean validateMAC(SecretKey authKey);
}

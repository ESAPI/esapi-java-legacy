/*
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 */
package org.owasp.esapi;

import java.io.Serializable;

// DISCUSS: Do we want to treat this as if it should be replaceable too???
//			If so, perhaps we need to define the service provider side and define
//			some appropriate 'setters'. More details in DefaultCipherText.
//			Also, check the method names to see if they make sense / are intuitive.

/**
 * A {@code Serializable} interface representing the result of encrypting
 * plaintext and some additional information about the encryption algorithm,
 * the IV (if pertinent), and an optional Message Integrity Code (MIC).
 * <p>
 * Copyright (c) 2009 - The OWASP Foundation
 * </p>
 * @author kevin.w.wall@gmail.com
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
	 * Return true if the cipher mode used requires an IV.
	 */
	public boolean requiresIV();
	
	/**
	 * Get the raw ciphertext byte array associated with encrypting some
	 * plaintext.
	 * 
	 * @return The raw ciphertext.
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
	 * Compute and store the Message Integrity Code (MIC) if the ESAPI property
	 * {@code Encryptor.CipherText.useMIC} is set to {@code true}. If it
	 * is, the MIC is calculated as:
	 * <pre>
	 * 		HMAC-SHA1(nonce, IV + secret_key)
	 * </pre>
	 * </p><p>
	 * As a side-effect, may set a nonce if it has not yet been calculated.
	 * </p><p>
	 * <b>Perceived Benefits</b>: There are certain cases where if an attacker
	 * is able to change the IV
	 * </p><p>
	 * <b>CAVEAT</b>: Even though an HMAC is used to compute this, since the HMAC
	 * key (the nonce) is contained in this {@code CipherText}, this is really a
	 * MIC and not an MAC. If there is some strange cryptographic attack that
	 * doing this permits (I am not aware of any, but that doesn't mean one
	 * doesn't exist; check with your own cryptography experts), then you might
	 * decide that the benefits don't outweigh the risks. Using a digital
	 * signature for this would be more secure, but is also much more computationally
	 * expensive.
	 * 
	 * @param secret_key The secret key with which the plaintext is encrypted.
	 */		// DISCUSS - Should this be secret_key or plaintext or neither? Have
			//			 post out to two former colleagues with more crypto knowledge.
			//			 May post to sci.crypt.research or elsewhere if no response.
			//			 Secret key would be preferable since we can test MIC via
			//			 validateMIC() even when decryption fails and results in
			//			 BadPaddingException. If we definitely decide its safe to
			//			 use the secret key, recommend changing arg for this method
			//			 and validateMIC() to use SecretKey rather than the encoded
			//			 secret key bytes.
	public void computeAndStoreMIC(byte[] secret_key);
	
	/**
	 * Validate the message integrity code (MIC) associated with the ciphertext.
	 * This is mostly meant to ensure that an attacker has not replaced the IV
	 * or raw ciphertext with something arbitrary. Note however that it will
	 * <i>not</i> detect the case where an attacker simply substitutes one
	 * valid ciphertext with another ciphertext.
	 * 
	 * @param secretKey		The raw bytes of the secret encryption key.
	 * @return True if the ciphertext has not be tampered with, and false otherwise.
	 */
	public boolean validateMIC(byte[] secretKey);	// DISCUSS: See above discussion.
}

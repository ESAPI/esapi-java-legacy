package org.owasp.esapi;

/**
 * An interface the result of encrypting plaintext and some additional
 * information about the encryption algorithm, the IV (if pertinent), and
 * an optional Message Integrity Code (MIC).
 * <p>
 * Copyright (c) 2009 - The OWASP Foundation
 * </p>
 * @author kevin.w.wall@gmail.com
 * @since 2.0
 */
public interface CipherText {

	/**
	 * Obtain the String representing the cipher transformation used to encrypt
	 * the plaintext. The cipher transformation represents the cipher algorithm,
	 * the cipher mode, and the padding scheme used to do the encryption. An
	 * example would be "AES/CBC/PKCS5Padding". See Appendix A in the
	 * {@linkplain http://java.sun.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#AppA
	 * Java Cryptography Architecture Reference Guide}
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
	 * Get the raw ciphertext byte array associated with encrypting some
	 * plaintext.
	 * 
	 * @return The raw ciphertext.
	 */
	public byte[] getRawCipherText();
	
	/**
	 * Return the ciphertext as a base64-encoded <code>String</code>. If an
	 * IV was used, the IV if first prepended to the raw ciphertext before
	 * base64-encoding.
	 * 
	 * @return The base64-encoded ciphertext or base64-encoded IV + ciphertext.
	 */
	public String getEncodedCipherText();
	
	/**
	 * Validate the message integrity code (MIC) associated with the ciphertext.
	 * This is mostly meant to ensure that an attacker has not replaced the IV
	 * or raw ciphertext with something arbitrary. Note however that it will
	 * <i>not</i> detect the case where an attacker simply substitutes one
	 * valid ciphertext with another ciphertext.
	 * 
	 * @return True if the ciphertext has not be tampered with, and false otherwise.
	 * 
	 * @see #getNonce()
	 */ 
	public boolean validateMIC();
	
	/**
	 * Obtain the nonce used to calculate the message integrity code (MIC).
	 * The purpose of this is two-fold: first is to ensure the integrity of
	 * the ciphertext and second is to help us detect if the wrong encryption
	 * key was used to attempt to decrypt (something that is very important
	 * when one occasionally does key change operations [i.e., rotates keys]).
	 * <p>
	 * Note that the nonce itself should be treated as an opaque object. That
	 * is, no meaning should be inferred from it by users of this class.
	 * 
	 * @return	The nonce (number used once) used in creating the MIC.
	 * 
	 * @see #validateMIC()
	 */
	byte[] getNonce();
}

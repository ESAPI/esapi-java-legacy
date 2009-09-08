/*
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 */
// If we had PRIVATE packages, e.g., org.owasp.esapi.util.pvt, this would belong
// there. CipherText uses this, but doesn't expose it directly.
package org.owasp.esapi.util;

import java.io.Serializable;
import javax.crypto.Cipher;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.util.StringUtils;

/**
 * Specifies all the relevant configuration data needed in constructing and
 * using a {@link javax.crypto.Cipher} except for the encryption key.
 * </p><p>
 * The "setters" all return a reference to {@code this} so that they can be
 * strung together.
 * 
 * @author kevin.w.wall@gmail.com
 * @since 2.0
 */
public class CipherSpec implements Serializable {

	private static final long serialVersionUID = 20090822;	// 2009-08-22 version
	
	private String  cipher_xform_   = ESAPI.securityConfiguration().getCipherTransformation();
	private int     keySize_        = ESAPI.securityConfiguration().getEncryptionKeyLength(); // In bits
	private int     blockSize_      = 16;   // In bytes! I.e., 128 bits!!!
	private byte[]  iv_             = null;
	
	private static final int ALG     = 0;
	private static final int MODE    = 1;
	private static final int PADDING = 2;
	
	/**
	 * CTOR that explicitly sets everything.
	 * @param cipherXform	The cipher transformation
	 * @param keySize		The key size (in bits).
	 * @param blockSize		The block size (in bytes).
	 * @param iv			The initialization vector. Null if not applicable.
	 */
	public CipherSpec(String cipherXform, int keySize, int blockSize, final byte[] iv) {
		setCipherTransformation(cipherXform);
		setKeySize(keySize);
		setBlockSize(blockSize);
		setIV(iv);
	}
	
	/**
	 * CTOR that sets everything but IV.
	 * @param cipherXform	The cipher transformation
	 * @param keySize		The key size (in bits).
	 * @param blockSize		The block size (in bytes).
	 */
	public CipherSpec(String cipherXform, int keySize, int blockSize) {
		// Note: Do NOT use
		//			this(cipherXform, keySize, blockSize, null);
		// because of assertion in setIV().
		//
		setCipherTransformation(cipherXform);
		setKeySize(keySize);
		setBlockSize(blockSize);
	}
	
	/** CTOR that sets everything but block size and IV. */
	public CipherSpec(String cipherXform, int keySize) {
		setCipherTransformation(cipherXform);
		setKeySize(keySize);
	}
	
	/** CTOR that sets everything except block size. */
	public CipherSpec(String cipherXform, int keySize, final byte[] iv) {
		setCipherTransformation(cipherXform);
		setKeySize(keySize);
		setIV(iv);
	}

	/** CTOR that sets everything except for the cipher key size and possibly
	 *  the IV. (IV may not be applicable--e.g., with ECB--or may not have
	 *  been specified yet.
	 */
	public CipherSpec(final Cipher cipher) {
		setCipherTransformation(cipher.getAlgorithm(), true);
		setBlockSize(cipher.getBlockSize());
		if ( cipher.getIV() != null ) {
			setIV(cipher.getIV());
		}
	}
	
	/** CTOR that sets everything. */
	public CipherSpec(final Cipher cipher, int keySize) {
		this(cipher);
		setKeySize(keySize);
	}
	
	/* CTOR that sets only the IV and uses defaults for everything else. */
	public CipherSpec(final byte[] iv) {
		setIV(iv);
	}
	
	/**
	 * Default CTOR. Creates a cipher specification for 128-bit cipher
	 * transformation of "AES/CBC/PKCS5Padding" and a {@code null} IV.
	 */
	public CipherSpec() {
		;	// All defaults
	}

	/**
	 * Set the cipher transformation for this {@code CipherSpec}.
	 * @param cipherXform	The cipher transformation string; e.g., "DESede/CBC/PKCS5Padding".
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec setCipherTransformation(String cipherXform) {
		setCipherTransformation(cipherXform, false);
		return this;
	}

	/**
	 * Set the cipher transformation for this {@code CipherSpec}. This is only
	 * used by the CTOR {@code CipherSpec(Cipher)} and {@code CipherSpec(Cipher, int)}.
	 * @param cipherXform	The cipher transformation string; e.g.,
	 * 						"DESede/CBC/PKCS5Padding".
	 * @param fromCipher If true, the cipher transformation was set via
	 * 					 {@code Cipher.getAlgorithm()} which may only return the
	 * 					 actual algorithm. In that case we check and if all 3 parts
	 * 					 were not specified, then we specify the parts that were
	 * 					 based on "ECB" as the default cipher mode and "NoPadding"
	 * 					 as the default padding scheme.
	 * @return	This current {@code CipherSpec} object.
	 */
	private CipherSpec setCipherTransformation(String cipherXform, boolean fromCipher) {
		assert StringUtils.notNullOrEmpty(cipherXform, true) : "cipherXform may not be null or empty";
		int parts = cipherXform.split("/").length;
		assert ( !fromCipher ? (parts == 3) : true ) :
			"Malformed cipherXform (" + cipherXform + "); must have form: \"alg/mode/paddingscheme\"";
		if ( fromCipher && (parts != 3)  ) {
				// Indicates cipherXform was set based on Cipher.getAlgorithm()
				// and thus may not be a *complete* cipher transformation.
			if ( parts == 1 ) {
				// Only algorithm was given.
				cipherXform += "/ECB/NoPadding";
			} else if ( parts == 2 ) {
				// Only algorithm and mode was given.
				cipherXform += "/NoPadding";
			} else if ( parts == 3 ) {
				// All threw parts provided. Do nothing. Could happen if not compiled with
				// assertions enabled.
				;	// Do nothing
			} else {
				// Should never happen unless Cipher implementation is totally screwed up.
				throw new IllegalArgumentException("Cipher transformation '" +
								cipherXform + "' must have form \"alg/mode/paddingscheme\"");
			}
		}
		assert cipherXform.split("/").length == 3 : "Implementation error setCipherTransformation()";
		this.cipher_xform_ = cipherXform;
		return this;
	}
	
	/**
	 * Get the cipher transformation.
	 * @return	The cipher transformation {@code String}.
	 */
	public String getCipherTransformation() {
		return cipher_xform_;
	}

	/**
	 * Set the key size for this {@code CipherSpec}.
	 * @param keySize	The key size, in bits. Must be positive integer.
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec setKeySize(int keySize) {
		assert keySize > 0 : "keySize must be > 0; keySize=" + keySize;
		this.keySize_ = keySize;
		return this;
	}

	/**
	 * Retrieve the key size, in bits.
	 * @return	The key size, in bits, is returned.
	 */
	public int getKeySize() {
		return keySize_;
	}

	/**
	 * Set the block size for this {@code CipherSpec}.
	 * @param blockSize	The block size, in bytes. Must be positive integer.
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec setBlockSize(int blockSize) {
		assert blockSize > 0 : "blockSize must be > 0; blockSize=" + blockSize;
		this.blockSize_ = blockSize;
		return this;
	}

	/**
	 * Retrieve the block size, in bytes.
	 * @return	The block size, in bytes, is returned.
	 */
	public int getBlockSize() {
		return blockSize_;
	}

	/**
	 * Retrieve the cipher algorithm.
	 * @return	The cipher algorithm.
	 */
	public String getCipherAlgorithm() {
		return getFromCipherXform(ALG);
	}
	
	/**
	 * Retrieve the cipher mode.
	 * @return	The cipher mode.
	 */
	public String getCipherMode() {
		return getFromCipherXform(MODE);
	}
	
	/**
	 * Retrieve the cipher padding scheme.
	 * @return	The padding scheme is returned.
	 */
	public String getPaddingScheme() {
		return getFromCipherXform(PADDING);
	}
	
	/**
	 * Retrieve the initialization vector (IV).
	 * @return	The IV as a byte array.
	 */
	public byte[] getIV() {
		return iv_;
	}
	
	/**
	 * Set the initialization vector (IV).
	 * @param iv	The byte array to set as the IV. A copy of the IV is saved.
	 * 				This parameter is ignored if the cipher mode does not
	 * 				require an IV.
	 * @return		This current {@code CipherSpec} object.
	 */
	public CipherSpec setIV(final byte[] iv) {
		assert requiresIV() && (iv != null && iv.length != 0) : "Required IV cannot be null or 0 length";
		// Don't store a reference, but make a copy!
		if ( iv != null ) {	// Allow null IV for ECB mode.
			iv_ = new byte[ iv.length ];
			CryptoHelper.copyByteArray(iv, iv_);
		}
		return this;
	}

	/**
	 * Return true if the cipher mode requires an IV.
	 * @return True if the cipher mode requires an IV, otherwise false.
	 * */
	public boolean requiresIV() {
		
		String cm = getCipherMode();
		
		// Add any other cipher modes supported by JCE but not requiring IV.
		// ECB is the only one I'm aware of that doesn't. Mode is not case
		// sensitive.
		if ( "ECB".equalsIgnoreCase(cm) ) {
			return false;
		}
		return true;
	}
	
	/**
	 * Override {@code Object.toString()} to provide something more useful.
	 * @return A meaningful string describing this object.
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("CipherSpec: ");
		sb.append( getCipherTransformation() ).append("; keysize= ").append( getKeySize() );
		sb.append(" bits; blocksize= ").append( getBlockSize() ).append(" bytes");
		byte[] iv = getIV();
		String ivLen = null;
		if ( iv != null ) {
			ivLen = "" + iv.length;	// Convert length to a string
		} else {
			ivLen = "[No IV present (not set or not required)]";
		}
		sb.append("; IV length = ").append( ivLen ).append(" bytes.");
		return sb.toString();
	}
	
	/**
	 * Split the current cipher transformation and return the requested part. 
	 * @param part The part to return. ALG (0), MODE (1), or PADDING (2).
	 * @return The cipher algorithm, cipher mode, or padding, as requested.
	 */
	private String getFromCipherXform(int part) {
		String[] parts = getCipherTransformation().split("/");
		assert parts.length == 3 : "Invalid cipher transformation: " + getCipherTransformation();	
		return parts[part];
	}
}

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

import java.io.Serializable;
import javax.crypto.Cipher;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.util.StringUtils;

/**
 * Specifies all the relevant configuration data needed in constructing and
 * using a @{link {@link javax.crypto.Cipher} except for the encryption key.
 * </p><p>
 * The "setters" all return a reference to {@code this} so that they can be
 * strung together.
 * 
 * @author kevin.w.wall@gmail.com
 * @since 2.0
 */
public class CipherSpec implements Serializable {

	private static final long serialVersionUID = 20090822;
	
	private String  cipher_xform_   = ESAPI.securityConfiguration().getCipherTransformation();
	private int     keySize_        = ESAPI.securityConfiguration().getEncryptionKeyLength(); // In bits
	private int     blockSize_      = 8;   // In bytes!
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
		setCipherTransformation(cipher.getAlgorithm());
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

	public CipherSpec setCipherTransformation(String cipherXform) {
		assert StringUtils.notNullOrEmpty(cipherXform, true) : "cipherXform may not be null or empty";
		this.cipher_xform_ = cipherXform;
		return this;
	}

	public String getCipherTransformation() {
		return cipher_xform_;
	}

	public CipherSpec setKeySize(int keySize) {
		assert keySize > 0 : "keySize must be > 0; keySize=" + keySize;
		this.keySize_ = keySize;
		return this;
	}

	public int getKeySize() {
		return keySize_;
	}

	public CipherSpec setBlockSize(int blockSize) {
		assert blockSize > 0 : "blockSize must be > 0; blockSize=" + blockSize;
		this.blockSize_ = blockSize;
		return this;
	}

	public int getBlockSize() {
		return blockSize_;
	}

	public String getCipherAlgorithm() {
		return getFromCipherXform(ALG);
	}
	
	public String getCipherMode() {
		return getFromCipherXform(MODE);
	}
	
	public String getPaddingScheme() {
		return getFromCipherXform(PADDING);
	}
	
	public byte[] getIV() {
		return iv_;
	}
	
	public CipherSpec setIV(final byte[] iv) {
		assert requiresIV() && (iv != null && iv.length != 0) : "Required IV cannot be null or 0 length";
		// Don't store a reference, but make a copy!
		iv_ = new byte[ iv.length ];
		CryptoHelper.copyByteArray(iv, iv_);
		return this;
	}
	
	/** Return true if the cipher mode requires an IV. */
	public boolean requiresIV() {
		
		String cm = getCipherMode();
		
		// Add any other cipher modes supported by JCE but not requiring IV.
		// ECB is the only one I'm aware of that doesn't. -kww
		if ( "ECB".equals(cm) ) {
			return false;
		}
		return true;
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

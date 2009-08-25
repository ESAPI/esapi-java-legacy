/*
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 */
package org.owasp.esapi.reference;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.owasp.esapi.CipherText;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.util.CipherSpec;
import org.owasp.esapi.util.CryptoHelper;

/**
 * Reference implementation of <code>CipherText</code>. This object is both
 * serializable, and once it is "frozen", it is immutable as well.
 * <p>
 * Copyright (c) 2009 - The OWASP Foundation
 * </p>
 * @author kevin.w.wall@gmail.com
 * @since 2.0
 */
public final class DefaultCipherText implements CipherText {

	private static final long serialVersionUID = 20080822;
	private static final Logger logger = ESAPI.getLogger("DefaultCipherText");
	
	private CipherSpec cipherSpec_     = null;
	private byte[]     raw_ciphertext_ = null;
	private byte[]     nonce_          = null;
	private byte[]     mic_            = null;
	private boolean    frozen_         = false;
	
	/**
	 * Default CTOR. Takes all the defaults from the ESAPI.properties, or
	 * default values from initial values from this class (when appropriate)
	 * when they are not set in ESAPI.properties.
	 */
	public DefaultCipherText() {
		cipherSpec_ = new CipherSpec(); // Uses default for everything but IV.
		frozen_ = false;
	}
	
	public DefaultCipherText(final CipherSpec cipherSpec) {
		cipherSpec_  = cipherSpec;
		frozen_ = false;
	}
	
	public DefaultCipherText(final CipherSpec cipherSpec, byte[] cipherText) {
		cipherSpec_ = cipherSpec;
		setCiphertext(cipherText);
		frozen_ = false;
	}
	
	/** Make this object immutable by making all setters throw if called
	 * after this.
	 */
	private void freeze() {
		if ( frozen_ ) {
			return;		// Harmless to call multiple times.
		}
		assert raw_ciphertext_ != null : "Can't free while raw ciphertext is still null!";
		boolean useMIC = ESAPI.securityConfiguration().useMICforCipherText();
		assert useMIC && nonce_ != null && mic_ != null : "Cannot freeze: MIC not computed!";
		frozen_ = true;
	}
	
	private boolean isFrozen() {
		return frozen_;
	}
	
	/**
	 *  {@inheritDoc}
	 */
	public String getCipherTransformation() {
		return cipherSpec_.getCipherTransformation();
	}

	/**
	 *  {@inheritDoc}
	 */
	public String getCipherAlgorithm() {
		return cipherSpec_.getCipherAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	public int getKeySize() {
		return cipherSpec_.getKeySize();
	}
	
	/**
	 * {@inheritDoc}
	 */
	public int getBlockSize() {
		return cipherSpec_.getBlockSize();
	}
	
	/**
	 *  {@inheritDoc}
	 */
	public String getCipherMode() {
		return cipherSpec_.getCipherMode();
	}
	
	/**
	 *  {@inheritDoc}
	 */
	public String getPaddingScheme() {
		return cipherSpec_.getPaddingScheme();
	}

	/**
	 *  {@inheritDoc}
	 */
	public byte[] getIV() {
		if ( isFrozen() ) {
			return cipherSpec_.getIV();
		} else {
			logger.error(Logger.SECURITY_FAILURE, "IV not set yet; unable to retrieve; returning null");
			return null;
		}
	}

	/**
	 *  {@inheritDoc}
	 */
	public byte[] getRawCipherText() {
		if ( isFrozen() ) {
			return raw_ciphertext_;
		} else {
			logger.error(Logger.SECURITY_FAILURE, "Raw ciphertext not set yet; unable to retrieve; returning null");
			return null;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public String getBase64EncodedRawCipherText() {
		return ESAPI.encoder().encodeForBase64(getRawCipherText(),false);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String getEncodedIVCipherText() {
		if ( isFrozen() ) {
			// First concatenate IV + raw ciphertext
			byte[] iv = getIV();
			byte[] raw = getRawCipherText();
			byte[] ivPlusCipherText = new byte[ iv.length + raw.length ];
			System.arraycopy(iv, 0, ivPlusCipherText, 0, iv.length);
			System.arraycopy(raw, 0, ivPlusCipherText, iv.length + 1, raw.length);
			// Then return the base64 encoded result
			return ESAPI.encoder().encodeForBase64(ivPlusCipherText, false);
		} else {
			logger.error(Logger.SECURITY_FAILURE, "Raw ciphertext and/or IV not set yet; unable to retrieve; returning null");
			return null;
		}
	}
	
	/**
	 * Compute a MIC, but do not store it. May set the nonce value as a
	 * side-effect.  The MIC is calculated as:
	 * <pre>
	 * 		HMAC-SHA1(nonce, IV + plaintext)
	 * </pre>
	 * @param ciphertext	The ciphertext value for which the MIC is computed.
	 * @return The value for the MIC.
	 */ 
	private byte[] computeMIC(byte[] ciphertext) {
		assert ciphertext != null && ciphertext.length != 0 : "Plaintext may not be null or empty.";
		try {
			KeyGenerator kg = KeyGenerator.getInstance("HmacSHA1");
			SecretKey sk = null;
			if ( nonce_ == null ) {
				sk = kg.generateKey();
			} else {
				sk = new SecretKeySpec(nonce_, "HmacSHA1");
			}
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(sk);
			byte[] result = mac.doFinal(ciphertext);
			// POSSIBLE SIDE-EFFECT !!!!
			if ( nonce_ == null ) {
				nonce_ = sk.getEncoded();
			}
			return result;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace(System.err);
			logger.error(Logger.SECURITY_FAILURE, "Cannot compute MIC w/out HmacSHA1.", e);
			return null;
		} catch (InvalidKeyException e) {
			e.printStackTrace(System.err);
			logger.error(Logger.SECURITY_FAILURE, "Cannot comput MIC; invalid 'key' for HmacSHA1.", e);
			return null;
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void computeAndStoreMIC(byte[] raw_ciphertext) {
		byte[] result = computeMIC(raw_ciphertext);
		if ( result != null ) {
			mic_ = new byte[ result.length ];
			CryptoHelper.copyByteArray(result, mic_);
			freeze();
		}
	}
	
	/**
	 * {@inheritDoc}
	 */ 
	public boolean validateMIC(byte[] ciphertext) {
		assert getNonce() != null : "Cannot validate MIC while nonce is null.";
		assert mic_ != null : "MIC not yet computed / stored!";
		boolean usesMIC = ESAPI.securityConfiguration().useMICforCipherText();

		if ( isFrozen() && usesMIC ) {
			// Calculate MIC from HMAC-SHA1(nonce, IV + plaintext) and
			// compare to stored value (mic_). If same, then return true,
			// else return false.
			byte[] mic = computeMIC(ciphertext);
			assert mic.length == mic_.length : "MICs are of differnt lengths. Should both be the same.";
			for ( int i = 0; i < mic.length; i++ ) {
				if ( mic[i] != mic_[i] ) {
					return false;
				}
			}
			return true;
		} else if ( ! usesMIC ) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 *  {@inheritDoc}
	 */
	public byte[] getNonce() {
		if ( isFrozen() ) {
			return nonce_;
		} else {
			logger.error(Logger.SECURITY_FAILURE, "Nonce for MIC not set yet; unable to retrieve; returning null");
			return null;
		}
	}
	
	/**
	 * TODO
	 * @param ciphertext
	 */
	public void setCiphertext(byte[] ciphertext) {
		if ( ! isFrozen() ) {
			raw_ciphertext_ = new byte[ ciphertext.length ];
			CryptoHelper.copyByteArray(ciphertext, raw_ciphertext_);
		} else {
			logger.error(Logger.SECURITY_FAILURE, "Raw ciphertext already set; may not be reset. Object now immutable.");
		}
	}
	
	/**
	 * TODO
	 * @param iv
	 * @param ciphertext
	 * @throws EncryptionException
	 */
	public void setIVandCiphertext(byte[] iv, byte[] ciphertext)
		throws EncryptionException
	{
		if ( ! isFrozen() ) {
			if ( ciphertext == null || ciphertext.length == 0 ) {
				throw new EncryptionException("Encryption faled; no ciphertext",
											  "Ciphertext may not be null or 0 length!");
			}
			if ( iv == null || iv.length == 0 ) {
				if ( requiresIV() ) {
					throw new EncryptionException("Encryption failed -- mandatory IV missing", // DISCUSS - appropriate?
												  "Cipher mode " + getCipherMode() + " has null or empty IV");
				}
			} else if ( iv.length != getBlockSize() ) {
					throw new EncryptionException("Encryption failed -- bad parameters passed to encrypt",
												  "IV length does not match cipher block size of " + getBlockSize());
			}
		}
		cipherSpec_.setIV(iv);		
		setCiphertext( ciphertext );
		
		freeze();
	}
	
	/**
	 *  {@inheritDoc}
	 */
	public boolean requiresIV() {
		return cipherSpec_.requiresIV();
	}
}

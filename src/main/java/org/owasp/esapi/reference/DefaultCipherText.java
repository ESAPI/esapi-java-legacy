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
import java.util.EnumSet;
import java.util.Iterator;

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

// DISCUSS: Should we attempt to make this reusable in the sense of
// 		    the other 'reference' classes are or restrict this just
//		    to using this within the JavaEncryptor class? If the former,
//			we probably need to add the 'setter' methods to the CipherText
//			interface. Also in that case, note that CipherSpec is not an
//			interface, but rather part of org.owasp.esapi.util package so
//			would that need to be an interface too? It is not exposed in
//			the CipherText interface, but it is here. OTOH, if we want to
//			"hide" it so it's only used by JavaEncryptor, it should probably
//			not be placed in the public Javadoc. (Anyone for 'pvt' packages?)
//			But if we do wish to restrict it to use from JavaEncryptor,
//			it I can assume this class will be used correctly and not be
//			concerned about making it act like it is immutable once everything
//			has been collected and the MIC has been computed...all of which make
//			this class much more complex than it otherwise needs to be. But if
//			we are uncertain as to the context of how it will be used, then it's
//			probably best to be defensive.
/**
 * Reference implementation of <code>CipherText</code>. This object is both
 * serializable, and once all the required information has been collected and
 * the Message Integrity Code (MIC) has been computed, it acts as though it is
 * immutable as well. At that point, one can no longer call any of the 'setter'
 * methods.
 * <p>
 * <b>NOTE:</b> This class is <i>not</i> thread-safe.
 * </p><p>
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

	// All the various pieces that can be set, either directly or indirectly
	// via CipherSpec.
    private enum CipherTextFlags {
        ALGNAME, CIPHERMODE, PADDING, KEYSIZE, BLOCKSIZE, CIPHERTEXT, INITVECTOR
    }

    // If we have everything set, we compare it to this using '==' which javac
    // specially overloads for this.
    private final EnumSet<CipherTextFlags> allCtFlags =
        EnumSet.of(CipherTextFlags.ALGNAME,    CipherTextFlags.CIPHERMODE,
                   CipherTextFlags.PADDING,    CipherTextFlags.KEYSIZE,
                   CipherTextFlags.BLOCKSIZE,  CipherTextFlags.CIPHERTEXT,
                   CipherTextFlags.INITVECTOR);
    
    // These are all the pieces we collect when passed a CipherSpec object.
    private final EnumSet<CipherTextFlags> fromCipherSpec =
    	EnumSet.of(CipherTextFlags.ALGNAME,    CipherTextFlags.CIPHERMODE,
                   CipherTextFlags.PADDING,    CipherTextFlags.KEYSIZE,
                   CipherTextFlags.BLOCKSIZE);

    // How much we've collected so far. We start out with having collected nothing.
    private EnumSet<CipherTextFlags> progress = EnumSet.noneOf(CipherTextFlags.class);

    ///////////////////////////  C O N S T R U C T O R S  /////////////////////////
    
	/**
	 * Default CTOR. Takes all the defaults from the ESAPI.properties, or
	 * default values from initial values from this class (when appropriate)
	 * when they are not set in ESAPI.properties.
	 */
	public DefaultCipherText() {
		cipherSpec_ = new CipherSpec(); // Uses default for everything but IV.
		received(fromCipherSpec);
	}
	
	/**
	 * Construct from a {@code CipherSpec} object. Still needs to have
	 * {@link #setCiphertext(byte[])} or {@link #setIVandCiphertext(byte[], byte[])}
	 * called to be usable.
	 * 
	 * @param cipherSpec The cipher specification to use.
	 */
	public DefaultCipherText(final CipherSpec cipherSpec) {
		cipherSpec_  = cipherSpec;
		received(fromCipherSpec);
		if ( cipherSpec.getIV() != null ) {
			received(CipherTextFlags.INITVECTOR);
		}
	}
	
	/**
	 * Construct from a {@code CipherSpec} object and the raw ciphertext.
	 * 
	 * @param cipherSpec The cipher specification to use.
	 * @param cipherText The raw ciphertext bytes to use.
	 * @throws EncryptionException	Thrown if {@code cipherText} is null or
	 * 					 empty array.
	 */
	public DefaultCipherText(final CipherSpec cipherSpec, byte[] cipherText)
		throws EncryptionException
	{
		cipherSpec_ = cipherSpec;
		setCiphertext(cipherText);
		received(fromCipherSpec);
		if ( cipherSpec.getIV() != null ) {
			received(CipherTextFlags.INITVECTOR);
		}
		received(CipherTextFlags.CIPHERTEXT);
	}
   
	/////////////////////////  P U B L I C   M E T H O D S  ////////////////////
	
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
		if ( isCollected(CipherTextFlags.INITVECTOR) ) {
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
		if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
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
		if ( isCollected(CipherTextFlags.INITVECTOR) && isCollected(CipherTextFlags.CIPHERTEXT) ) {
			// First concatenate IV + raw ciphertext
			byte[] iv = getIV();
			byte[] raw = getRawCipherText();
			byte[] ivPlusCipherText = new byte[ iv.length + raw.length ];
			System.arraycopy(iv, 0, ivPlusCipherText, 0, iv.length);
			System.arraycopy(raw, 0, ivPlusCipherText, iv.length, raw.length);
			// Then return the base64 encoded result
			return ESAPI.encoder().encodeForBase64(ivPlusCipherText, false);
		} else {
			logger.error(Logger.SECURITY_FAILURE, "Raw ciphertext and/or IV not set yet; unable to retrieve; returning null");
			return null;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void computeAndStoreMIC(byte[] raw_ciphertext) {
		assert !micComputed() : "Programming error: Can't store message integrity code while encrypting; " +
										  "computeAndStoreMIC() called multiple times.";
		assert collectedAll() : "Have not collected all required information to compute and store MIC.";
		byte[] result = computeMIC(raw_ciphertext);
		if ( result != null ) {
			mic_ = new byte[ result.length ];
			CryptoHelper.copyByteArray(result, mic_);
			assert micComputed();
		}
		// If 'result' is null, we already logged this in computeMIC().
	}
	
	/**
	 * {@inheritDoc}
	 */ 
	public boolean validateMIC(byte[] ciphertext) {
		boolean usesMIC = ESAPI.securityConfiguration().useMICforCipherText();

		if (  usesMIC && micComputed() ) {	// Uses MIC and it was computed
			// Calculate MIC from HMAC-SHA1(nonce, IV + plaintext) and
			// compare to stored value (mic_). If same, then return true,
			// else return false.
			assert getNonce() != null : "Cannot validate MIC while nonce is null.";
			byte[] mic = computeMIC(ciphertext);
			assert mic.length == mic_.length : "MICs are of differnt lengths. Should both be the same.";
			for ( int i = 0; i < mic.length; i++ ) {
				if ( mic[i] != mic_[i] ) {
					return false;
				}
			}
			return true;
		} else if ( ! usesMIC ) {			// Doesn't use MIC
			return true;
		} else {							// Uses MIC but it has not been computed / stored.
			logger.warning(Logger.SECURITY_FAILURE, "Cannot validate MIC as it was never computed and stored. Decryption result may be garbage.");
			return true;	// Need to return 'true' here because of CryptoHelper encrypt() / decrypt() methods.
		}
	}

	
	/**
	 * Set the raw ciphertext.
	 * @param ciphertext	The raw ciphertext.
	 * @throws EncryptionException	Thrown if the MIC has already been computed
	 * 				via {@link #computeAndStoreMIC(byte[])}.
	 */
	public void setCiphertext(byte[] ciphertext)
		throws EncryptionException
	{
		if ( ! micComputed() ) {
			if ( ciphertext == null || ciphertext.length == 0 ) {
				throw new EncryptionException("Encryption faled; no ciphertext",
											  "Ciphertext may not be null or 0 length!");
			}
			if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
				logger.warning(Logger.SECURITY_FAILURE, "Raw ciphertext was already set; resetting.");
			}
			raw_ciphertext_ = new byte[ ciphertext.length ];
			CryptoHelper.copyByteArray(ciphertext, raw_ciphertext_);
		} else {
			String logMsg = "Programming error: Attempt to set ciphertext after MIC already computed.";
			logger.error(Logger.SECURITY_FAILURE, logMsg);
			throw new EncryptionException("Cannot store raw ciphertext.", logMsg);
		}
	}
	
	/**
	 * Set the IV and raw ciphertext.
	 * @param iv			The initialization vector.
	 * @param ciphertext	The raw ciphertext.
	 * @throws EncryptionException
	 */
	public void setIVandCiphertext(byte[] iv, byte[] ciphertext)
		throws EncryptionException
	{
		if ( isCollected(CipherTextFlags.INITVECTOR) ) {
			logger.warning(Logger.SECURITY_FAILURE, "IV was already set; resetting.");
		}
		if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
			logger.warning(Logger.SECURITY_FAILURE, "Raw ciphertext was already set; resetting.");
		}
		if ( ! micComputed() ) {
			if ( ciphertext == null || ciphertext.length == 0 ) {
				throw new EncryptionException("Encryption faled; no ciphertext",
											  "Ciphertext may not be null or 0 length!");
			}
			if ( iv == null || iv.length == 0 ) {
				if ( requiresIV() ) {
					throw new EncryptionException("Encryption failed -- mandatory IV missing", // DISCUSS - also log? See below.
												  "Cipher mode " + getCipherMode() + " has null or empty IV");
				}
			} else if ( iv.length != getBlockSize() ) {
					throw new EncryptionException("Encryption failed -- bad parameters passed to encrypt",	// DISCUSS - also log? See below.
												  "IV length does not match cipher block size of " + getBlockSize());
			}
			cipherSpec_.setIV(iv);
			received(CipherTextFlags.INITVECTOR);
			setCiphertext( ciphertext );
			received(CipherTextFlags.CIPHERTEXT);
		} else {
			String logMsg = "MIC already computed from previously set IV and raw ciphertext; may not be reset -- object is immutable.";
			logger.error(Logger.SECURITY_FAILURE, logMsg);	// Discuss: By throwing, this gets logged as warning, but it's really error! Why is an exception only a warning???
			throw new EncryptionException("Validation of decryption failed.", logMsg);
		}
	}
	
	/**
	 *  {@inheritDoc}
	 */
	public boolean requiresIV() {
		return cipherSpec_.requiresIV();
	}
	
	/**
	 * More useful {@code toString()} method.
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder( "DefaultCipherText: " );
		String rawCipherText = (( getRawCipherText() != null ) ? "present" : "absent");
		String mic = (( mic_ != null ) ? "present" : "absent");
		sb.append("raw ciphertext is ").append(rawCipherText);
		sb.append(", MIC is ").append(mic).append("; ");
		sb.append( cipherSpec_.toString() );
		return sb.toString();
	}
	
	////////////////////////////////////  P R I V A T E  /////////////////////////////////////////
	
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
				nonce_ = sk.getEncoded();	// Side-effect -- nonce set here!
				assert nonce_ != null : "Failed to create nonce value.";
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
	 * Return true if the MIC has already been computed (i.e., not null).
	 */
	private boolean micComputed() {
		return (mic_ != null);
	}

	/**
	 *  Retrieve the nonce value used in the calculation of the MIC.
	 */
	private byte[] getNonce() {
		if ( micComputed() ) {
			return nonce_;
		} else {
			logger.error(Logger.SECURITY_FAILURE, "Nonce for MIC not set yet; unable to retrieve; returning null");
			return null;
		}
	}

	/**
	 * Return true if we've collected all the required pieces; otherwise false.
	 */
    private boolean collectedAll() {
    	EnumSet<CipherTextFlags> ctFlags = null;
    	if ( requiresIV() ) {
    		ctFlags = allCtFlags;
    	} else {
    		EnumSet<CipherTextFlags> initVector = EnumSet.of(CipherTextFlags.INITVECTOR);
    		ctFlags = EnumSet.complementOf(initVector);
    	}
    	boolean result = progress.containsAll(ctFlags);  
        return result;
    }

    /** Check if we've collected a specific flag type.
     * @param flag	The flag type; e.g., {@code CipherTextFlags.INITVECTOR}, etc.
     * @return	Return true if we've collected a specific flag type; otherwise false.
     */
    private boolean isCollected(CipherTextFlags flag) {
        return progress.contains(flag);
    }

    /**
     * Add the flag to the set of what we've already collected.
     * @param flag	The flag type to be added; e.g., {@code CipherTextFlags.INITVECTOR}.
     */
    private void received(CipherTextFlags flag) {
        progress.add(flag);
    }
    
    /**
     * Add all the flags from the specified set to that we've collected so far.
     * @param ctSet	A {@code EnumSet<CipherTextFlags>} containing all the flags
     * 				we wish to add.
     */
    private void received(EnumSet<CipherTextFlags> ctSet) {
    	Iterator<CipherTextFlags> it = ctSet.iterator();
    	while ( it.hasNext() ) {
    		received( it.next() );
    	}
    }
    
}

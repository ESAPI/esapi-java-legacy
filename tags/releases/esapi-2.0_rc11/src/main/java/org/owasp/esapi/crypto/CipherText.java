/*
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright &copy; 2009 - The OWASP Foundation
 */
package org.owasp.esapi.crypto;


import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.EnumSet;
import java.util.Iterator;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.EncryptionException;

// CHECKME: Some of these assertions probably should be actual runtime checks
//          with suitable exceptions to account for cases where programmers
//          accidentally pass in byte arrays that are not really serialized
//          CipherText objects (note: as per asPortableSerializedByteArra()).
//          However, not sure what exception time is really suitable here.
//          It probably should be a sub-class of RuntimeException, but
//          IllegalArguementException doesn't really make sense here. Suggestions?

/**
 * A {@code Serializable} interface representing the result of encrypting
 * plaintext and some additional information about the encryption algorithm,
 * the IV (if pertinent), and an optional Message Authentication Code (MAC).
 * </p><p>
 * Note that while this class is {@code Serializable} in the usual Java sense,
 * ESAPI uses {@link #asPortableSerializedByteArray()} for serialization. Not
 * only is this serialization somewhat more compact, it is also portable
 * across other ESAPI programming language implementations. However, Java
 * serialization is supported in the event that one wishes to store
 * {@code CipherText} in an {@code HttpSession} object.
 * </p><p>
 * Copyright &copy; 2009 - The OWASP Foundation
 * </p>
 * @author kevin.w.wall@gmail.com
 * @see PlainText
 * @see org.owasp.esapi.Encryptor
 * @since 2.0
 */
public final class CipherText implements Serializable {	
    // NOTE: Do NOT change this in future versions, unless you are knowingly
    //       making changes to the class that will render this class incompatible
    //       with previously serialized objects from older versions of this class.
	//		 If this is done, that you must provide for supporting earlier ESAPI versions.
    //       Be wary making incompatible changes as discussed at:
    //          http://java.sun.com/javase/6/docs/platform/serialization/spec/version.html#6678
    //       Any incompatible change in the serialization of CipherText *must* be
    //       reflected in the class CipherTextSerializer.
    // This should be *same* version as in CipherTextSerializer and KeyDerivationFunction.
	// If one changes, the other should as well to accommodate any differences.
	public  static final int cipherTextVersion = 20110203; // Format: YYYYMMDD, max is 99991231.
		// Required by Serializable classes.
	private static final long serialVersionUID = cipherTextVersion; // Format: YYYYMMDD
	
	private static final Logger logger = ESAPI.getLogger("CipherText");
    
    private CipherSpec cipherSpec_           = null;
    private byte[]     raw_ciphertext_       = null;
    private byte[]     separate_mac_         = null;
    private long       encryption_timestamp_ = 0;
    private int		   kdfVersion_           = KeyDerivationFunction.kdfVersion;
    private int		   kdfPrfSelection_      = KeyDerivationFunction.getDefaultPRFSelection();

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
    public CipherText() {
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
    public CipherText(final CipherSpec cipherSpec) {
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
     * @throws EncryptionException  Thrown if {@code cipherText} is null or
     *                   empty array.
     */
    public CipherText(final CipherSpec cipherSpec, byte[] cipherText)
        throws EncryptionException
    {
        cipherSpec_ = cipherSpec;
        setCiphertext(cipherText);
        received(fromCipherSpec);
        if ( cipherSpec.getIV() != null ) {
            received(CipherTextFlags.INITVECTOR);
        }
    }
    
    /** Create a {@code CipherText} object from what is supposed to be a
     *  portable serialized byte array, given in network byte order, that
     *  represents a valid, previously serialized {@code CipherText} object
     *  using {@link #asPortableSerializedByteArray()}.
     * @param bytes A byte array created via
     *              {@code CipherText.asPortableSerializedByteArray()}
     * @return A {@code CipherText} object reconstructed from the byte array.
     * @throws EncryptionException
     * @see #asPortableSerializedByteArray()
     */     // DISCUSS: BTW, I detest this name. Suggestions???
    public static CipherText fromPortableSerializedBytes(byte[] bytes)
            throws EncryptionException
    {
        CipherTextSerializer cts = new CipherTextSerializer(bytes);
        return cts.asCipherText();
    }

    /////////////////////////  P U B L I C   M E T H O D S  ////////////////////

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
    public String getCipherTransformation() {
        return cipherSpec_.getCipherTransformation();
    }
	
	/**
	 * Obtain the name of the cipher algorithm used for encrypting the
	 * plaintext.
	 * 
	 * @return The name as the cryptographic algorithm used to perform the
	 * 		   encryption resulting in this ciphertext.
	 */
    public String getCipherAlgorithm() {
        return cipherSpec_.getCipherAlgorithm();
    }
	
	/**
	 * Retrieve the key size used with the cipher algorithm that was used to
	 * encrypt data to produce this ciphertext.
	 * 
	 * @return The key size in bits. We work in bits because that's the crypto way!
	 */
    public int getKeySize() {
        return cipherSpec_.getKeySize();
    }
	
	/**
	 * Retrieve the block size (in bytes!) of the cipher used for encryption.
	 * (Note: If an IV is used, this will also be the IV length.)
	 * 
	 * @return The block size in bytes. (Bits, bytes! It's confusing I know. Blame
	 * 									the cryptographers; we've just following
	 * 									convention.)
	 */
    public int getBlockSize() {
        return cipherSpec_.getBlockSize();
    }
	
	/**
	 * Get the name of the cipher mode used to encrypt some plaintext.
	 * 
	 * @return The name of the cipher mode used to encrypt the plaintext
	 *         resulting in this ciphertext. E.g., "CBC" for "cipher block
	 *         chaining", "ECB" for "electronic code book", etc.
	 */
    public String getCipherMode() {
        return cipherSpec_.getCipherMode();
    }
	
	/**
	 * Get the name of the padding scheme used to encrypt some plaintext.
	 * 
	 * @return The name of the padding scheme used to encrypt the plaintext
	 * 		   resulting in this ciphertext. Example: "PKCS5Padding". If no
	 * 		   padding was used "None" is returned.
	 */
    public String getPaddingScheme() {
        return cipherSpec_.getPaddingScheme();
    }
	
	/**
	 * Return the initialization vector (IV) used to encrypt the plaintext
	 * if applicable.
	 *  
	 * @return	The IV is returned if the cipher mode used to encrypt the
	 * 			plaintext was not "ECB". ECB mode does not use an IV so in
	 * 			that case, <code>null</code> is returned.
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
	 * Return true if the cipher mode used requires an IV. Usually this will
	 * be true unless ECB mode (which should be avoided whenever possible) is
	 * used.
	 */
    public boolean requiresIV() {
        return cipherSpec_.requiresIV();
    }
	
	/**
	 * Get the raw ciphertext byte array resulting from encrypting some
	 * plaintext.
	 * 
	 * @return A copy of the raw ciphertext as a byte array.
	 */
	public byte[] getRawCipherText() {
	    if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
	        byte[] copy = new byte[ raw_ciphertext_.length ];
	        System.arraycopy(raw_ciphertext_, 0, copy, 0, raw_ciphertext_.length);
	        return copy;
	    } else {
	        logger.error(Logger.SECURITY_FAILURE, "Raw ciphertext not set yet; unable to retrieve; returning null");
	        return null;
	    }
	}
	
	/**
	 * Get number of bytes in raw ciphertext. Zero is returned if ciphertext has not
	 * yet been stored.
	 * 
	 * @return The number of bytes of raw ciphertext; 0 if no raw ciphertext has been stored.
	 */
	public int getRawCipherTextByteLength() {
	    if ( raw_ciphertext_ != null ) {
	        return raw_ciphertext_.length;
	    } else {
	        return 0;
	    }
	}

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
	public String getBase64EncodedRawCipherText() {
	    return ESAPI.encoder().encodeForBase64(getRawCipherText(),false);
	}
	
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
	 * Compute and store the Message Authentication Code (MAC) if the ESAPI property
	 * {@code Encryptor.CipherText.useMAC} is set to {@code true}. If it
	 * is, the MAC is conceptually calculated as:
	 * <pre>
	 * 		authKey = DerivedKey(secret_key, "authenticate")
	 * 		HMAC-SHA1(authKey, IV + secret_key)
	 * </pre>
	 * where derived key is an HMacSHA1, possibly repeated multiple times.
	 * (See {@link org.owasp.esapi.crypto.CryptoHelper#computeDerivedKey(SecretKey, int, String)}
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
	 *				{@link org.owasp.esapi.crypto.CryptoHelper#computeDerivedKey(SecretKey, int, String)}
	 *				is a secure way to produce this derived key.
	 */		// DISCUSS - Cryptographers David Wagner, Ian Grigg, and others suggest
			// computing authenticity using derived key and HmacSHA1 of IV + ciphertext.
			// However they also argue that what should be returned and treated as
			// (i.e., stored as) ciphertext would be something like this:
			//		len_of_raw_ciphertext + IV + raw_ciphertext + MAC
			// TODO: Need to do something like this for custom serialization and then
	        // document order / format so it can be used by other ESAPI implementations.
	public void computeAndStoreMAC(SecretKey authKey) {
	    assert !macComputed() : "Programming error: Can't store message integrity code " +
	                            "while encrypting; computeAndStoreMAC() called multiple times.";
	    assert collectedAll() : "Have not collected all required information to compute and store MAC.";
	    byte[] result = computeMAC(authKey);
	    if ( result != null ) {
	        storeSeparateMAC(result);
	    }
	    // If 'result' is null, we already logged this in computeMAC().
	}
	
	/**
	 * Same as {@link #computeAndStoreMAC(SecretKey)} but this is only used by
	 * {@code CipherTextSerializeer}. (Has package level access.)
	 */ // CHECKME: For this to be "safe", it requires ESAPI jar to be sealed.
	void storeSeparateMAC(byte[] macValue) {
	    if ( !macComputed() ) {
	        separate_mac_ = new byte[ macValue.length ];
	        CryptoHelper.copyByteArray(macValue, separate_mac_);
	        assert macComputed();
	    }
	}
	
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
	 *				{@link org.owasp.esapi.crypto.CryptoHelper#computeDerivedKey(SecretKey, int, String)}
	 *				is a secure way to produce this derived key.
	 * @return True if the ciphertext has not be tampered with, and false otherwise.
	 */
	public boolean validateMAC(SecretKey authKey) {
	    boolean usesMAC = ESAPI.securityConfiguration().useMACforCipherText();

	    if (  usesMAC && macComputed() ) {  // Uses MAC and it was computed
	        // Calculate MAC from HMAC-SHA1(nonce, IV + plaintext) and
	        // compare to stored value (separate_mac_). If same, then return true,
	        // else return false.
	        byte[] mac = computeMAC(authKey);
	        assert mac.length == separate_mac_.length : "MACs are of differnt lengths. Should both be the same.";
	        return CryptoHelper.arrayCompare(mac, separate_mac_); // Safe compare!!!
	    } else if ( ! usesMAC ) {           // Doesn't use MAC
	        return true;
	    } else {                            // Uses MAC but it has not been computed / stored.
	        logger.warning(Logger.SECURITY_FAILURE, "Cannot validate MAC as it was never computed and stored. " +
	        "Decryption result may be garbage even when decryption succeeds.");
	        return true;    // Need to return 'true' here because of encrypt() / decrypt() methods don't support this.
	    }
	}
	
	/**
	 * Return this {@code CipherText} object as a portable (i.e., network byte
	 * ordered) serialized byte array. Note this is <b>not</b> the same as
	 * returning a serialized object using Java serialization. Instead this
	 * is a representation that all ESAPI implementations will use to pass
	 * ciphertext between different programming language implementations.
	 * 
	 * @return A network byte-ordered serialized representation of this object.
	 * @throws EncryptionException
	 */    // DISCUSS: This method name sucks too. Suggestions???
	public byte[] asPortableSerializedByteArray() throws EncryptionException {
        // Check if this CipherText object is "complete", i.e., all
        // mandatory has been collected.
	    if ( ! collectedAll() ) {
	        String msg = "Can't serialize this CipherText object yet as not " +
	                     "all mandatory information has been collected";
	        throw new EncryptionException("Can't serialize incomplete ciphertext info", msg);
	    }
	    
	    // If we are supposed to be using a (separate) MAC, also make sure
	    // that it has been computed/stored.
	    boolean usesMAC = ESAPI.securityConfiguration().useMACforCipherText();
	    if (  usesMAC && ! macComputed() ) {
	        String msg = "Programming error: MAC is required for this cipher mode (" +
	                     getCipherMode() + "), but MAC has not yet been " +
	                     "computed and stored. Call the method " +
	                     "computeAndStoreMAC(SecretKey) first before " +
	                     "attempting serialization.";
	        throw new EncryptionException("Can't serialize ciphertext info: Data integrity issue.",
	                                      msg);
	    }
	    
	    // OK, everything ready, so give it a shot.
	    return new CipherTextSerializer(this).asSerializedByteArray();
	}
	
    ///// Setters /////
    /**
     * Set the raw ciphertext.
     * @param ciphertext    The raw ciphertext.
     * @throws EncryptionException  Thrown if the MAC has already been computed
     *              via {@link #computeAndStoreMAC(SecretKey)}.
     */
    public void setCiphertext(byte[] ciphertext)
        throws EncryptionException
    {
        if ( ! macComputed() ) {
            if ( ciphertext == null || ciphertext.length == 0 ) {
                throw new EncryptionException("Encryption faled; no ciphertext",
                                              "Ciphertext may not be null or 0 length!");
            }
            if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
                logger.warning(Logger.SECURITY_FAILURE, "Raw ciphertext was already set; resetting.");
            }
            raw_ciphertext_ = new byte[ ciphertext.length ];
            CryptoHelper.copyByteArray(ciphertext, raw_ciphertext_);
            received(CipherTextFlags.CIPHERTEXT);
            setEncryptionTimestamp();
        } else {
            String logMsg = "Programming error: Attempt to set ciphertext after MAC already computed.";
            logger.error(Logger.SECURITY_FAILURE, logMsg);
            throw new EncryptionException("MAC already set; cannot store new raw ciphertext", logMsg);
        }
    }
    
    /**
     * Set the IV and raw ciphertext.
     * @param iv            The initialization vector.
     * @param ciphertext    The raw ciphertext.
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
        if ( ! macComputed() ) {
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
                    throw new EncryptionException("Encryption failed -- bad parameters passed to encrypt",  // DISCUSS - also log? See below.
                                                  "IV length does not match cipher block size of " + getBlockSize());
            }
            cipherSpec_.setIV(iv);
            received(CipherTextFlags.INITVECTOR);
            setCiphertext( ciphertext );
        } else {
            String logMsg = "MAC already computed from previously set IV and raw ciphertext; may not be reset -- object is immutable.";
            logger.error(Logger.SECURITY_FAILURE, logMsg);  // Discuss: By throwing, this gets logged as warning, but it's really error! Why is an exception only a warning???
            throw new EncryptionException("Validation of decryption failed.", logMsg);
        }
    }
    
    public int getKDFVersion() {
    	return kdfVersion_;
    }

    public void setKDFVersion(int vers) {
    	assert vers > 0 && vers <= 99991231 : "Version must be positive, in format YYYYMMDD and <= 99991231.";
    	kdfVersion_ = vers;
    }
    
    public KeyDerivationFunction.PRF_ALGORITHMS getKDF_PRF() {
    	return KeyDerivationFunction.convertIntToPRF(kdfPrfSelection_);
    }

    int kdfPRFAsInt() {
    	return kdfPrfSelection_;
    }
    
    public void setKDF_PRF(int prfSelection) {
        assert prfSelection >= 0 && prfSelection <= 15 : "kdfPrf == " + prfSelection + " must be between 0 and 15.";
    	kdfPrfSelection_ = prfSelection;
    }
    
    /** Get stored time stamp representing when data was encrypted. */
    public long getEncryptionTimestamp() {
        return encryption_timestamp_;
    }
    
    /**
     * Set the encryption timestamp to the current system time as determined by
     * {@code System.currentTimeMillis()}, but only if it has not been previously
     * set. That is, this method ony has an effect the first time that it is
     * called for this object.
     */
    private void setEncryptionTimestamp() {
        // We want to skip this when it's already been set via the package
        // level call setEncryptionTimestamp(long) done via CipherTextSerializer
        // otherwise it gets reset to the current time. But when it's restored
        // from a serialized CipherText object, we want to keep the original
        // encryption timestamp.
        if ( encryption_timestamp_ != 0 ) {
            logger.warning(Logger.EVENT_FAILURE, "Attempt to reset non-zero " +
                    "CipherText encryption timestamp to current time!");
        }
        encryption_timestamp_ = System.currentTimeMillis();
    }
 
    /**
     * Set the encryption timestamp to the time stamp specified by the parameter.
     * </p><p>
     * This method is intended for use only by {@code CipherTextSerializer}.
     * 
     * @param timestamp The time in milliseconds since epoch time (midnight,
     *                  January 1, 1970 GMT).
     */ // Package level access. ESAPI jar should be sealed and signed.
    void setEncryptionTimestamp(long timestamp) {
        assert timestamp > 0 : "Timestamp must be greater than zero.";
        if ( encryption_timestamp_ == 0 ) {     // Only set it if it's not yet been set.
            logger.warning(Logger.EVENT_FAILURE, "Attempt to reset non-zero " +
                           "CipherText encryption timestamp to " + new Date(timestamp) + "!");
        }
        encryption_timestamp_ = timestamp;
    }
    
    /** Used in supporting {@code CipherText} serialization.
     * @deprecated	Use {@code CipherText.cipherTextVersion} instead. Will
     * 				disappear as of ESAPI 2.1.
     */
    public static long getSerialVersionUID() {
        return CipherText.serialVersionUID;
    }
    
    /** Return the separately calculated Message Authentication Code (MAC) that
     * is computed via the {@code computeAndStoreMAC(SecretKey authKey)} method.
     * @return The copy of the computed MAC, or {@code null} if one is not used.
     */
    public byte[] getSeparateMAC() {
        if ( separate_mac_ == null ) {
            return null;
        }
        byte[] copy = new byte[ separate_mac_.length ];
        System.arraycopy(separate_mac_, 0, copy, 0, separate_mac_.length);
        return copy;   
    }
    
    /**
     * More useful {@code toString()} method.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder( "CipherText: " );
        String creationTime = (( getEncryptionTimestamp() == 0) ? "No timestamp available" :
                                (new Date(getEncryptionTimestamp())).toString());
        int n = getRawCipherTextByteLength();
        String rawCipherText = (( n > 0 ) ? "present (" + n + " bytes)" : "absent");
        String mac = (( separate_mac_ != null ) ? "present" : "absent");
        sb.append("Creation time: ").append(creationTime);
        sb.append(", raw ciphertext is ").append(rawCipherText);
        sb.append(", MAC is ").append(mac).append("; ");
        sb.append( cipherSpec_.toString() );
        return sb.toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override public boolean equals(Object other) {
        boolean result = false;
        if ( this == other )
            return true;
        if ( other == null )
            return false;
        if ( other instanceof CipherText) {
            CipherText that = (CipherText)other;
            if ( this.collectedAll() && that.collectedAll() ) {
                result = (that.canEqual(this) &&
                          this.cipherSpec_.equals(that.cipherSpec_) &&
                            // Safe comparison, resistant to timing attacks
                          CryptoHelper.arrayCompare(this.raw_ciphertext_, that.raw_ciphertext_) &&
                          CryptoHelper.arrayCompare(this.separate_mac_, that.separate_mac_) &&
                          this.encryption_timestamp_ == that.encryption_timestamp_ );
            } else {
                logger.warning(Logger.EVENT_FAILURE, "CipherText.equals(): Cannot compare two " +
                               "CipherText objects that are not complete, and therefore immutable!");
                logger.info(Logger.EVENT_FAILURE, "This CipherText: " + this.collectedAll() + ";" +
                            "other CipherText: " + that.collectedAll());
                logger.info(Logger.EVENT_FAILURE, "CipherText.equals(): Progress comparison: " +
                               ((this.progress == that.progress) ? "Same" : "Different"));
                logger.info(Logger.EVENT_FAILURE, "CipherText.equals(): Status this: " + this.progress +
                               "; status other CipherText object: " + that.progress);
                // CHECKME: Perhaps we should throw a RuntimeException instead???
                return false;
            }
        }
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override public int hashCode() {
        if ( this.collectedAll() ) {
                logger.warning(Logger.EVENT_FAILURE, "CipherText.hashCode(): Cannot compute " +
                               "hachCode() of incomplete CipherText object; object not immutable- " +
                               "returning 0.");
                // CHECKME: Throw RuntimeException instead?
                return 0;
        }
        StringBuilder sb = new StringBuilder();
        sb.append( cipherSpec_.hashCode() );
        sb.append( encryption_timestamp_ );
        String raw_ct = null;
        String mac = null;
        try {
            raw_ct = new String(raw_ciphertext_, "UTF-8");
                // Remember, MAC is optional even when CipherText is complete.
            mac = new String( ((separate_mac_ != null) ? separate_mac_ : new byte[] { }), "UTF-8");
        } catch(UnsupportedEncodingException ex) {
            // Should never happen as UTF-8 encode supported by rt.jar,
            // but it it does, just use default encoding.
            raw_ct = new String(raw_ciphertext_);
            mac = new String( ((separate_mac_ != null) ? separate_mac_ : new byte[] { }));
        }
        sb.append( raw_ct );
        sb.append( mac );
        return sb.toString().hashCode();
    }

    /**
     * Needed for correct definition of equals for general classes.
     * (Technically not needed for 'final' classes though like this class
     * though; this will just allow it to work in the future should we
     * decide to allow * sub-classing of this class.)
     * </p><p>
     * See {@link http://www.artima.com/lejava/articles/equality.html}
     * for full explanation.
     * </p>
     */
    protected boolean canEqual(Object other) {
        return (other instanceof CipherText);
    }

    ////////////////////////////////////  P R I V A T E  /////////////////////////////////////////
    
    /**
     * Compute a MAC, but do not store it. May set the nonce value as a
     * side-effect.  The MAC is calculated as:
     * <pre>
     *      HMAC-SHA1(nonce, IV + plaintext)
     * </pre>
     * @param ciphertext    The ciphertext value for which the MAC is computed.
     * @return The value for the MAC.
     */ 
    private byte[] computeMAC(SecretKey authKey) {
        assert raw_ciphertext_ != null && raw_ciphertext_.length != 0 : "Raw ciphertext may not be null or empty.";
        assert authKey != null && authKey.getEncoded().length != 0 : "Authenticity secret key may not be null or zero length.";
        try {
        	// IMPORTANT NOTE: The NSA review was (apparently) OK with using HmacSHA1
        	// to calculate the MAC that ensures authenticity of the IV+ciphertext.
        	// (Not true of calculation of the use HmacSHA1 for the KDF though.) Therefore,
        	// we did not make this configurable. Note also that choosing an improved
        	// MAC algorithm here would cause the overall length of the serialized ciphertext
        	// to be just that much longer, which is probably unacceptable when encrypting
        	// short strings.
            SecretKey sk = new SecretKeySpec(authKey.getEncoded(), "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(sk);
            if ( requiresIV() ) {
                mac.update( getIV() );
            }
            byte[] result = mac.doFinal( getRawCipherText() );
            return result;
        } catch (NoSuchAlgorithmException e) {
            logger.error(Logger.SECURITY_FAILURE, "Cannot compute MAC w/out HmacSHA1.", e);
            return null;
        } catch (InvalidKeyException e) {
            logger.error(Logger.SECURITY_FAILURE, "Cannot comput MAC; invalid 'key' for HmacSHA1.", e);
            return null;
        }
    }
    
    /**
     * Return true if the MAC has already been computed (i.e., not null).
     */
    private boolean macComputed() {
        return (separate_mac_ != null);
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
     * @param flag  The flag type; e.g., {@code CipherTextFlags.INITVECTOR}, etc.
     * @return  Return true if we've collected a specific flag type; otherwise false.
     */
    private boolean isCollected(CipherTextFlags flag) {
        return progress.contains(flag);
    }

    /**
     * Add the flag to the set of what we've already collected.
     * @param flag  The flag type to be added; e.g., {@code CipherTextFlags.INITVECTOR}.
     */
    private void received(CipherTextFlags flag) {
        progress.add(flag);
    }
    
    /**
     * Add all the flags from the specified set to that we've collected so far.
     * @param ctSet A {@code EnumSet<CipherTextFlags>} containing all the flags
     *              we wish to add.
     */
    private void received(EnumSet<CipherTextFlags> ctSet) {
        Iterator<CipherTextFlags> it = ctSet.iterator();
        while ( it.hasNext() ) {
            received( it.next() );
        }
    }

    /**
     * Based on the KDF version and the selected MAC algorithm for the KDF PRF,
     * calculate the 32-bit quantity representing these.
     * @return	A 4-byte (octet) quantity representing the KDF version and the
     * 			MAC algorithm used for the KDF's Pseudo-Random Function.
     * @see <a href="http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-ciphertext-serialization.pdf">Format of portable serialization of org.owasp.esapi.crypto.CipherText object (pg 2)</a>
     */
	public int getKDFInfo() {
		final int unusedBit28 = 0x8000000;  // 1000000000000000000000000000
		
		// 		kdf version is bits 1-27, bit 28 (reserved) should be 0, and
		//		bits 29-32 are the MAC algorithm indicating which PRF to use for the KDF.
		int kdfVers = getKDFVersion();
		assert kdfVers > 0 && kdfVers <= 99991231 : "KDF version (YYYYMMDD, max 99991231) out of range: " + kdfVers;
		int kdfInfo = kdfVers;
		int macAlg = kdfPRFAsInt();
		assert macAlg >= 0 && macAlg <= 15 : "MAC algorithm indicator must be between 0 to 15 inclusion; value is: " + macAlg;
		
	    // Make sure bit28 is cleared. (Reserved for future use.)
	    kdfInfo &= ~unusedBit28;

	    // Set MAC algorithm bits in high (MSB) nibble.
	    kdfInfo |= (macAlg << 28);

		return kdfInfo;
	}
}

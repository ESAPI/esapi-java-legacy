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
package org.owasp.esapi.crypto;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.util.NullSafe;


/**
 * Specifies all the relevant configuration data needed in constructing and
 * using a {@link javax.crypto.Cipher} except for the encryption key.
 * </p><p>
 * The "setters" all return a reference to {@code this} so that they can be
 * strung together.
 * </p><p>
 * Note: While this is a useful class in it's own right, it should primarily be
 * regarded as an implementation class to use with ESAPI encryption, especially
 * the reference implementation. It is <i>not</i> intended to be used directly
 * by application developers, but rather only by those either extending ESAPI
 * or in the ESAPI reference implementation. Use <i>directly</i> by application
 * code is not recommended or supported.
 * 
 * @author kevin.w.wall@gmail.com
 * @since 2.0
 */
public final class CipherSpec implements Serializable {

	private static final long serialVersionUID = 20090822;	// version, in YYYYMMDD format
	
	private String  cipher_xform_   = ESAPI.securityConfiguration().getCipherTransformation();
	private int     keySize_        = ESAPI.securityConfiguration().getEncryptionKeyLength(); // In bits
	private int     blockSize_      = 16;   // In bytes! I.e., 128 bits!!!
	private byte[]  iv_             = null;

	private boolean blockSizeExplicitlySet = false;	// Used for check in setIV().
	
	// Cipher transformation component. Format is ALG/MODE/PADDING
    private enum CipherTransformationComponent { ALG, MODE, PADDING }

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
		// because of checks in setIV().
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
		// All defaults
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
	 * 						"DESede/CBC/PKCS5Padding". May not be null or empty.
	 * @param fromCipher If true, the cipher transformation was set via
	 * 					 {@code Cipher.getAlgorithm()} which may only return the
	 * 					 actual algorithm. In that case we check and if all 3 parts
	 * 					 were not specified, then we specify the parts that were
	 * 					 based on "ECB" as the default cipher mode and "NoPadding"
	 * 					 as the default padding scheme.
	 * @return	This current {@code CipherSpec} object.
	 */
	private CipherSpec setCipherTransformation(String cipherXform, boolean fromCipher) {
		if ( ! StringUtilities.notNullOrEmpty(cipherXform, true) ) {	// Yes, really want '!' here.
			throw new IllegalArgumentException("Cipher transformation may not be null or empty string (after trimming whitespace).");
		}
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
				// All three parts provided. Do nothing. Could happen if not compiled with
				// assertions enabled.
				;	// Do nothing - shown only for completeness.
			} else {
				// Should never happen unless Cipher implementation is totally screwed up.
				throw new IllegalArgumentException("Cipher transformation '" +
								cipherXform + "' must have form \"alg/mode/paddingscheme\"");
			}
		} else if ( !fromCipher && parts != 3 ) {
			throw new IllegalArgumentException("Malformed cipherXform (" + cipherXform +
											   "); must have form: \"alg/mode/paddingscheme\"");
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
		if ( keySize <= 0 ) {
			throw new IllegalArgumentException("keySize must be > 0; keySize=" + keySize);
		}
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
	 * @param blockSize	The block size, in bytes. Must be positive integer appropriate
	 * 					for the specified cipher algorithm.
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec setBlockSize(int blockSize) {
		if ( blockSize <= 0 ) {
			throw new IllegalArgumentException("blockSize must be > 0; blockSize=" + blockSize);
		}
		this.blockSize_ = blockSize;
		blockSizeExplicitlySet = true;
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
		return getFromCipherXform(CipherTransformationComponent.ALG);
	}
	
	/**
	 * Retrieve the cipher mode.
	 * @return	The cipher mode.
	 */
	public String getCipherMode() {
		return getFromCipherXform(CipherTransformationComponent.MODE);
	}
	
	/**
	 * Retrieve the cipher padding scheme.
	 * @return	The padding scheme is returned.
	 */
	public String getPaddingScheme() {
		return getFromCipherXform(CipherTransformationComponent.PADDING);
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
		if ( ! ( requiresIV() && (iv != null && iv.length != 0) ) ) {
			throw new IllegalArgumentException("Required IV cannot be null or 0 length.");
		}
		
		// Don't store a reference, but make a copy! When an IV is provided, it should
		// be the same length as the block size of the cipher.
		if ( iv != null ) {	// Allow null IV for ECB mode.
			  // TODO: FIXME: As per email from Jeff Walton to Kevin Wall dated 12/03/2013,
			  //			  this is not always true. E.g., for CCM, the IV length is supposed
			  //			  to be 7, 8,  7, 8, 9, 10, 11, 12, or 13 octets because of
			  //			  it's formatting function.
/***
			if ( iv.length != this.getBlockSize() && blockSizeExplicitlySet ) {
				throw new IllegalArgumentException("IV must be same length as cipher block size (" +
													this.getBlockSize() + " bytes)");
			}
***/
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
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object other) {
        boolean result = false;
        if ( this == other )
            return true;
        if ( other == null )
            return false;
        if ( other instanceof CipherSpec) {
            CipherSpec that = (CipherSpec)other;
            result = (that.canEqual(this) &&
                      NullSafe.equals(this.cipher_xform_, that.cipher_xform_) &&
                      this.keySize_ == that.keySize_ &&
                      this.blockSize_ == that.blockSize_ &&
                        // Comparison safe from timing attacks.
                      CryptoHelper.arrayCompare(this.iv_, that.iv_) );
        }
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        StringBuilder sb = new StringBuilder();
        sb.append( getCipherTransformation() );
        sb.append( "" + getKeySize() );
        sb.append( "" + getBlockSize() );
        byte[] iv = getIV();
        if ( iv != null && iv.length > 0 ) {
            String ivStr = null;
            try {
                ivStr = new String(iv, "UTF-8");
            }
            catch(UnsupportedEncodingException ex) {
                // Should never happen as UTF-8 encode supported by rt.jar,
                // but it it does, just use default encoding.
                ivStr = new String(iv);
            }
            sb.append( ivStr );
        }
        return sb.toString().hashCode();
    }

    /**
     * Needed for correct definition of equals for general classes.
     * (Technically not needed for 'final' classes like this class though; this
     * will just allow it to work in the future should we decide to allow
     * sub-classing of this class.)
     * </p><p>
     * See <a href="http://www.artima.com/lejava/articles/equality.html">
     * How to write an Equality Method in Java</a>
     * for full explanation.
     * </p>
     */
    protected boolean canEqual(Object other) {
        return (other instanceof CipherSpec);
    }	
	
	/**
	 * Split the current cipher transformation and return the requested part. 
	 * @param component The component of the cipher transformation to return.
	 * @return The cipher algorithm, cipher mode, or padding, as requested.
	 */
	private String getFromCipherXform(CipherTransformationComponent component) {
        int part = component.ordinal();
		String[] parts = getCipherTransformation().split("/");
		assert parts.length == 3 : "Invalid cipher transformation: " + getCipherTransformation();	
		return parts[part];
	}
}

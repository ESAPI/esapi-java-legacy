package org.owasp.esapi.crypto;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;

/**
 * A class representing plaintext (versus ciphertext) as related to
 * cryptographic systems.  This class embodies UTF-8 byte-encoding to
 * translate between byte arrays and {@code String}s. Once constructed, this
 * object is immutable.
 * <p>
 * Note: Conversion to/from UTF-8 byte-encoding can, in theory, throw
 * an {@code UnsupportedEncodingException}. However, UTF-8 encoding
 * should be a standard encoding for all Java installations, so an
 * {@code UnsupportedEncodingException} never actually be thrown. Therefore,
 * in order to to keep client code uncluttered, any possible
 * {@code UnsupportedEncodingException}s will be first logged, and then
 * re-thrown as a {@code RuntimeException} with the original
 * {@code UnsupportedEncodingException} as the cause.
 * <p>
 * Copyright &copy; 2009 - The OWASP Foundation
 * </p>
 * @author kevin.w.wall@gmail.com
 * @see CipherText
 * @since 2.0
 */
public final class PlainText implements Serializable {

	private static final long serialVersionUID = 20090921;
	private static Logger logger = ESAPI.getLogger("PlainText");
	
	private byte[] rawBytes = null;
	
	/**
	 * Construct a {@code PlainText} object from a {@code String}.
	 * @param str	The {@code String} that is converted to a UTF-8 encoded
	 * 				byte array to create the {@code PlainText} object.
	 */
	public PlainText(String str) {
		try {
		    assert str != null : "String for plaintext cannot be null.";
			rawBytes = str.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// Should never happen.
			logger.error(Logger.EVENT_FAILURE, "PlainText(String) CTOR failed: Can't find UTF-8 byte-encoding!", e);
			throw new RuntimeException("Can't find UTF-8 byte-encoding!", e);
		}
	}

	/**
	 * Construct a {@code PlainText} object from a {@code byte} array.
	 * @param b	The {@code byte} array used to create the {@code PlainText}
	 * 			object.
	 */
	public PlainText(byte[] b) {
		// Must allow 0 length arrays though, to represent empty strings.
		assert b != null : "Byte array representing plaintext cannot be null.";
		    // Make copy so mutable byte array b can't change PlainText.
		rawBytes = new byte[ b.length ];
		System.arraycopy(b, 0, rawBytes, 0, b.length);
	}
	
	/**
	 * Convert the {@code PlainText} object to a UTF-8 encoded {@code String}.
	 * @return	A {@code String} representing the {@code PlainText} object.
	 */
	public String toString() {
		try {
			return new String(rawBytes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// Should never happen.
			logger.error(Logger.EVENT_FAILURE, "PlainText.toString() failed: Can't find UTF-8 byte-encoding!", e);
			throw new RuntimeException("Can't find UTF-8 byte-encoding!", e);
		}
	}
	
	/**
	 * Convert the {@code PlainText} object to a byte array.
	 * @return	A byte array representing the {@code PlainText} object.
	 */
	public byte[] asBytes() {
	    byte[] bytes = new byte[ rawBytes.length ];
	    System.arraycopy(rawBytes, 0, bytes, 0, rawBytes.length);
		return bytes;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override public boolean equals(Object anObject) {

        if ( this == anObject ) return true;
        if ( anObject == null ) return false;
        boolean result = false;
        if ( anObject instanceof PlainText ) {
            PlainText that = (PlainText)anObject;
            result = ( that.canEqual(this) &&
                    ( this.toString().equals( that.toString() ) )
                  );
        }
        return result;
	}
	
	/**
	 * Same as {@code this.toString().hashCode()}.
	 * @return	{@code this.toString().hashCode()}.
	 */
	@Override public int hashCode() {
		return this.toString().hashCode();
	}
	
	/**
	 * Return the length of the UTF-8 encoded byte array representing this
	 * object. Note that if this object was constructed with the constructor
	 * {@code PlainText(String str)}, then this length might not necessarily
	 * agree with {@code str.length()}.
	 * 
	 * @return	The length of the UTF-8 encoded byte array representing this
	 * 			object.
	 */
	public int length() {
		return rawBytes.length;
	}
	
	// DISCUSS: Should we set 'rawBytes' to null??? Won't make it eligible for
	//			GC unless this PlainText object is set to null which can't do
	//			from here. If we set it to null, most methods will cause
	//			NullPointerException to be thrown. Also will have to change a
	//			lot of JUnit tests.
	/**
	 * First overwrite the bytes of plaintext with the character '*'.
	 */
	public void overwrite() {
		CryptoHelper.overwrite( rawBytes );
		// rawBytes = null;					// See above comment re: discussion.
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
        return (other instanceof PlainText);
    }
}
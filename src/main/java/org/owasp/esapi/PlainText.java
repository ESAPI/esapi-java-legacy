package org.owasp.esapi;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import org.owasp.esapi.Logger;
import org.owasp.esapi.util.CryptoHelper;

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
		assert b != null : "Byte array cannot be null.";
		rawBytes = b;
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
		return rawBytes;
	}
	
	/**
	 * Implements {@code Object.equals()} method for {@code PlainText}.
	 * @return True if this object is equal to {@code anObject}; otherwise false.
	 */
	public boolean equals(Object anObject) {

        if ( this == anObject ) return true;
        if ( !(anObject instanceof PlainText) ) return false;
        PlainText pt = (PlainText)anObject;
        return ( this.toString().equals( pt.toString() ) );
	}
	
	/**
	 * Same as {@code this.toString().hashCode()}.
	 * @return	{@code this.toString().hashCode()}.
	 */
	public int hashCode() {
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
}
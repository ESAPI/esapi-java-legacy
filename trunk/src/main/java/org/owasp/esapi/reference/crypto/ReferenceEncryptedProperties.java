/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.reference.crypto;

import bsh.This;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Set;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncryptedProperties;
import org.owasp.esapi.Logger;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.errors.EncryptionRuntimeException;

/**
 * Reference implementation of the {@code EncryptedProperties} interface. This
 * implementation wraps a normal properties file, and creates surrogates for the
 * {@code getProperty} and {@code setProperty} methods that perform encryption
 * and decryption based on {@code Encryptor}.
 * <p>
 * This implementation differs from {@code DefaultEncryptedProperties} in that
 * it actually extends from java.util.Properties for applications that need an
 * instance of that class. In order to do so, the {@code getProperty} and
 * {@code setProperty} methods were modified to throw {@code EncryptionRuntimeException}
 * instead of {@code EncryptionException}.
 *
 * @author August Detlefsen (augustd at codemagi dot com)
 *         <a href="http://www.codemagi.com">CodeMagi, Inc.</a>
 * @since October 8, 2010
 * @see org.owasp.esapi.EncryptedProperties
 */
public class ReferenceEncryptedProperties extends java.util.Properties implements org.owasp.esapi.EncryptedProperties {

	/** The logger. */
	private final Logger logger = ESAPI.getLogger(this.getClass());

	private static final String[] GET_ERROR_MESSAGES = new String[]{
		": failed decoding from base64",
		": failed to deserialize properly",
		": failed to decrypt properly"
	};

	private static final String[] SET_ERROR_MESSAGES = new String[]{
		": failed to encrypt properly",
		": failed to serialize correctly",
		": failed to base64-encode properly",
		": failed to set base64-encoded value as property. Illegal key name?"
	};

	/**
	 * Instantiates a new encrypted properties.
	 */
	public ReferenceEncryptedProperties() {
		super();
	}

	public ReferenceEncryptedProperties(Properties defaults) {
		super();

		for (Object oKey : defaults.keySet()) {
			String key		= (oKey instanceof String) ? (String)oKey : oKey.toString();
			String value	= defaults.getProperty(key);

			this.setProperty(key, value);
		}
	}

	/**
	 * {@inheritDoc}
	 *
	 * @throws This method will throw an {@code EncryptionRuntimeException} if decryption fails.
	 */
	@Override
	public synchronized String getProperty(String key) throws EncryptionRuntimeException {
	    int progressMark = 0;
	    try {
	        String encryptedValue = super.getProperty(key);

	        if(encryptedValue==null)
	            return null;

	        progressMark = 0;
	        byte[] serializedCiphertext   = ESAPI.encoder().decodeFromBase64(encryptedValue);
	        progressMark++;
	        CipherText restoredCipherText = CipherText.fromPortableSerializedBytes(serializedCiphertext);
	        progressMark++;
	        PlainText plaintext           = ESAPI.encryptor().decrypt(restoredCipherText);

	        return plaintext.toString();
		} catch (Exception e) {
			throw new EncryptionRuntimeException("Property retrieval failure",
					                             "Couldn't retrieve encrypted property for property " + key +
												 GET_ERROR_MESSAGES[progressMark], e);
	    }
	}

	/**
	 * {@inheritDoc}
	 *
	 * @throws This method will throw an {@code EncryptionRuntimeException} if decryption fails.
	 */
	@Override
	public String getProperty(String key, String defaultValue) throws EncryptionRuntimeException {
		String value = getProperty(key);

		if (value == null) return defaultValue;

		return value;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @throws This method will throw an {@code EncryptionRuntimeException} if encryption fails.
	 */
	@Override
	public synchronized String setProperty(String key, String value) throws EncryptionRuntimeException {
	    int progressMark = 0;
	    try {
	        if ( key == null ) {
	            throw new NullPointerException("Property name may not be null.");
	        }
	        if ( value == null ) {
	            throw new NullPointerException("Property value may not be null.");
	        }
	        // NOTE: Not backward compatible w/ ESAPI 1.4.
	        PlainText pt = new PlainText(value);
	        CipherText ct = ESAPI.encryptor().encrypt(pt);
	        progressMark++;
	        byte[] serializedCiphertext = ct.asPortableSerializedByteArray();
	        progressMark++;
	        String b64str = ESAPI.encoder().encodeForBase64(serializedCiphertext, false);
	        progressMark++;
	        return (String)super.put(key, b64str);
	    } catch (Exception e) {
	        throw new EncryptionRuntimeException("Property setting failure",
	                                      "Couldn't set encrypted property " + key +
	                                      SET_ERROR_MESSAGES[progressMark], e);
	    }
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void load(InputStream in) throws IOException {
		super.load(in);
		logger.trace(Logger.SECURITY_SUCCESS, "Encrypted properties loaded successfully");
	}

	/**
	 * {@inheritDoc}
	 *
	 * For JDK 1.5 compatibility, this method has been overridden convert the Reader
	 * into an InputStream and call the superclass constructor. 
	 */
	@Override
	public void load(Reader in) throws IOException {

		if (in == null) return;

		//read from the reader into a StringBuffer
		char[] cbuf				= new char[65536];
		BufferedReader buff		= new BufferedReader(in);
		StringBuilder contents	= new StringBuilder();

		int read_this_time = 0;
		while (read_this_time != -1) {
			read_this_time = buff.read(cbuf, 0, 65536);
			if (read_this_time > 0) contents.append(cbuf, 0, read_this_time);
		}

		//create a new InputStream from the StringBuffer
		InputStream is = new ByteArrayInputStream(contents.toString().getBytes());

		super.load(is);
		logger.trace(Logger.SECURITY_SUCCESS, "Encrypted properties loaded successfully");
	}

	/**
	 * This method has been overridden to throw an {@code UnsupportedOperationException}
	 */
	@Override
	public void list(PrintStream out) {
		throw new UnsupportedOperationException("This method has been removed for security.");
	}

	/**
	 * This method has been overridden to throw an {@code UnsupportedOperationException}
	 */
	@Override
	public void list(PrintWriter out) {
		throw new UnsupportedOperationException("This method has been removed for security.");
	}

	/**
	 * This method has been overridden to throw an {@code UnsupportedOperationException}
	 */
	@Override
	public Collection values() {
		throw new UnsupportedOperationException("This method has been removed for security.");
	}

	/**
	 * This method has been overridden to throw an {@code UnsupportedOperationException}
	 */
	@Override
	public Set entrySet() {
		throw new UnsupportedOperationException("This method has been removed for security.");
	}

	/**
	 * This method has been overridden to throw an {@code UnsupportedOperationException}
	 */
	@Override
	public Enumeration elements() {
		throw new UnsupportedOperationException("This method has been removed for security.");
	}

	/**
	 * This method has been overridden to only accept Strings for key and value, and to encrypt
	 * those Strings before storing them. Outside classes should always use {@code setProperty}
	 * to add values to the Properties map. If an outside class does erroneously call this method 
	 * with non-String parameters an {@code IllegalArgumentException} will be thrown.
	 *
	 * @param key	A String key to add
	 * @param value A String value to add
	 * @return		The old value associated with the specified key, or {@code null}
     *				if the key did not exist.
	 */
	@Override
	public synchronized Object put(Object key, Object value) {
		//if java.util.Properties is calling this method, just forward to the implementation in
		//the superclass (java.util.Hashtable)
		Throwable t = new Throwable();
		for (StackTraceElement trace : t.getStackTrace()) {
			if ("java.util.Properties".equals(trace.getClassName()) ) return super.put(key, value);
		}

		//otherwise, if both arguments are Strings, encrypt and store them
		if (key instanceof String && value instanceof String) return setProperty((String)key, (String)value);

		//other Object types are not allowed
		throw new IllegalArgumentException("This method has been overridden to only accept Strings for key and value.");
	}

	/**
	 * This method has been overridden to not print out the keys and values stored in this properties file.
	 *
	 * @return The minimal String representation of this class, as per java.lang.Object.
	 */
	@Override
	public String toString() {
		return getClass().getName() + "@" + Integer.toHexString(hashCode());
	}

}

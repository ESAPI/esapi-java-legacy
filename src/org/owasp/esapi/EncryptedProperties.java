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
package org.owasp.esapi;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Set;

import org.owasp.esapi.errors.EncryptionException;


/**
 * The EncryptedProperties interface represents a properties file where all the data is
 * encrypted before it is added, and decrypted when it retrieved. This interface can be
 * implemented in a number of ways, the simplest being extending Properties and overloading
 * the getProperty and setProperty methods.
 * <P>
 * <img src="doc-files/EncryptedProperties.jpg" height="600">
 * <P>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface EncryptedProperties {

	/**
	 * Gets the property value from the encrypted store, decrypts it, and returns the plaintext value to the caller.
	 * 
	 * @param key
	 *            the key
	 * 
	 * @return the decrypted property value
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	String getProperty(String key) throws EncryptionException;

	/**
	 * Encrypts the plaintext property value and stores the ciphertext value in the encrypted store.
	 * 
	 * @param key
	 *            the key
	 * @param value
	 *            the value
	 * 
	 * @return the encrypted property value
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	String setProperty(String key, String value) throws EncryptionException;

	
	/**
	 * Key set.
	 * 
	 * @return the set
	 */
	public Set keySet();
	
	
	/**
	 * Load.
	 * 
	 * @param in
	 *            the in
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void load(InputStream in) throws IOException;
	

	/**
	 * Store.
	 * 
	 * @param out
	 *            the out
	 * @param comments
	 *            the comments
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void store(OutputStream out, String comments) throws IOException;	
	
	
}

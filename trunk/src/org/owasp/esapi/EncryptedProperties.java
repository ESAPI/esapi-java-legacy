/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;


/**
 * The IEncryptedProperties interface is a properties file where all the data is
 * encrypted before it is added, and decrypted when it retrieved.
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
	 * @return the property
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
	 * @return the object
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	String setProperty(String key, String value) throws EncryptionException;

}

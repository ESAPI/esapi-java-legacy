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
 * The {@code EncryptedProperties} interface represents a properties file
 * where all the data is encrypted before it is added, and decrypted when it
 * retrieved. This interface can be implemented in a number of ways, the
 * simplest being extending {@link java.util.Properties} and overloading
 * the {@code getProperty} and {@code setProperty} methods. In all cases,
 * the master encryption key, as given by the {@code Encryptor.MasterKey}
 * property in <b><code>ESAPI.properties</code></b> file.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface EncryptedProperties {

	/**
	 * Gets the property value from the encrypted store, decrypts it, and
	 * returns the plaintext value to the caller.
	 * 
	 * @param key
	 *      the name of the property to get 
	 * 
	 * @return 
	 * 	The decrypted property value. null if the key is not set.
	 * 
	 * @throws EncryptionException
	 *      if the property could not be decrypted
	 */
	String getProperty(String key) throws EncryptionException;

	/**
	 * Encrypts the plaintext property value and stores the ciphertext value
	 * in the encrypted store.
	 * 
	 * @param key
	 *      the name of the property to set
	 * @param value
	 * 		the value of the property to set
	 * 
	 * @return 
	 * 		the previously encrypted property value for the specified key, or
	 *      {@code null} if it did not have one.
	 * 
	 * @throws EncryptionException
	 *      if the property could not be encrypted
	 */
	String setProperty(String key, String value) throws EncryptionException;
	
	/**
	 * Returns a {@code Set} view of properties. The {@code Set} is backed by a
	 * {@code java.util.Hashtable}, so changes to the {@code Hashtable} are
	 * reflected in the {@code Set}, and vice-versa. The {@code Set} supports element 
	 * removal (which removes the corresponding entry from the {@code Hashtable),
	 * but not element addition.
	 * 
	 * @return 
	 * 		a set view of the properties contained in this map.
	 */
	public Set<?> keySet();
		
	/**
	 * Reads a property list (key and element pairs) from the input stream.
	 * 
	 * @param in
	 * 		the input stream that contains the properties file
	 * 
	 * @throws IOException
	 *      Signals that an I/O exception has occurred.
	 */
	public void load(InputStream in) throws IOException;
	
	/**
	 * Writes this property list (key and element pairs) in this Properties table to 
	 * the output stream in a format suitable for loading into a Properties table using the load method. 
	 * 
	 * @param out
	 * 		the output stream that contains the properties file
	 * @param comments
	 *            a description of the property list (ex. "Encrypted Properties File").
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void store(OutputStream out, String comments) throws IOException;	
	
	
}

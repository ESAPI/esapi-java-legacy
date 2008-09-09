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
package org.owasp.esapi.reference;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.EncryptionException;

/**
 * Reference implementation of the EncryptedProperties interface. This
 * implementation wraps a normal properties file, and creates surrogates for the
 * getProperty and setProperty methods that perform encryption and decryption based on the Encryptor.
 * A very simple main program is provided that can be used to create an
 * encrypted properties file. A better approach would be to allow unencrypted
 * properties in the file and to encrypt them the first time the file is
 * accessed.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.EncryptedProperties
 */
public class DefaultEncryptedProperties implements org.owasp.esapi.EncryptedProperties {

	/** The properties. */
	private final Properties properties = new Properties();

	/** The logger. */
	private final Logger logger = ESAPI.getLogger("EncryptedProperties");

	/**
	 * Instantiates a new encrypted properties.
	 */
	public DefaultEncryptedProperties() {
		// hidden
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptedProperties#getProperty(java.lang.String)
	 */
	public synchronized String getProperty(String key) throws EncryptionException {
		try {
			return ESAPI.encryptor().decrypt(properties.getProperty(key));
		} catch (Exception e) {
			throw new EncryptionException("Property retrieval failure", "Couldn't decrypt property", e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptedProperties#setProperty(java.lang.String,
	 *      java.lang.String)
	 */
	public synchronized String setProperty(String key, String value) throws EncryptionException {
		try {
			return (String)properties.setProperty(key, ESAPI.encryptor().encrypt(value));
		} catch (Exception e) {
			throw new EncryptionException("Property setting failure", "Couldn't encrypt property", e);
		}
	}

	/**
	 * Key set.
	 * 
	 * @return the set
	 */
	public Set keySet() {
		return properties.keySet();
	}

	/**
	 * Load.
	 * 
	 * @param in
	 *            the in
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public void load(InputStream in) throws IOException {
		properties.load(in);
		logger.trace(Logger.SECURITY, "Encrypted properties loaded successfully");
	}

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
	public void store(OutputStream out, String comments) throws IOException {
		properties.store(out, comments);
	}

	/**
	 * The main method.
	 * 
	 * @param args
	 *            the arguments
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public static void main(String[] args) throws Exception {
		File f = new File(args[0]);
		ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY, "Loading encrypted properties from " + f.getAbsolutePath() );
		if ( !f.exists() ) throw new IOException( "Properties file not found: " + f.getAbsolutePath() );
		ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY, "Encrypted properties found in " + f.getAbsolutePath() );
		DefaultEncryptedProperties ep = new DefaultEncryptedProperties();
		FileInputStream in = new FileInputStream(f);
		ep.load(in);

		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String key = null;
		do {
			System.out.print("Enter key: ");
			key = br.readLine();
			System.out.print("Enter value: ");
			String value = br.readLine();
			if (key != null && key.length() > 0 && value != null && value.length() > 0) {
				ep.setProperty(key, value);
			}
		} while (key != null && key.length() > 0);

		FileOutputStream out = new FileOutputStream(f);
		ep.store(out, "Encrypted Properties File");
		out.close();

		Iterator i = ep.keySet().iterator();
		while (i.hasNext()) {
			String k = (String) i.next();
			String value = ep.getProperty(k);
			System.out.println("   " + k + "=" + value);
		}
	}

}

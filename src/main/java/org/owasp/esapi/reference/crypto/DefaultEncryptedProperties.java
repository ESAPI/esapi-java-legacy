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
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.errors.EncryptionException;

/**
 * Reference implementation of the {@code EncryptedProperties} interface. This
 * implementation wraps a normal properties file, and creates surrogates for the
 * {@code getProperty} and {@code setProperty} methods that perform encryption
 * and decryption based on {@code Encryptor}.
 * <p>
 * A very simple main program is provided that can be used to create an
 * encrypted properties file. A better approach would be to allow unencrypted
 * properties in the file and to encrypt them the first time the file is
 * accessed.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author kevin.w.wall@gmail.com
 * @since June 1, 2007
 * @see org.owasp.esapi.EncryptedProperties
 * @see org.owasp.esapi.reference.crypto.ReferenceEncryptedProperties
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

	/**
	 * {@inheritDoc}
	 */
	public synchronized String getProperty(String key) throws EncryptionException {
	    String[] errorMsgs = new String[] {
	            ": failed decoding from base64",
	            ": failed to deserialize properly",
	            ": failed to decrypt properly"
	        };

	    int progressMark = 0;
	    try {
	        String encryptedValue = properties.getProperty(key);

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
	        throw new EncryptionException("Property retrieval failure",
	                                      "Couldn't retrieve encrypted property for property " + key +
	                                      errorMsgs[progressMark], e);
	    }
	}

	/**
	 * {@inheritDoc}
	 */
	public synchronized String setProperty(String key, String value) throws EncryptionException {
	    String[] errorMsgs = new String[] {
	            ": failed to encrypt properly",
	            ": failed to serialize correctly",
	            ": failed to base64-encode properly",
	            ": failed to set base64-encoded value as property. Illegal key name?"
	    };

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
	        String encryptedValue = (String)properties.setProperty(key, b64str);
	        progressMark++;
	        return encryptedValue;
	    } catch (Exception e) {
	        throw new EncryptionException("Property setting failure",
	                                      "Couldn't set encrypted property " + key +
	                                      errorMsgs[progressMark], e);
	    }
	}

	/**
	 * {@inheritDoc}
	 */
	public Set<?> keySet() {
		return properties.keySet();
	}

	/**
	 * {@inheritDoc}
	 */
	public void load(InputStream in) throws IOException {
		properties.load(in);
		logger.trace(Logger.SECURITY_SUCCESS, "Encrypted properties loaded successfully");
	}

	/**
	 * {@inheritDoc}
	 */
	public void store(OutputStream out, String comments) throws IOException {
		properties.store(out, comments);
	}

	/**
	 * Loads encrypted properties file based on the location passed in args then prompts the 
	 * user to input key-value pairs.  When the user enters a null or blank key, the values 
	 * are stored to the properties file.
	 * 
	 * @param args
	 *            the location of the properties file to load and write to
	 * 
	 * @throws Exception
	 *             Any exception thrown
	 * @deprecated Use {@code EncryptedPropertiesUtils} instead, which allows creating, reading,
	 *			   and writing encrypted properties.
	 */
	public static void main(String[] args) throws Exception {
		File f = new File(args[0]);
		ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY_SUCCESS, "Loading encrypted properties from " + f.getAbsolutePath() );
		if ( !f.exists() ) throw new IOException( "Properties file not found: " + f.getAbsolutePath() );
		ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY_SUCCESS, "Encrypted properties found in " + f.getAbsolutePath() );
		DefaultEncryptedProperties ep = new DefaultEncryptedProperties();

		FileInputStream in = null;
		FileOutputStream out = null;
		try {
    		in = new FileInputStream(f);
            out = new FileOutputStream(f);

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
    		ep.store(out, "Encrypted Properties File");
		} finally {
		    // FindBugs and PMD both complain about these next lines, that they may
		    // ignore thrown exceptions. Really!!! That's the whole point.
    		try { if ( in != null ) in.close(); } catch( Exception e ) {}
    		try { if ( out != null ) out.close(); } catch( Exception e ) {}
		}
		
		Iterator<?> i = ep.keySet().iterator();
		while (i.hasNext()) {
			String k = (String) i.next();
			String value = ep.getProperty(k);
			System.out.println("   " + k + "=" + value);
		}
	}

}

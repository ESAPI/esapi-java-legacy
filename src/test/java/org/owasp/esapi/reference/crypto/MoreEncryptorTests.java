/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2013 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Kevin W. Wall
 * @created 2013
 * @since ESAPI 2.1.1
 */
package org.owasp.esapi.reference.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.util.Properties;

import javax.crypto.SecretKey;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.CryptoHelper;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.owasp.esapi.reference.crypto.JavaEncryptor;


public class MoreEncryptorTests extends TestCase {

	public MoreEncryptorTests(String testName) {
		super(testName);
	}

    /**
     * Run all the test cases in this suite.
     * This is to allow running from {@code org.owasp.esapi.AllTests}.
     * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(MoreEncryptorTests.class);
        
        return suite;
    }
    
    public void testGetInstance() {
    	try {
    		Encryptor encryptor = JavaEncryptor.getInstance();
    		assertTrue( encryptor != null );
    	} catch( Throwable t ) {
    		t.printStackTrace(System.err);
    		fail("JavaEncryptor.getInstance() threw exception; exception was: " + t);
    	}
    }
    
    public void testGetInstanceWithPropertyOverride() {
    	try {
    		Properties myEnv = new Properties();
    			// Let's try 2-key Triple DES.
    		myEnv.setProperty(DefaultSecurityConfiguration.CIPHER_TRANSFORMATION_IMPLEMENTATION,
    				          "DESede/CBC/PKCS5Padding");
    		myEnv.setProperty(DefaultSecurityConfiguration.KEY_LENGTH, "112");
    		
    		Encryptor tdesEncryptor = JavaEncryptor.getInstance(myEnv);
    		assertTrue( tdesEncryptor != null );
    		
    		CipherText ct = null;
    		
    		try {
    			// Since this is using the Encryptor.MasterKey from the
    			// ESAPI.properties file, which is a 128-bit key for AES, we
    			// expect this to fail with an EncryptionException whose cause
    			// was an InvalidKeyException.
    			ct = tdesEncryptor.encrypt(new PlainText("2-key 3DES"));
    			fail("Excepted EncryptionException with cause of InvalidKeyException");
    		} catch( EncryptionException ee) {
    			assertTrue( ee != null);
    			Throwable cause = ee.getCause();
    			assertTrue( cause != null && cause instanceof InvalidKeyException );
    		}
    		
    		try {
    			// Since this is using the Encryptor.MasterKey from the
    			// ESAPI.properties file, which is a 128-bit key for AES, we
    			// expect this to fail with an EncryptionException whose cause
    			// was an InvalidKeyException.
    			SecretKey tdes112key = CryptoHelper.generateSecretKey("DESede/CBC/PKCS5Padding", 112);
    			ct = tdesEncryptor.encrypt(tdes112key, new PlainText("2-key 3DES"));
    			assertTrue( ct != null );
    			PlainText decryptedPlaintext  = tdesEncryptor.decrypt(tdes112key, ct);
    			assertTrue ( decryptedPlaintext != null );
    			assertTrue( decryptedPlaintext.toString().equals("2-key 3DES") );
    		} catch( EncryptionException ee) {
    			assertTrue( ee != null);
    			Throwable cause = ee.getCause();
    			assertTrue( cause != null && cause instanceof InvalidKeyException );
    		}    		
    		
    	} catch( Throwable t ) {
    		t.printStackTrace(System.err);
    		fail("JavaEncryptor.getInstance() threw exception; exception was: " + t);
    	}
    }
}

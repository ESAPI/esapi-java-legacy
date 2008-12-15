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

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntegrityException;

/**
 * The Class EncryptorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EncryptorTest extends TestCase {
    
    /**
	 * Instantiates a new encryptor test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public EncryptorTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     */
    protected void setUp() throws Exception {
    	// none
    }

    /**
     * {@inheritDoc}
     */
    protected void tearDown() throws Exception {
    	// none
    }

    /**
	 * Suite.
	 * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(EncryptorTest.class);
        
        return suite;
    }

    /**
	 * Test of hash method, of class org.owasp.esapi.Encryptor.
	 */
    public void testHash() throws EncryptionException {
        System.out.println("hash");
        Encryptor instance = ESAPI.encryptor();
        String hash1 = instance.hash("test1", "salt");
        String hash2 = instance.hash("test2", "salt");
        assertFalse(hash1.equals(hash2));
        String hash3 = instance.hash("test", "salt1");
        String hash4 = instance.hash("test", "salt2");
        assertFalse(hash3.equals(hash4));
    }

    /**
	 * Test of encrypt method, of class org.owasp.esapi.Encryptor.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void testEncrypt() throws EncryptionException {
        System.out.println("encrypt");
        Encryptor instance = ESAPI.encryptor();
        String plaintext = "test123";
        String ciphertext = instance.encrypt(plaintext);
    	String result = instance.decrypt(ciphertext);
        assertEquals(plaintext, result);
    }

    /**
	 * Test of decrypt method, of class org.owasp.esapi.Encryptor.
	 */
    public void testDecrypt() {
        System.out.println("decrypt");
        Encryptor instance = ESAPI.encryptor();
        try {
            String plaintext = "test123";
            String ciphertext = instance.encrypt(plaintext);
            assertFalse(plaintext.equals(ciphertext));
        	String result = instance.decrypt(ciphertext);
        	assertEquals(plaintext, result);
        }
        catch( EncryptionException e ) {
        	fail();
        }
    }

    /**
	 * Test of sign method, of class org.owasp.esapi.Encryptor.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void testSign() throws EncryptionException {
        System.out.println("sign");        
        Encryptor instance = ESAPI.encryptor();
        String plaintext = ESAPI.randomizer().getRandomString( 32, DefaultEncoder.CHAR_ALPHANUMERICS );
        String signature = instance.sign(plaintext);
        assertTrue( instance.verifySignature( signature, plaintext ) );
        assertFalse( instance.verifySignature( signature, "ridiculous" ) );
        assertFalse( instance.verifySignature( "ridiculous", plaintext ) );
    }

    /**
	 * Test of verifySignature method, of class org.owasp.esapi.Encryptor.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void testVerifySignature() throws EncryptionException {
        System.out.println("verifySignature");
        Encryptor instance = ESAPI.encryptor();
        String plaintext = ESAPI.randomizer().getRandomString( 32, DefaultEncoder.CHAR_ALPHANUMERICS );
        String signature = instance.sign(plaintext);
        assertTrue( instance.verifySignature( signature, plaintext ) );
    }
    
 
    /**
	 * Test of seal method, of class org.owasp.esapi.Encryptor.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void testSeal() throws IntegrityException {
        System.out.println("seal");
        Encryptor instance = ESAPI.encryptor(); 
        String plaintext = ESAPI.randomizer().getRandomString( 32, DefaultEncoder.CHAR_ALPHANUMERICS );
        String seal = instance.seal( plaintext, instance.getTimeStamp() + 1000*60 );
        instance.verifySeal( seal );
    }

    /**
	 * Test of verifySeal method, of class org.owasp.esapi.Encryptor.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void testVerifySeal() throws EnterpriseSecurityException {
        System.out.println("verifySeal");
        Encryptor instance = ESAPI.encryptor(); 
        String plaintext = ESAPI.randomizer().getRandomString( 32, DefaultEncoder.CHAR_ALPHANUMERICS );
        String seal = instance.seal( plaintext, instance.getRelativeTimeStamp( 1000*60 ) );
        assertTrue( instance.verifySeal( seal ) );
        assertFalse( instance.verifySeal( "ridiculous" ) );
        assertFalse( instance.verifySeal( instance.encrypt("ridiculous") ) );
        assertFalse( instance.verifySeal( instance.encrypt(100 + ":" + "ridiculous" ) ) );
        assertTrue( instance.verifySeal( instance.encrypt(Long.MAX_VALUE + ":" + "ridiculous" ) ) );
    }
    
}

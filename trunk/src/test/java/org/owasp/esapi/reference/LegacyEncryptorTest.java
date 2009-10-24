package org.owasp.esapi.reference;

import static org.junit.Assert.*;
import junit.framework.JUnit4TestAdapter;
import junit.framework.TestCase;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.util.CryptoHelperTest;

public class LegacyEncryptorTest {
	
	static Encryptor savedEncryptor = null;
	Encryptor encryptor = null;

	// Save the current encryptor, set up so we get warnings every 3 encryptions
	// (instead of the default every 25) and then change to the legacy encryptor.
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		savedEncryptor = ESAPI.encryptor();
		System.setProperty("ESAPI.Encryptor.legacy.warnEveryNthUse", "3");
		ESAPI.setEncryptor( new LegacyJavaEncryptor() );
	}

	// Restore the original encryptor.
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		ESAPI.setEncryptor(savedEncryptor);
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}
	
    /**
	 * Test of old, deprecated encrypt method from ESAPI 1.4, now in
	 * LegacyJavaEncryptor.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	@Test
    public void testEncrypt() throws EncryptionException {
        System.out.println("Legacy encrypt");
        Encryptor instance = ESAPI.encryptor();
        String plaintext = "test123";
        String ciphertext = instance.encrypt(plaintext);
    	String result = instance.decrypt(ciphertext);
        assertEquals(plaintext, result);
    }

    /**
	 * Test of old, deprecated decrypt method from ESAPI 1.4, now in
	 * LegacyJavaEncryptor.
	 */
	@Test
    public void testDecrypt() {
        System.out.println("Legacy decrypt");
        Encryptor instance = ESAPI.encryptor();
        try {
            String plaintext = "test123";
            String ciphertext = instance.encrypt(plaintext);
            assertFalse(plaintext.equals(ciphertext));
        	String result = instance.decrypt(ciphertext);
        	assertEquals(plaintext, result);
        }
        catch( EncryptionException e ) {
        	fail("Failed; caught unexpected exception: " + e.getMessage());
        }
    }

	/**
	 * Repeat 10 times and see if warning comes out every 3 times. (Not sure
	 * how to _easily_ automate this test, so for now, will confirm via
	 * _manual_ observation.)
	 */
	@Test
	public void testRepeat10Times() {
		for ( int i = 0; i < 10; i++ ) {
			try {
				testEncrypt();
			} catch (EncryptionException e) {
				fail("Failed; caught unexpected exception: " + e.getMessage());
			}
		}
	}
	
	/**
	 * Run all the test cases in this suite.
	 * This is to allow running from {@code org.owasp.esapi.AllTests} which
	 * uses a JUnit 3 test runner.
	 */
	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(LegacyEncryptorTest.class);
	}
}

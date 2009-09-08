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

import java.io.UnsupportedEncodingException;

import javax.crypto.SecretKey;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.CipherText;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.util.CryptoHelper;

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
     * @throws Exception
     */
    protected void setUp() throws Exception {
    	// none
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void tearDown() throws Exception {
    	// none
    }

    /**
     * Run all the test cases in this suite.
     * This is to allow running from {@code org.owasp.esapi.AllTests}.
     * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(EncryptorTest.class);
        
        return suite;
    }

    /**
	 * Test of hash method, of class org.owasp.esapi.Encryptor.
     *
     * @throws EncryptionException
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
	 * Test of old, deprecated encrypt method, of class org.owasp.esapi.Encryptor.
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
	 * Test of old, deprecated decrypt method, of class org.owasp.esapi.Encryptor.
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
     * Test of new encrypt / decrypt methods added in ESAPI 2.0.
     */
    public void testNewEncryptDecrypt() {
    	try {
			runNewEncryptDecryptTestCase("AES/CBC/PKCS5Padding", 128, "Encrypt the world!".getBytes("UTF-8"));
			runNewEncryptDecryptTestCase("DESede/CBC/PKCS5Padding", 112, "1234567890".getBytes("UTF-8"));
			runNewEncryptDecryptTestCase("DESede/CBC/NoPadding", 112, "12345678".getBytes("UTF-8"));
			runNewEncryptDecryptTestCase("AES/ECB/NoPadding", 256, "test1234test1234".getBytes("UTF-8"));
			runNewEncryptDecryptTestCase("DES/ECB/NoPadding", 56, "test1234".getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			fail("OK, who stole UTF-8 encoding from the Java rt.jar ???");
		}
    	
    }
    
    private void runNewEncryptDecryptTestCase(String cipherXform, int keySize, byte[] plaintextBytes) {
    	System.out.println("New encrypt / decrypt: " + cipherXform);
    	// Let's try it with a 2 key version of 3DES. If we were to use the 3 key version
    	// if would force all the ESAPI developers to download the unlimited export JCE
    	// jurisdiction policy files.
    	try { 
			SecretKey skey = CryptoHelper.generateSecretKey(cipherXform, keySize);	
			assertTrue( skey.getAlgorithm().equals(cipherXform.split("/")[0]) );
			String cipherAlg = cipherXform.split("/")[0];
			
			// NOTE: Key size that encrypt() method is using is 192 bits!!!
    		//        which is 3 times 64 bits, but DES key size is only 56 bits.
    		// See 'DISCUSS' note, JavaEncryptor, near line 288. It's a "feature"!!!
			if ( cipherAlg.equals( "DESede" ) ) {
				keySize = 192;
			} else if ( cipherAlg.equals( "DES" ) ) {
				keySize = 64;
			} // Else... use specified keySize.
			assertTrue( keySize / 8 == skey.getEncoded().length );
System.out.println("testNewEncryptDecrypt(): Skey length (bits) = " + 8 * skey.getEncoded().length);

			// Change the cipher transform from whatever it is to specified cipherXform.
	    	String oldCipherXform = ESAPI.securityConfiguration().setCipherTransformation(cipherXform);
System.out.println("Cipher xform changed from " + oldCipherXform + " to \"" + cipherXform + "\"");
	    	Encryptor instance = ESAPI.encryptor();
	    	String origPlaintext = new String(plaintextBytes, "UTF-8");
	    	byte[] ptBytes = origPlaintext.getBytes("UTF-8");
	    	CipherText ciphertext = instance.encrypt(skey, ptBytes, true);	// New encrypt() method.
System.out.println("Encrypt(): Returned ciphertext -- " + ciphertext);
	    	assertTrue( ciphertext != null );
	    	assertTrue( checkByteArray(ptBytes, (byte)'*') );
	    	byte[] resultBytes = instance.decrypt(skey, ciphertext);		// New decrypt() method.
	    	String plaintextString = new String(resultBytes, "UTF-8");
	    	assertTrue( plaintextString.equals(origPlaintext) );
	    	String previousCipherXform = ESAPI.securityConfiguration().setCipherTransformation(null);
	    	assertTrue( previousCipherXform.equals( cipherXform ) );
	    	String defaultCipherXform = ESAPI.securityConfiguration().getCipherTransformation();
	    	assertTrue( defaultCipherXform.equals( oldCipherXform ) );
		} catch (Exception e) {
			// OK if not counted toward code coverage.
			System.err.println("testNewEncryptDecrypt(): Caught unexpected exception: " + e.getClass().getName());
			e.printStackTrace(System.err);
			fail("Caught unexpected exception; msg was: " + e.getMessage());
		}
    }
    
    // TODO - Because none of the encryption / decryption tests persists
    //		  encrypted data across runs, that means everything is run
    //		  under same JVM at same time thus always with the same
    //		  _native_ byte encoding.
    //
    //		  Need test(s) such that data is persisted across JVM runs
    //		  so we can test a run on (say) a Windows Intel box can decrypt
    //		  encrypted data produced by the reference Encryptor on
    //		  (say) a Solaris SPARC box. I.e., test that the change to
    //		  JavaEncryptor to use UTF-8 encoding throughout works as
    //		  desired.
    //
    //		  Files saved across tests need to be added to SVN (under
    //		  resources or where) and they should be named so we know
    //		  where and how they were created. E.g., WinOS-AES-ECB.dat,
    //		  Sparc-Solaris-AEC-CBC-PKCS5Padding.dat, etc.
    //
    //				-kevin wall
    

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
     * @throws IntegrityException
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
     * @throws EnterpriseSecurityException
	 */
    public void testVerifySeal() throws EnterpriseSecurityException {
        System.out.println("verifySeal");
        Encryptor instance = ESAPI.encryptor(); 
        String plaintext = "ridiculous";
        String seal = instance.seal( plaintext, instance.getRelativeTimeStamp( 1000*60 ) );
        try {
        	assertTrue( instance.verifySeal( seal ) );
        } catch ( Exception e ) {
        	fail();
        }
        try {
        	assertFalse( instance.verifySeal( plaintext ) );
        } catch ( Exception e ) {
        	fail();
        }
        try {
        	assertFalse( instance.verifySeal( instance.encrypt( plaintext ) ) );
        } catch ( Exception e ) {
        	fail();
        }
        try {
        	assertFalse( instance.verifySeal( instance.encrypt(100 + ":" + plaintext ) ) );
        } catch ( Exception e ) {
        	fail();
        }
        try {
        	assertFalse( instance.verifySeal( instance.encrypt(Long.MAX_VALUE + ":" + plaintext ) ) );
        } catch ( Exception e ) {
        	fail();
        }
        try {
        	assertFalse( instance.verifySeal( instance.encrypt(Long.MAX_VALUE + ":random:" + plaintext ) ) );
        } catch ( Exception e ) {
        	fail();
        }
        try {
        	assertFalse( instance.verifySeal( instance.encrypt(Long.MAX_VALUE + ":random:" + plaintext+ ":badsig"  ) ) );
        } catch ( Exception e ) {
        	fail();
        }
        try {
        	assertTrue( instance.verifySeal( instance.encrypt(Long.MAX_VALUE + ":random:" + plaintext + ":"+ instance.sign( Long.MAX_VALUE + ":random:" + plaintext ) ) ) );
        } catch ( Exception e ) {
        	fail();
        }
    }

    
    /**
     * Test of main method, of class org.owasp.esapi.Encryptor.
     * @throws Exception
     */
    public void testMain() throws Exception {
        System.out.println("Encryptor Main");
        String[] args = {};
        JavaEncryptor.main( args );        
        String[] args1 = {"-print"};
        JavaEncryptor.main( args1 );        
    }
    
	private boolean checkByteArray(byte[] ba, byte b) {
		for(int i = 0; i < ba.length; i++ ) {
			if ( ba[i] != b ) {
				return false;
			}
		}
		return true;
	}
    
}

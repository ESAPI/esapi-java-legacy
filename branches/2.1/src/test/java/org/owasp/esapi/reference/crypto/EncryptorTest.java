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

import java.io.UnsupportedEncodingException;

import javax.crypto.SecretKey;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.CryptoHelper;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.reference.DefaultEncoder;
import org.owasp.esapi.reference.crypto.JavaEncryptor;

/**
 * The Class EncryptorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @author kevin.w.wall@gmail.com
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
        // This is only mechanism to change this for now. Will do this with
        // a soon to be CryptoControls class in next release.
        ESAPI.securityConfiguration().setCipherTransformation("AES/CBC/PKCS5Padding");
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
        System.out.println("testHash()");
        Encryptor instance = ESAPI.encryptor();
        String hash1 = instance.hash("test1", "salt");
        String hash2 = instance.hash("test2", "salt");
        assertFalse(hash1.equals(hash2));
        String hash3 = instance.hash("test", "salt1");
        String hash4 = instance.hash("test", "salt2");
        assertFalse(hash3.equals(hash4));
    }

    /**
	 * Test of deprecated encrypt method for Strings.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void testEncrypt() throws EncryptionException {
        System.out.println("testEncrypt()");
        Encryptor instance = ESAPI.encryptor();
        String plaintext = "test123456";	// Not multiple of block cipher size
        String ciphertext = instance.encrypt(plaintext);
    	String result = instance.decrypt(ciphertext);
        assertEquals(plaintext, result);
    }

    /**
	 * Test of deprecated decrypt method for Strings.
	 */
    public void testDecrypt() {
        System.out.println("testDecrypt()");
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
     * Test of encrypt methods for empty String.
     * 
     * @throws EncryptionException
     *             the encryption exception
     */
    @SuppressWarnings("deprecation")
    public void testEncryptEmptyStrings() {
        System.out.println("testEncryptEmptyStrings()");
        Encryptor instance = ESAPI.encryptor();
        String plaintext = "";
        try {
            // System.out.println("Deprecated encryption methods");
            String ciphertext = instance.encrypt(plaintext);
            String result = instance.decrypt(ciphertext);
            assertTrue( result.equals("") );
            
            // System.out.println("New encryption methods");
            CipherText ct = instance.encrypt(new PlainText(plaintext));
            PlainText pt = instance.decrypt(ct);
            assertTrue( pt.toString().equals("") );
        } catch(Exception e) {
            fail("testEncryptEmptyStrings() -- Caught exception: " + e);
        }
    }
    
    /**
     * Test encryption / decryption methods for null.
     */
    @SuppressWarnings("deprecation")
    public void testEncryptNull() {
        System.out.println("testEncryptNull()");
        Encryptor instance = ESAPI.encryptor();
        String plaintext = "";
        try {
            String nullStr = null;
            instance.encrypt(nullStr);
            fail("testEncryptNull(): Did not result in expected exception!");
        } catch(Throwable t) {
            // It should be one of these, depending on whether or not assertions are enabled.
            assertTrue( t instanceof NullPointerException || t instanceof AssertionError);
        }
    }

    /**
     * Test of new encrypt / decrypt methods added in ESAPI 2.0.
     */
    public void testNewEncryptDecrypt() {
    	System.out.println("testNewEncryptDecrypt()");
    	try {

    	    // Let's try it with a 2-key version of 3DES. This should work for all
    	    // installations, whereas the 3-key Triple DES will only work for those
    	    // who have the Unlimited Strength Jurisdiction Policy files installed.
			runNewEncryptDecryptTestCase("DESede/CBC/PKCS5Padding", 112, "1234567890".getBytes("UTF-8"));
			runNewEncryptDecryptTestCase("DESede/CBC/NoPadding", 112, "12345678".getBytes("UTF-8"));
			
			runNewEncryptDecryptTestCase("DES/ECB/NoPadding", 56, "test1234".getBytes("UTF-8"));
			
	        runNewEncryptDecryptTestCase("AES/CBC/PKCS5Padding", 128, "Encrypt the world!".getBytes("UTF-8"));
	        
	        // These tests are only valid (and run) if one has the JCE Unlimited
	        // Strength Jurisdiction Policy files installed for this Java VM.
	            // 256-bit AES
            runNewEncryptDecryptTestCase("AES/ECB/NoPadding", 256, "test1234test1234".getBytes("UTF-8"));
                // 168-bit (aka, 3-key) Triple DES
            runNewEncryptDecryptTestCase("DESede/CBC/PKCS5Padding", 168, "Groucho's secret word".getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			fail("OK, who stole UTF-8 encoding from the Java rt.jar ???");
		}
    	
    }
    
    /**
     * Helper method to test new encryption / decryption.
     * @param cipherXform	Cipher transformation
     * @param keySize	Size of key, in bits.
     * @param plaintextBytes Byte array of plaintext.
     * @return The base64-encoded IV+ciphertext (or just ciphertext if no IV) or
     *         null if {@code keysize} is greater than 128 bits and unlimited
     *         strength crypto is not available for this Java VM.
     */
    private String runNewEncryptDecryptTestCase(String cipherXform, int keySize, byte[] plaintextBytes) {
    	System.out.println("New encrypt / decrypt: " + cipherXform);
    	
    	if ( keySize > 128 && !CryptoPolicy.isUnlimitedStrengthCryptoAvailable() ) {
    	    System.out.println("Skipping test for cipher transformation " +
    	                       cipherXform + " with key size of " + keySize +
    	                       " bits because this requires JCE Unlimited Strength" +
    	                       " Jurisdiction Policy files to be installed and they" +
    	                       " are not.");
    	    return null;
    	}

    	try {
    		// Generate an appropriate random secret key
			SecretKey skey = CryptoHelper.generateSecretKey(cipherXform, keySize);	
			assertTrue( skey.getAlgorithm().equals(cipherXform.split("/")[0]) );
			String cipherAlg = cipherXform.split("/")[0];
			
			// Adjust key size for DES and DESede specific oddities.
			// NOTE: Key size that encrypt() method is using is 192 bits!!!
    		//        which is 3 times 64 bits, but DES key size is only 56 bits.
    		// See 'IMPORTANT NOTE', in JavaEncryptor, near line 376. It's a "feature"!!!
			if ( cipherAlg.equals( "DESede" ) ) {
				keySize = 192;
			} else if ( cipherAlg.equals( "DES" ) ) {
				keySize = 64;
			} // Else... use specified keySize.
			assertTrue( (keySize / 8) == skey.getEncoded().length );
System.out.println("testNewEncryptDecrypt(): Skey length (bits) = " + 8 * skey.getEncoded().length);

			// Change to a possibly different cipher. This is kludgey at best. Am thinking about an
			// alternate way to do this using a new 'CryptoControls' class. Maybe not until release 2.1.
			// Change the cipher transform from whatever it currently is to the specified cipherXform.
	    	String oldCipherXform = ESAPI.securityConfiguration().setCipherTransformation(cipherXform);
	    	if ( ! cipherXform.equals(oldCipherXform) ) {
	    		System.out.println("Cipher xform changed from \"" + oldCipherXform + "\" to \"" + cipherXform + "\"");
	    	}
	    	
	    	// Get an Encryptor instance with the specified, possibly new, cipher transformation.
	    	Encryptor instance = ESAPI.encryptor();
	    	PlainText plaintext = new PlainText(plaintextBytes);
	    	PlainText origPlainText = new PlainText( plaintext.toString() ); // Make _copy_ of original for comparison.
	    	
	    	// Do the encryption with the new encrypt() method and get back the CipherText.
	    	CipherText ciphertext = instance.encrypt(skey, plaintext);	// The new encrypt() method.
	    	System.out.println("DEBUG: Encrypt(): CipherText object is -- " + ciphertext);
	    	assertTrue( ciphertext != null );
//	    	System.out.println("DEBUG: After encryption: base64-encoded IV+ciphertext: " + ciphertext.getEncodedIVCipherText());
//	    	System.out.println("\t\tOr... " + ESAPI.encoder().decodeFromBase64(ciphertext.getEncodedIVCipherText()) );
//	    	System.out.println("DEBUG: After encryption: base64-encoded raw ciphertext: " + ciphertext.getBase64EncodedRawCipherText());
//	    	System.out.println("\t\tOr... " + ESAPI.encoder().decodeFromBase64(ciphertext.getBase64EncodedRawCipherText()) );

	    	// If we are supposed to have overwritten the plaintext, check this to see
	    	// if origPlainText was indeed overwritten.
			boolean overwritePlaintext = ESAPI.securityConfiguration().overwritePlainText();
			if ( overwritePlaintext ) {
				assertTrue( isPlaintextOverwritten(plaintext) );
			}
	    	
	    	// Take the resulting ciphertext and decrypt w/ new decryption method.
	    	PlainText decryptedPlaintext  = instance.decrypt(skey, ciphertext);		// The new decrypt() method.
	    	
	    	// Make sure we got back the same thing we started with.
	    	System.out.println("\tOriginal plaintext: " + origPlainText);
	    	System.out.println("\tResult after decryption: " + decryptedPlaintext);
			assertTrue( "Failed to decrypt properly.", origPlainText.toString().equals( decryptedPlaintext.toString() ) );
	    	
	    	// Restore the previous cipher transformation. For now, this is only way to do this.
	    	String previousCipherXform = ESAPI.securityConfiguration().setCipherTransformation(null);
	    	assertTrue( previousCipherXform.equals( cipherXform ) );
	    	String defaultCipherXform = ESAPI.securityConfiguration().getCipherTransformation();
	    	assertTrue( defaultCipherXform.equals( oldCipherXform ) );
	    	
	    	return ciphertext.getEncodedIVCipherText();
		} catch (Exception e) {
			// OK if not counted toward code coverage.
			System.out.println("testNewEncryptDecrypt(): Caught unexpected exception: " + e.getClass().getName());
			e.printStackTrace(System.out);
			fail("Caught unexpected exception; msg was: " + e);
		}
		return null;
    }
    
    private static boolean isPlaintextOverwritten(PlainText plaintext) {
    	// Note: An assumption here that the original plaintext did not consist
    	// entirely of all '*' characters.
    	byte[] ptBytes = plaintext.asBytes();
    	
    	for ( int i = 0; i < ptBytes.length; i++ ) {
    		if ( ptBytes[i] != '*' ) {
    			return false;
    		}
    	}
    	return true;
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
    //		  Sparc-Solaris-AEC-CBC-PKCS5Padding.dat, etc., but they should be
    //		  able to be decrypted from any platform. May wish to place that
    //		  under a separate JUnit test.
    //
    // TODO - Need to test rainy day paths of new encrypt / decrypt so can
    //		  verify that exception handling working OK, etc. Maybe also in
    //		  a separate JUnit test, since everything here seems to be sunny
    //		  day path.
    //
    //				-kevin wall
    

    /**
	 * Test of sign method, of class org.owasp.esapi.Encryptor.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void testSign() throws EncryptionException {
        System.out.println("testSign()");        
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
        System.out.println("testVerifySignature()");
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
        System.out.println("testSeal()");
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
        System.out.println("testVerifySeal()");
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

    public void testEncryptionSerialization() throws EncryptionException {
        String secretMsg = "Secret Message";
        ESAPI.securityConfiguration().setCipherTransformation("AES/CBC/PKCS5Padding");
        CipherText ct = ESAPI.encryptor().encrypt(new PlainText(secretMsg));
        
        byte[] serializedCipherText = ct.asPortableSerializedByteArray();
        
        PlainText plainText = ESAPI.encryptor().decrypt(
                                CipherText.fromPortableSerializedBytes(serializedCipherText) );
        
        assertTrue( secretMsg.equals( plainText.toString() ) );
    }
    
    /**
     * Test of main method, of class org.owasp.esapi.Encryptor.
     * @throws Exception
     */
    public void testMain() throws Exception {
        System.out.println("testMain(): Encryptor Main");
        String[] args = {};
        JavaEncryptor.main( args );        
        String[] args1 = {"-print"};
        // TODO:
        // It probably would be a better if System.out were changed to be
        // a file or a byte stream so that the output could be slurped up
        // and checked against (at least some of) the expected output.
        // Left as an exercise to some future, ambitious ESAPI developer. ;-)
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

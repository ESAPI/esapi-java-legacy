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
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.CryptoHelper;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.reference.crypto.JavaEncryptor;

/**
 * The Class EncryptorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @author kevin.w.wall@gmail.com
 */
public class EncryptorTest extends TestCase {

    public static boolean unlimitedStrengthJurisdictionPolicyInstalled = false;
    static {
        try {
            unlimitedStrengthJurisdictionPolicyInstalled = CryptoPolicy.isUnlimitedStrengthCryptoAvailable();
        } catch(Throwable t) {
            ;   // Intentionally ignore (but really shouldn't happen unless Error thrown) and we don't want to bail in that case anyhow
        } finally {
            System.out.println("EncryptorTest: Strong crypto tests " +
                                ( unlimitedStrengthJurisdictionPolicyInstalled ? "will not" : "will" ) +
                                " be skipped.");
        }
    }
    
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
    @SuppressWarnings("deprecation")
	protected void setUp() throws Exception {
        // This is only mechanism to change this for now. Will do this with
        // a soon to be CryptoControls class or equivalent mechanism in a
    	// future release.
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
	 * Test of new encrypt / decrypt method for Strings whose length is
	 * not a multiple of the cipher block size (16 bytes for AES).
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void testEncryptDecrypt1() throws EncryptionException {
        System.out.println("testEncryptDecrypt2()");
        Encryptor instance = ESAPI.encryptor();
        String plaintext = "test1234test1234tes"; // Not a multiple of block size (16 bytes)
        try {
            CipherText ct = instance.encrypt(new PlainText(plaintext));
            PlainText pt = instance.decrypt(ct);
            assertTrue( pt.toString().equals(plaintext) );
        }
        catch( EncryptionException e ) {
        	fail("testEncryptDecrypt2(): Caught exception: " + e);
        }
    }

    /**
	 * Test of new encrypt / decrypt method for Strings whose length is
	 * same as cipher block size (16 bytes for AES).
	 */
    public void testEncryptDecrypt2() {
        System.out.println("testEncryptDecrypt2()");
        Encryptor instance = ESAPI.encryptor();
        String plaintext = "test1234test1234";
        try {
            CipherText ct = instance.encrypt(new PlainText(plaintext));
            PlainText pt = instance.decrypt(ct);
            assertTrue( pt.toString().equals(plaintext) );
        }
        catch( EncryptionException e ) {
        	fail("testEncryptDecrypt2(): Caught exception: " + e);
        }
    }

    /**
     * Test of encrypt methods for empty String.
     */
    public void testEncryptEmptyStrings() {
        System.out.println("testEncryptEmptyStrings()");
        Encryptor instance = ESAPI.encryptor();
        String plaintext = "";
        try {
            // System.out.println("New encryption methods");
            CipherText ct = instance.encrypt(new PlainText(plaintext));
            PlainText pt = instance.decrypt(ct);
            assertTrue( pt.toString().equals("") );
        } catch(Exception e) {
            fail("testEncryptEmptyStrings() -- Caught exception: " + e);
        }
    }
    
    /**
     * Test encryption method for null.
     */
    public void testEncryptNull() {
        System.out.println("testEncryptNull()");
        Encryptor instance = ESAPI.encryptor();
        try {
			CipherText ct = instance.encrypt( null );  // Should throw NPE or AssertionError
            fail("New encrypt(PlainText) method did not throw. Result was: " + ct.toString());
        } catch(Throwable t) {
            // It should be one of these, depending on whether or not assertions are enabled.
            assertTrue( t instanceof IllegalArgumentException || t instanceof AssertionError);
        }
    }

    /**
     * Test decryption method for null.
     */
    public void testDecryptNull() {
        System.out.println("testDecryptNull()");
        Encryptor instance = ESAPI.encryptor();
        try {
			PlainText pt = instance.decrypt( null );  // Should throw IllegalArgumentException or AssertionError
            fail("New decrypt(PlainText) method did not throw. Result was: " + pt.toString());
        } catch(Throwable t) {
            // It should be one of these, depending on whether or not assertions are enabled.
            assertTrue( t instanceof IllegalArgumentException || t instanceof AssertionError);
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
    
    /** Special encryption case!!! Test encryption with DES, which has a key less than the
     * min key size specified as Encryptor.EncryptionKeyLength in the file
     * src/test/resources/esapi/ESAPI.properties.
     */
    public void testWithTooShortKey() {
        boolean desTestFailed = false;
        try {
            // We expect this one to throw because we have:
            //      Encryptor.EncryptionKeyLength=112
            // set in src/test/resources/esapi/ESAPI.properties. It should throw
            // an EncryptionException (with a cause of ConfigurationException).

            // Generate an appropriate random secret key
            SecretKey skey = CryptoHelper.generateSecretKey("DES/ECB/NoPadding", 56);

            // Change to different cipher. (Default is AES.) This is kludgey at best. Am thinking about an
            // alternate way to do this using a new 'CryptoControls' class. Maybe not until release 2.1.
            // Change the cipher transform from whatever it currently is to the specified cipherXform.
            @SuppressWarnings("deprecation")
            String oldCipherXform = ESAPI.securityConfiguration().setCipherTransformation("DES/ECB/NoPadding");

            // Get an Encryptor instance with the specified, new, cipher transformation.
            Encryptor instance = ESAPI.encryptor();
            PlainText plaintext = new PlainText( "test1234".getBytes("UTF-8") );

            // Do the encryption with the new encrypt() method and get back the CipherText.
            // This should throw because the key is too short.
            CipherText ciphertext = instance.encrypt(skey, plaintext);  // The new encrypt() method. Should throw!

        } catch ( EncryptionException eex ) {
            desTestFailed = true;
        } catch ( Exception ex ) {
            fail("testWithTooShortKey(): Caught unexpected exception; msg was: " + ex);
        }

        assertTrue(
                    "Expected 56-key DES to throw EncryptionException; " +
                        "check Encryptor.EncryptionKeyLength in src/test/resources/esapi/ESAPI.properties file.",
                    desTestFailed);
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
    	// System.err.println("New encrypt / decrypt: " + cipherXform + "; requested key size: " + keySize + " bits.");
    	
    	if ( keySize > 128 && !unlimitedStrengthJurisdictionPolicyInstalled ) {
    	    System.err.println("Skipping test for cipher transformation " +
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

            // System.err.println("Key size of generated encoded key: " + skey.getEncoded().length * 8 + " bits.");
			
			// Adjust key size for DES and DESede specific oddities.
			// NOTE: Key size that encrypt() method is using is 192 bits!!!
    		//        which is 3 times 64 bits, but DES key size is only 56 bits.
    		// See 'IMPORTANT NOTE', in JavaEncryptor, near line 376. It's a "feature"!!!
/////   This section is causing problems. BC for instance sometimes creates a
/////   192 bit key and then subsequently creates a 128-bit key for 2-key
/////   3DES so adjusing this is futile. THis is a holdover when we were
/////   doing an *exact* size comparison in the following assertTrue() though.
/////   Since we are no longer doing that, we don't need to "adjust" the size
/////   so hopefully all will be well with the world.
/////
/////   Delete this comment and the following commented-out code after the
/////   official 2.2.0.0 release.
/////
/*
			if ( cipherAlg.equals( "DESede" ) ) {
                System.err.println("Adjusting requested key size of " + keySize + " bits to 192 bits for DESede");
				keySize = 192;
			} else if ( cipherAlg.equals( "DES" ) ) {
                System.err.println("Adjusting requested key size of " + keySize + " bits to 64 bits for DES");
				keySize = 64;
			} // Else... use specified keySize.
 */

            assertTrue(cipherXform + ": encoded key size of " + skey.getEncoded().length + " shorter than requested key size of: " + (keySize / 8),
            		skey.getEncoded().length >= (keySize / 8) );

			// Change to a possibly different cipher. This is kludgey at best. Am thinking about an
			// alternate way to do this using a new 'CryptoControls' class. Maybe not until release 2.1.
			// Change the cipher transform from whatever it currently is to the specified cipherXform.
	    	@SuppressWarnings("deprecation")
			String oldCipherXform = ESAPI.securityConfiguration().setCipherTransformation(cipherXform);
/*
	    	if ( ! cipherXform.equals(oldCipherXform) ) {
	    		System.err.println("Cipher xform changed from \"" + oldCipherXform + "\" to \"" + cipherXform + "\"");
	    	}
 */
	    	
	    	// Get an Encryptor instance with the specified, possibly new, cipher transformation.
	    	Encryptor instance = ESAPI.encryptor();
	    	PlainText plaintext = new PlainText(plaintextBytes);
	    	PlainText origPlainText = new PlainText( plaintext.toString() ); // Make _copy_ of original for comparison.
	    	
	    	// Do the encryption with the new encrypt() method and get back the CipherText.
	    	CipherText ciphertext = instance.encrypt(skey, plaintext);	// The new encrypt() method.
	    	System.err.println("DEBUG: Encrypt(): CipherText object is -- " + ciphertext);
	    	assertNotNull( ciphertext );
//	    	System.err.println("DEBUG: After encryption: base64-encoded IV+ciphertext: " + ciphertext.getEncodedIVCipherText());
//	    	System.err.println("\t\tOr... " + ESAPI.encoder().decodeFromBase64(ciphertext.getEncodedIVCipherText()) );
//	    	System.err.println("DEBUG: After encryption: base64-encoded raw ciphertext: " + ciphertext.getBase64EncodedRawCipherText());
//	    	System.err.println("\t\tOr... " + ESAPI.encoder().decodeFromBase64(ciphertext.getBase64EncodedRawCipherText()) );

	    	// If we are supposed to have overwritten the plaintext, check this to see
	    	// if origPlainText was indeed overwritten.
	    	@SuppressWarnings("deprecation")
			boolean overwritePlaintext = ESAPI.securityConfiguration().overwritePlainText();
			if ( overwritePlaintext ) {
				assertTrue( isPlaintextOverwritten(plaintext) );
			}
	    	
	    	// Take the resulting ciphertext and decrypt w/ new decryption method.
	    	PlainText decryptedPlaintext  = instance.decrypt(skey, ciphertext);		// The new decrypt() method.
	    	
	    	// Make sure we got back the same thing we started with.
	    	System.out.println("\tOriginal plaintext: " + origPlainText);
	    	System.out.println("\tResult after decryption: " + decryptedPlaintext);
			assertEquals( "Failed to decrypt properly.", origPlainText.toString(), decryptedPlaintext.toString() );
	    	
	    	// Restore the previous cipher transformation. For now, this is only way to do this.
	    	@SuppressWarnings("deprecation")
			String previousCipherXform = ESAPI.securityConfiguration().setCipherTransformation(null);
	    	assertEquals( previousCipherXform,  cipherXform  );
	    	@SuppressWarnings("deprecation")
	    	String defaultCipherXform = ESAPI.securityConfiguration().getCipherTransformation();
	    	assertEquals( defaultCipherXform, oldCipherXform );
	    	
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
    //		  day path. (Note: Some of this no in new test case,
    //		  org.owasp.esapi.crypto.ESAPICryptoMACByPassTest.)
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
        String plaintext = ESAPI.randomizer().getRandomString( 32, EncoderConstants.CHAR_ALPHANUMERICS );
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
        String plaintext = ESAPI.randomizer().getRandomString( 32, EncoderConstants.CHAR_ALPHANUMERICS );
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
        String plaintext = ESAPI.randomizer().getRandomString( 32, EncoderConstants.CHAR_ALPHANUMERICS );
        String seal = instance.seal( plaintext, instance.getTimeStamp() + 1000*60 );
        instance.verifySeal( seal );
        
        int progressMark = 1;
        boolean caughtExpectedEx = false;
        try {
            seal = instance.seal("", instance.getTimeStamp() + 1000*60);
            progressMark++;
            instance.verifySeal(seal);
            progressMark++;
        } catch(Exception e) {
            fail("Failed empty string test: " + e + "; progress mark = " + progressMark);
        }
        try {
            seal = instance.seal(null, instance.getTimeStamp() + 1000*60);
            fail("Did not throw expected IllegalArgumentException");
        } catch(IllegalArgumentException e) {
            caughtExpectedEx = true;
        } catch(Exception e) {
            fail("Failed null string test; did not get expected IllegalArgumentException: " + e);
        }
        assertTrue(caughtExpectedEx);
        
        try {
            seal = instance.seal("test", 0);
            progressMark++;
            // instance.verifySeal(seal);
            progressMark++;
        } catch(Exception e) {
            fail("Fail test with 0 timestamp: " + e + "; progress mark = " + progressMark);
        }
        try {
            seal = instance.seal("test", -1);
            progressMark++;
            // instance.verifySeal(seal);
            progressMark++;
        } catch(Exception e) {
            fail("Fail test with -1 timestamp: " + e + "; progress mark = " + progressMark);
        }
    }

    /**
	 * Test of verifySeal method, of class org.owasp.esapi.Encryptor.
	 * 
     * @throws EnterpriseSecurityException
	 */
    public void testVerifySeal() throws EnterpriseSecurityException {
        final int NSEC = 5;
        System.out.println("testVerifySeal()");
        Encryptor instance = ESAPI.encryptor(); 
        String plaintext = "ridiculous:with:delimiters";    // Should now work w/ : (issue #28)
        String seal = instance.seal( plaintext, instance.getRelativeTimeStamp( 1000 * NSEC ) );
        try {
        	assertNotNull("Encryptor.seal() returned null", seal );
        	assertTrue("Failed to verify seal", instance.verifySeal( seal ) );
        } catch ( Exception e ) {
        	fail();
        }
        int progressMark = 1;
        try {
            // NOTE: I regrouped these all into a single try / catch since they
            //       all test the same thing. Hence if one fails, they all should.
            //       Also changed these tests so they no longer depend on the
            //       deprecated encrypt() methods. IMO, *all these multiple
            //       similar tests are not really required*, as they all are more
            //       or less testing the same thing.
            //                                              -kevin wall
            // ================================================================
            // Try to validate some invalid seals.
            //
            // All these should return false and log a warning with an Exception stack
            // trace caused by an EncryptionException indicating "Invalid seal".
        	assertFalse( instance.verifySeal( plaintext ) );
        	progressMark++;      	
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(plaintext) ).getBase64EncodedRawCipherText() ) );
            progressMark++;            
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(100 + ":" + plaintext) ).getBase64EncodedRawCipherText() ) );
            progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(Long.MAX_VALUE + ":" + plaintext) ).getBase64EncodedRawCipherText() ) );
            progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(Long.MAX_VALUE + ":random:" + plaintext) ).getBase64EncodedRawCipherText() ) );
            progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(Long.MAX_VALUE + ":random:" + plaintext+ ":badsig")  ).getBase64EncodedRawCipherText() ) );
            progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(Long.MAX_VALUE + ":random:" + plaintext + ":"+ instance.sign( Long.MAX_VALUE + ":random:" + plaintext) ) ).getBase64EncodedRawCipherText() ) );
            progressMark++;
        } catch ( Exception e ) {
        	// fail("Failed invalid seal test # " + progressMark + " to verify seal.");
            System.err.println("Failed seal verification at step # " + progressMark);
            System.err.println("Exception was: " + e);
            e.printStackTrace(System.err);
        }
        
        try {
            Thread.sleep(1000 * (NSEC + 1) );
                // Seal now past expiration date.
            assertFalse( instance.verifySeal( seal ) );
        } catch ( Exception e ) {
            fail("Failed expired seal test. Seal should be expired.");
        }
    }
        

    @SuppressWarnings("deprecation")
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
     * Test of main method, of class org.owasp.esapi.Encryptor. Must be done by
     * visual inspection for now. (Needs improvement.)
     * @throws Exception
     */
    public void testMain() throws Exception {
        System.out.println("testMain(): Encryptor Main with '-print' argument.");
        String[] args = {};
        JavaEncryptor.main( args );        
            // TODO:
            // It probably would be a better if System.out were changed to be
            // a file or a byte stream so that the output could be slurped up
            // and checked against (at least some of) the expected output.
            // Left as an exercise to some future, ambitious ESAPI developer. ;-)
        String[] args1 = {"-print"};
        JavaEncryptor.main( args1 );        
    }    
}

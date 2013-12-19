package org.owasp.esapi.crypto;

import static org.junit.Assert.*;

import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.Properties;

import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.owasp.esapi.reference.crypto.JavaEncryptor;

/**
 * Test for class {@code SecurityProviderLoader}. Note that these tests
 * use Bouncy Castle's JCE provider so a version their jar must be added
 * to your class path. If you wish to add it via Maven, you can do so by
 * adding this to your <b><i>pom.xml</i></b>:
 * <pre>
 * <dependency>
 *      <groupId>org.bouncycastle</groupId>
 *      <artifactId>bcprov-jdk15</artifactId>
 *      <version>1.44</version>
 * </dependency>
 * </pre>
 * It has been tested with Bouncy Castle 1.44, but any later version should
 * do as well.
 * @author kevin.w.wall@gmail.com
 */
public class SecurityProviderLoaderTest {

    private static boolean HAS_BOUNCY_CASTLE = false;
    
    @BeforeClass
    public static void setUpBeforeClass() {
        try {
            Class<?> providerClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Provider cryptoProvider = (Provider)providerClass.newInstance();
            assertTrue( cryptoProvider != null );
            HAS_BOUNCY_CASTLE = true;
        } catch(Exception ex) {
            // Note: FindBugs reports a false positive here...
            //    REC_CATCH_EXCEPTION: Exception is caught when Exception is not thrown
            // but exceptions really can be thrown.
            HAS_BOUNCY_CASTLE = false;
        }
    }

    @Test
    public final void testInsertProviderAt() {
        if ( ! HAS_BOUNCY_CASTLE ) {
            System.out.println("SecurityProviderLoaderTest.testInsertProviderAt(): " +
                               "Skipping test -- must have Bouncy Castle JCE provider in classpath.");
            return;
        }

        try {
            SecurityProviderLoader.insertProviderAt("BC", 1);
            assertTrue(true);
        } catch (NoSuchProviderException e) {
            fail("Caught NoSuchProviderException trying to load Bouncy Castle; exception was: " + e);
        }
    }

    @Test
    public final void testLoadESAPIPreferredJCEProvider() {
        // Note: OK if empty string or unset, in fact default is empty string.
        String preferredProvider = ESAPI.securityConfiguration().getPreferredJCEProvider();
        try {
            SecurityProviderLoader.loadESAPIPreferredJCEProvider();
            assertTrue(true);
        } catch (NoSuchProviderException e) {
            fail("Caught NoSuchProviderException trying to preferred JCE provider " +
                 preferredProvider + "; exception was: " + e);
        }
    }
    
    @Test(expected=NoSuchProviderException.class)
    public final void testNoSuchProviderException() throws NoSuchProviderException {
        SecurityProviderLoader.insertProviderAt("DrBobsSecretSnakeOilElixirCryptoJCE", 5);
    }

    @Test(expected=NoSuchProviderException.class)
    public final void testBogusProviderWithFQCN() throws NoSuchProviderException {
        SecurityProviderLoader.insertProviderAt("com.snakeoil.DrBobsSecretSnakeOilElixirCryptoJCE", 5);
    }
    
    @Test
    public final void testWithBouncyCastle() {
        if ( ! HAS_BOUNCY_CASTLE ) {
            System.out.println("SecurityProviderLoaderTest.testInsertProviderAt(): " +
                               "Skipping test -- must have Bouncy Castle JCE provider in classpath.");
            return;
        }

        try {
            SecurityProviderLoader.insertProviderAt("BC", 1);
            assertTrue(true);
        } catch (NoSuchProviderException e) {
            fail("Caught NoSuchProviderException trying to load Bouncy Castle; exception was: " + e);
        }
        
        // First encrypt w/ preferred cipher transformation (AES/CBC/PKCS5Padding).
        try {
            PlainText clearMsg = new PlainText("This is top secret! We are all out of towels!");
            String origMsg = clearMsg.toString(); // Must keep 'cuz by default, clearMsg is overwritten.
            CipherText ct = ESAPI.encryptor().encrypt(clearMsg);
            assertEquals( "*********************************************", clearMsg.toString() );
            PlainText plain = ESAPI.encryptor().decrypt(ct);
            assertEquals( origMsg, plain.toString() );
        } catch (EncryptionException e) {
            fail("Encryption w/ Bouncy Castle failed with EncryptionException for preferred " +
                 "cipher transformation; exception was: " + e);
        }
        
        // Next, try a "combined mode" cipher mode available in Bouncy Castle.
        String encryptor = null;
        try {
            Properties myEnv = new Properties();
    		myEnv.setProperty(DefaultSecurityConfiguration.CIPHER_TRANSFORMATION_IMPLEMENTATION,
    						  "AES/GCM/NoPadding");

	    	// Get an Encryptor instance with the specified, possibly new, cipher transformation.
	    	Encryptor aesGCMencryptor = JavaEncryptor.getInstance(myEnv);
	    	
            PlainText clearMsg = new PlainText("This is top secret! We are all out of towels!");
            String origMsg = clearMsg.toString(); // Must keep 'cuz by default, clearMsg is overwritten.
            CipherText ct = aesGCMencryptor.encrypt(clearMsg);
            PlainText plain = aesGCMencryptor.decrypt(ct);
            assertEquals( origMsg, plain.toString() );
            // Verify that no MAC is calculated for GCM cipher mode. There is no method to
            // validate this, so we look at the String representation of this CipherText
            // object and pick it out of there.
            String str = ct.toString();
            assertTrue( str.matches(".*, MAC is absent;.*") );
        } catch (EncryptionException e) {
            fail("Encryption w/ Bouncy Castle failed with EncryptionException for preferred " +
                 "cipher transformation; exception was: " + e);
        }
    }
}

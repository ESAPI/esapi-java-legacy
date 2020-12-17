package org.owasp.esapi.crypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Before;
import org.junit.Test;

import junit.framework.JUnit4TestAdapter;

import org.owasp.esapi.crypto.KeyDerivationFunction;
import org.owasp.esapi.crypto.CryptoHelper;
import org.owasp.esapi.errors.EncryptionException;

public class KeyDerivationFunctionTest {

    private static SecretKey desKey;
    private static SecretKey tdes2key;
    private static SecretKey tdes3key;
    private static SecretKey aes128key;
    private static SecretKey aes192key;
    private static SecretKey aes256key;
    private static SecretKey shortKey;

    private KeyDerivationFunction kdfSha1;
    private KeyDerivationFunction kdfSha256;

    @BeforeClass
    public static void setupStatic() {
        try {
            desKey    = CryptoHelper.generateSecretKey("DES", 56);
            tdes2key  = CryptoHelper.generateSecretKey("DESede", 112);
            tdes3key  = CryptoHelper.generateSecretKey("DESede", 168);
            aes128key = CryptoHelper.generateSecretKey("AES", 128);
            aes128key = CryptoHelper.generateSecretKey("AES", 128);
            aes192key = CryptoHelper.generateSecretKey("AES", 192);
            aes256key = CryptoHelper.generateSecretKey("AES", 256);

            shortKey  = new SecretKeySpec(desKey.getEncoded(), 0, 5, "Blowfish");   // 40-bits. Blowfish has var key size
        } catch (EncryptionException e) {
            fail("Caught unexpected EncryptionException while generating keys; msg was "
                    + e.getMessage());
        }
    }

    @Before
    public void setup() {
        kdfSha1     = new KeyDerivationFunction( KeyDerivationFunction.PRF_ALGORITHMS.HmacSHA1 );
        kdfSha256   = new KeyDerivationFunction( KeyDerivationFunction.PRF_ALGORITHMS.HmacSHA256 );
    }

    @Test(expected = EncryptionException.class)
    public void testKeyTooShort() throws EncryptionException {
        // System.out.println("testKeyTooShort");
        try {
            SecretKey key = kdfSha1.computeDerivedKey( shortKey, 128, "encryption" );
            fail("testKeyTooShort: Expected IllegalArgumentException to be thrown.");
        } catch ( NoSuchAlgorithmException | InvalidKeyException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKeySizeTooShort() {
        // System.out.println("testKeySizeTooShort");
        try {
            SecretKey key = kdfSha1.computeDerivedKey( aes128key, 40, "encryption" );   // Min size is 56 bits
            fail("testKeySizeTooShort: Expected IllegalArgumentException to be thrown.");
        } catch ( NoSuchAlgorithmException | InvalidKeyException | EncryptionException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullKey() {
        // System.out.println("testNullKey");
        try {
            SecretKey key = kdfSha1.computeDerivedKey( null, 56, "encryption" );        // Null key disallowed
            assertTrue(key == null); // Not reached!
        } catch ( NoSuchAlgorithmException | InvalidKeyException | EncryptionException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKeySizeNotEvenNumberOfBytes() {
        // System.out.println("testKeySizeNotEvenNumberOfBytes");
        try {
            SecretKey key = kdfSha1.computeDerivedKey( aes128key, 60, "encryption" );   // 60 % 8 == 4
            assertTrue(key == null); // Not reached!
        } catch ( NoSuchAlgorithmException | InvalidKeyException | EncryptionException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPurposeNull() {
        // System.out.println("testPurposeNull");
        try {
            SecretKey key = kdfSha1.computeDerivedKey( aes128key, 128, null );   // purpose is null
            assertTrue(key == null); // Not reached!
        } catch ( NoSuchAlgorithmException | InvalidKeyException | EncryptionException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPurposeEmpty() {
        // System.out.println("testPurposeEmpty");
        try {
            SecretKey key = kdfSha1.computeDerivedKey( aes128key, 128, "" );   // purpose is empty string
            assertTrue(key == null); // Not reached!
        } catch ( NoSuchAlgorithmException | InvalidKeyException | EncryptionException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    @Test
    public void testSunnyDay() {
        // System.out.println("testSunnyDay");
        try {
            SecretKey key1 = kdfSha1.computeDerivedKey( aes128key, 128, "encryption" );
            assertTrue(key1 != null);
            assertTrue( key1.getEncoded().length == 128 / 8 );

            SecretKey key2 = kdfSha1.computeDerivedKey( aes128key, 128, "authenticity" );
            assertTrue(key2 != null);
            assertTrue( key2.getEncoded().length == 128 / 8 );

            SecretKey key1b = kdfSha1.computeDerivedKey( aes128key, 128, "encryption" );

            assertTrue( java.security.MessageDigest.isEqual( key1.getEncoded(), key1b.getEncoded() ) );
            assertFalse( java.security.MessageDigest.isEqual( key1.getEncoded(), key2.getEncoded() ) );
        } catch ( NoSuchAlgorithmException | InvalidKeyException | EncryptionException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    @Test
    public void testSunnyDay2() {       // Two sunny day tests in a row!? This inevitably will fail if run in Columbus, OH.
        // System.out.println("testSunnyDay2");
        try {
            SecretKey key1 = kdfSha256.computeDerivedKey( aes256key, 192, "Why am I here?" );
            assertTrue(key1 != null);
            assertTrue( key1.getEncoded().length == 192 / 8 );

            // Be honest. You thought I was goint to say "42", didn't you?
            SecretKey key2 = kdfSha256.computeDerivedKey( aes256key, 192, "No doubt, to annoy people." );
            assertTrue(key2 != null);
            assertTrue( key2.getEncoded().length == 192 / 8 );

                // Should be different because different purpose given for each.
            assertFalse( java.security.MessageDigest.isEqual( key1.getEncoded(), key2.getEncoded() ) );
        } catch ( NoSuchAlgorithmException | InvalidKeyException | EncryptionException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    @Test
    public void testSetContext() {
        // System.out.println("testSetContext");
        try {
            SecretKey key1 = kdfSha256.computeDerivedKey( aes128key, 128, "encryption" );
            assertTrue(key1 != null);
            assertTrue( key1.getEncoded().length == 128 / 8 );

            SecretKey key2 = kdfSha1.computeDerivedKey( aes128key, 128, "encryption" );

                // Should be false because one uses HmacSHA256 and the other uses HmacSHA1
            assertFalse( java.security.MessageDigest.isEqual( key1.getEncoded(), key2.getEncoded() ) );

            kdfSha256.setContext( "plugh xyzzy" );  // Change context. Originally it is empty string.
            SecretKey key1b = kdfSha256.computeDerivedKey( aes128key, 128, "encryption" );
            assertTrue(key1b != null);
            assertTrue( key1b.getEncoded().length == 128 / 8 );

                // Should be false because different contexts used.
            assertFalse( java.security.MessageDigest.isEqual( key1.getEncoded(), key1b.getEncoded() ) );
        } catch ( NoSuchAlgorithmException | InvalidKeyException | EncryptionException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetContextToNull() {
        // System.out.println("testSetContextToNull");
        try {
            SecretKey key1 = kdfSha256.computeDerivedKey( aes128key, 128, "encryption" );
            kdfSha256.setContext( null );   // Throws IllegalArgumentExeption

            fail("testSetContextToNull: Expected IllegalArgumentException to be thrown.");
        } catch ( NoSuchAlgorithmException | InvalidKeyException | EncryptionException e ) {
            fail("Caught unexpected exception " + e.getClass().getName() + ": exception msg: " + e);
        }
    }

    /**
     * Run all the test cases in this suite. This is to allow running from
     * {@code org.owasp.esapi.AllTests} which uses a JUnit 3 test runner.
     */
    public static junit.framework.Test suite() {
        // System.out.println("In suite()");
        return new JUnit4TestAdapter(KeyDerivationFunctionTest.class);
    }
}

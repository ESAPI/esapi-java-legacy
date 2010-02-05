package org.owasp.esapi.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import junit.framework.TestCase;
import junit.framework.TestSuite;

import javax.crypto.Cipher;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.Hex;
import org.owasp.esapi.crypto.CipherSpec;

/** JUnit test to test CipherSpec class. */
public class CipherSpecTest extends TestCase {

	private Cipher dfltAESCipher = null;
	private Cipher dfltECBCipher = null;	// will be "AES/ECB/NoPadding";
	private Cipher dfltOtherCipher = null;
	private CipherSpec cipherSpec = null;
	private static byte[] myIV = null;

	@Before public void setUp() throws Exception {
			// This will throw ConfigurationException if IV type is not set to
			// 'fixed', which it's not. (We have it set to 'random'.)
		// myIV = Hex.decode( ESAPI.securityConfiguration().getFixedIV() );
		myIV = Hex.decode( "0x000102030405060708090a0b0c0d0e0f" );

		dfltAESCipher   = Cipher.getInstance("AES");
		dfltECBCipher   = Cipher.getInstance("AES/ECB/NoPadding");
		dfltOtherCipher = Cipher.getInstance("Blowfish/OFB8/PKCS5Padding");

		assertTrue( dfltAESCipher != null );
		assertTrue( dfltECBCipher != null );
		assertTrue( dfltOtherCipher != null );

		cipherSpec = new CipherSpec(dfltOtherCipher);
		assertTrue( cipherSpec != null );
	}

	@After public void tearDown() throws Exception {
    	// none
	}
	
	/** Test CipherSpec(String cipherXform, int keySize, int blockSize, final byte[] iv) */
	@Test public void testCipherSpecStringIntIntByteArray() {
		
		cipherSpec = new CipherSpec( "AES/CBC/NoPadding",  128,  8, myIV);
		assertTrue( cipherSpec != null );
		cipherSpec = null;
		try {
				// Invalid cipher xform -- empty
			cipherSpec = new CipherSpec( "",  128,  8, myIV);
		} catch( Throwable t ) {
			assertTrue( cipherSpec == null );
		}
		try {
				// Invalid cipher xform -- missing padding scheme
			cipherSpec = new CipherSpec("AES/CBC", 128, 8, myIV);
		} catch( Throwable t ) {
			assertTrue( cipherSpec == null );
		}

	}

	/** CipherSpec(final Cipher cipher, int keySize) */
	@Test public void testCipherSpecCipherInt() {
    	cipherSpec = new CipherSpec(dfltOtherCipher, 112);
    	assertTrue( cipherSpec != null );
    	assertTrue( cipherSpec.getCipherAlgorithm().equals("Blowfish"));
    	assertTrue( cipherSpec.getCipherMode().equals("OFB8"));
    	
    	cipherSpec = new CipherSpec(dfltAESCipher, 256);
    	assertTrue( cipherSpec != null );
    	assertTrue( cipherSpec.getCipherAlgorithm().equals("AES"));
    	assertTrue( cipherSpec.getCipherMode().equals("ECB") );
    	assertTrue( cipherSpec.getPaddingScheme().equals("NoPadding") );
    	// System.out.println("testCipherSpecInt(): " + cipherSpec);
	}

	/** Test CipherSpec(final byte[] iv) */
	@Test public void testCipherSpecByteArray() {
		assertTrue( myIV != null );
		assertTrue( myIV.length > 0 );
		cipherSpec = new CipherSpec(myIV);
		assertTrue( cipherSpec.getKeySize() == 
						ESAPI.securityConfiguration().getEncryptionKeyLength() );
		assertTrue( cipherSpec.getCipherTransformation().equals(
						ESAPI.securityConfiguration().getCipherTransformation() ) );
	}

	/** Test CipherSpec() */
	@Test public void testCipherSpec() {
		cipherSpec = new CipherSpec( dfltECBCipher );
		assertTrue( cipherSpec.getCipherTransformation().equals("AES/ECB/NoPadding") );
		assertTrue( cipherSpec.getIV() == null );
	
		cipherSpec = new CipherSpec(dfltOtherCipher);
		assertTrue( cipherSpec.getCipherMode().equals("OFB8") );
	}

	/** Test setCipherTransformation(String cipherXform) */
	@Test public void testSetCipherTransformation() {
		cipherSpec = new CipherSpec();
		cipherSpec.setCipherTransformation("AlgName/Mode/Padding");
		cipherSpec.getCipherAlgorithm().equals("AlgName/Mode/Padding");
		
		try {
				// Don't use null here as compiling JUnit tests disables assertion
				// checking so we get a NullPointerException here instead.
			cipherSpec.setCipherTransformation(""); // Throws AssertionError
		} catch (AssertionError e) {
			assertTrue(true);	// Doesn't work w/ @Test(expected=AssertionError.class)
		}
	}

	/** Test getCipherTransformation() */
	@Test public void testGetCipherTransformation() {
		assertTrue( (new CipherSpec()).getCipherTransformation().equals("AES/CBC/PKCS5Padding") );
	}

	/** Test setKeySize() */
	@Test public void testSetKeySize() {
		assertTrue( (new CipherSpec()).setKeySize(56).getKeySize() == 56 );
	}

	/** Test getKeySize() */
	@Test public void testGetKeySize() {
		assertTrue( (new CipherSpec()).getKeySize() ==
			ESAPI.securityConfiguration().getEncryptionKeyLength() );
	}

	/** Test setBlockSize() */
	@Test public void testSetBlockSize() {
		try {
			cipherSpec.setBlockSize(0); // Throws AssertionError
		} catch (AssertionError e) {
			assertTrue(true);	// Doesn't work w/ @Test(expected=AssertionError.class)
		}
		try {
			cipherSpec.setBlockSize(-1); // Throws AssertionError
		} catch (AssertionError e) {
			assertTrue(true);	// Doesn't work w/ @Test(expected=AssertionError.class)
		}
		assertTrue( cipherSpec.setBlockSize(4).getBlockSize() == 4 );
	}

	/** Test getBlockSize() */
	@Test public void testGetBlockSize() {
		assertTrue( cipherSpec.getBlockSize() == 8 );
	}

	/** Test getCipherAlgorithm() */
	@Test public void testGetCipherAlgorithm() {
		assertTrue( cipherSpec.getCipherAlgorithm().equals("Blowfish") );
	}

	/** Test getCipherMode */
	@Test public void testGetCipherMode() {
		assertTrue( cipherSpec.getCipherMode().equals("OFB8") );
	}

	/** Test getPaddingScheme() */
	@Test public void testGetPaddingScheme() {
		assertTrue( cipherSpec.getPaddingScheme().equals("PKCS5Padding") );
	}

	/** Test setIV() */
	@Test public void testSetIV() {
		try {
			// Test that ECB mode allows a null IV
			cipherSpec = new CipherSpec(dfltECBCipher);
			cipherSpec.setIV(null);
			assertTrue(true);
		} catch ( AssertionError e) {
			assertFalse("Test failed; unexpected exception", false);
		}
		try {
			// Test that CBC mode does allows a null IV
			cipherSpec = new CipherSpec(dfltAESCipher);
			cipherSpec.setIV(null);
			assertFalse("Test failed; Expected exception not thrown", false);
		} catch ( AssertionError e) {
			assertTrue(true);
		}
	}

	/** Test requiresIV() */
	@Test public void testRequiresIV() {
		assertTrue( (new CipherSpec(dfltECBCipher)).requiresIV() == false );
		cipherSpec = new CipherSpec(dfltAESCipher);
		assertTrue( cipherSpec.getCipherMode().equals("ECB") );
		assertTrue( cipherSpec.requiresIV() == false );
		assertTrue( new CipherSpec(dfltOtherCipher).requiresIV() );
	}
	
	/** Test serialization */
	@Test public void testSerialization() {
        String filename = "cipherspec.ser";
        File serializedFile = new File(filename);
        boolean success = false;
        try {
            serializedFile.delete();	// Delete any old serialized file.
            
            cipherSpec = new CipherSpec( "AES/CBC/NoPadding",  128,  8, myIV);
            FileOutputStream fos = new FileOutputStream(filename);
            ObjectOutputStream out = new ObjectOutputStream(fos);
            out.writeObject(cipherSpec);
            out.close();
            fos.close();

            FileInputStream fis = new FileInputStream(filename);
            ObjectInputStream in = new ObjectInputStream(fis);
            CipherSpec restoredCipherSpec = (CipherSpec)in.readObject();
            in.close();
            fis.close();

            // check that cipherSpec and restoredCipherSpec are equal. Just
            // compare them via their string representations.
            assertEquals("Serialized restored CipherSpec differs from saved CipherSpec",
            			 cipherSpec.toString(), restoredCipherSpec.toString() );
            
            success = true;
        } catch(IOException ex) {
            ex.printStackTrace(System.err);
            fail("testSerialization(): Unexpected IOException: " + ex);
        } catch(ClassNotFoundException ex) {
            ex.printStackTrace(System.err);
            fail("testSerialization(): Unexpected ClassNotFoundException: " + ex);
        } finally {
            // If test succeeds, remove the file. If it fails, leave it behind
            // for further analysis.
            if ( success && serializedFile.exists() ) {
                boolean deleted = serializedFile.delete();
                if ( !deleted ) {
                    try {
                        System.err.println("Unable to delete file: " + serializedFile.getCanonicalPath() );
                    } catch (IOException e) {
                        ; // Ignore
                    }
                }
            }
        }
	}
	
    /**
     * Run all the test cases in this suite.
     * This is to allow running from {@code org.owasp.esapi.AllTests}.
     */
    public static junit.framework.Test suite() {
        TestSuite suite = new TestSuite(CipherSpecTest.class);

        return suite;
    }
}
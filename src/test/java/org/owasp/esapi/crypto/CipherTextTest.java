package org.owasp.esapi.crypto;

import static org.junit.Assert.*;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.*;
import org.junit.rules.TemporaryFolder;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.reference.crypto.CryptoPolicy;

import junit.framework.Assert;
import junit.framework.JUnit4TestAdapter;

public class CipherTextTest {

	private CipherSpec cipherSpec_ = null;
    private Cipher encryptor = null;
    private Cipher decryptor = null;
    private IvParameterSpec ivSpec = null;
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
   
    
	@Before
	public void setUp() throws Exception {
        encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = null;
        ivBytes = ESAPI.randomizer().getRandomBytes(encryptor.getBlockSize());
        ivSpec = new IvParameterSpec(ivBytes);
	}

	/** Test the default CTOR */
	@Test
	public final void testCipherText() {
		CipherText ct =  new CipherText();

		cipherSpec_ = new CipherSpec();
		assertTrue( ct.getCipherTransformation().equals( cipherSpec_.getCipherTransformation()));
		assertTrue( ct.getBlockSize() == cipherSpec_.getBlockSize() );
	}

	@Test
	public final void testCipherTextCipherSpec() {
		cipherSpec_ = new CipherSpec("DESede/OFB8/NoPadding", 112);
		CipherText ct = new CipherText( cipherSpec_ );
		assertTrue( ct.getRawCipherText() == null );
		assertTrue( ct.getCipherAlgorithm().equals("DESede") );
		assertTrue( ct.getKeySize() == cipherSpec_.getKeySize() );
	}

	@Test
	public final void testCipherTextCipherSpecByteArray()
	{
		try {
			CipherSpec cipherSpec = new CipherSpec(encryptor, 128);
			cipherSpec.setIV(ivSpec.getIV());
			SecretKey key =
				CryptoHelper.generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			encryptor.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] raw = encryptor.doFinal("Hello".getBytes("UTF8"));
			CipherText ct = new CipherText(cipherSpec, raw);
			assertTrue( ct != null );
			byte[] ctRaw = ct.getRawCipherText();
			assertTrue( ctRaw != null );
			assertArrayEquals(raw, ctRaw);
			assertTrue( ct.getCipherTransformation().equals(cipherSpec.getCipherTransformation()) );;
			assertTrue( ct.getCipherAlgorithm().equals(cipherSpec.getCipherAlgorithm()) );
			assertTrue( ct.getPaddingScheme().equals(cipherSpec.getPaddingScheme()) );
			assertTrue( ct.getBlockSize() == cipherSpec.getBlockSize() );
			assertTrue( ct.getKeySize() == cipherSpec.getKeySize() );
			byte[] ctIV = ct.getIV();
			byte[] csIV = cipherSpec.getIV();
			assertArrayEquals(ctIV, csIV);
		} catch( Exception ex) {
			// As far as test coverage goes, we really don't want this to be covered.
			fail("Caught unexpected exception: " + ex.getClass().getName() +
					    "; exception message was: " + ex.getMessage());
		}
	}


	@Test
	public final void testDecryptionUsingCipherText() {
		try {
			CipherSpec cipherSpec = new CipherSpec(encryptor, 128);
			cipherSpec.setIV(ivSpec.getIV());
			assertTrue( cipherSpec.getIV() != null );
			assertTrue( cipherSpec.getIV().length > 0 );
			SecretKey key =
				CryptoHelper.generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			encryptor.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] ctraw = encryptor.doFinal("Hello".getBytes("UTF8"));
			CipherText ct = new CipherText(cipherSpec, ctraw);
			assertTrue( ct.getCipherMode().equals("CBC") );
			assertTrue( ct.requiresIV() ); // CBC mode requires an IV.
			String b64ctraw = ct.getBase64EncodedRawCipherText();
			assertTrue( b64ctraw != null);
			assertArrayEquals( ESAPI.encoder().decodeFromBase64(b64ctraw), ctraw );
			decryptor.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ct.getIV()));
			byte[] ptraw = decryptor.doFinal(ESAPI.encoder().decodeFromBase64(b64ctraw));
			assertTrue( ptraw != null );
			assertTrue( ptraw.length > 0 );
			String plaintext = new String( ptraw, "UTF-8");
			assertTrue( plaintext.equals("Hello") );
			assertArrayEquals( ct.getRawCipherText(), ctraw );
			
			byte[] ivAndRaw = ESAPI.encoder().decodeFromBase64( ct.getEncodedIVCipherText() );
			assertTrue( ivAndRaw.length > ctraw.length );
			assertTrue( ct.getBlockSize() == ( ivAndRaw.length - ctraw.length ) );
		} catch( Exception ex) {
		    // Note: FindBugs reports a false positive here...
		    //    REC_CATCH_EXCEPTION: Exception is caught when Exception is not thrown
		    // but exceptions really can be thrown. This probably is because FindBugs
		    // examines the byte-code rather than the source code. However "fixing" this
		    // so that it doesn't complain will make the test much more complicated as there
		    // are about 3 or 4 different exception types.
		    //
		    // On a completely different note, as far as test coverage metrics goes,
			// we really don't care if this is covered or nit as it is not our intent
		    // to be causing exceptions here.
			ex.printStackTrace(System.err);
			fail("Caught unexpected exception: " + ex.getClass().getName() +
					"; exception message was: " + ex.getMessage());
		}
	}

	@Test
	public final void testMIC() {
		try {
			CipherSpec cipherSpec = new CipherSpec(encryptor, 128);
			cipherSpec.setIV(ivSpec.getIV());
			SecretKey key =
				CryptoHelper.generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			encryptor.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] ctraw = encryptor.doFinal("Hello".getBytes("UTF8"));
			CipherText ct = new CipherText(cipherSpec, ctraw);
			assertTrue( ct.getIV() != null && ct.getIV().length > 0 );
			SecretKey authKey = CryptoHelper.computeDerivedKey(key, key.getEncoded().length * 8, "authenticity");
			ct.computeAndStoreMAC( authKey ); 
			try {
				ct.setIVandCiphertext(ivSpec.getIV(), ctraw);	// Expected to log & throw.
			} catch( Exception ex ) {
				assertTrue( ex instanceof EncryptionException );
			}
			try {
				ct.setCiphertext(ctraw);	// Expected to log and throw message about
											// not being able to store raw ciphertext.
			} catch( Exception ex ) {
				assertTrue( ex instanceof EncryptionException );
			}
			decryptor.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec( ct.getIV() ) );
			byte[] ptraw = decryptor.doFinal( ct.getRawCipherText() );
			assertTrue( ptraw != null && ptraw.length > 0 );
			ct.validateMAC( authKey );
		} catch( Exception ex) {
			// As far as test coverage goes, we really don't want this to be covered.
			ex.printStackTrace(System.err);
			fail("Caught unexpected exception: " + ex.getClass().getName() +
					"; exception message was: " + ex.getMessage());
		}
	}

	/** Test <i>portable</i> serialization. */
	@Test public final void testPortableSerialization() throws Exception{
	    System.out.println("CipherTextTest.testPortableSerialization()starting...");
	    String filename = "ciphertext-portable.ser";
	    File serializedFile = tempFolder.newFile(filename);
	  

	    int keySize = 128;
	    if ( CryptoPolicy.isUnlimitedStrengthCryptoAvailable() ) {
	        keySize = 256;
	    }
	    CipherSpec cipherSpec = new CipherSpec(encryptor, keySize);
	    cipherSpec.setIV(ivSpec.getIV());
	    SecretKey key;
	    try {
	        key = CryptoHelper.generateSecretKey(cipherSpec.getCipherAlgorithm(), keySize);

	        encryptor.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	        byte[] raw = encryptor.doFinal("This is my secret message!!!".getBytes("UTF8"));
	        CipherText ciphertext = new CipherText(cipherSpec, raw);
		    KeyDerivationFunction kdf = new KeyDerivationFunction( KeyDerivationFunction.PRF_ALGORITHMS.HmacSHA1 );
	        SecretKey authKey = kdf.computeDerivedKey(key, key.getEncoded().length * 8, "authenticity");
	        ciphertext.computeAndStoreMAC( authKey );
//          System.err.println("Original ciphertext being serialized: " + ciphertext);
	        byte[] serializedBytes = ciphertext.asPortableSerializedByteArray();
	        
	        FileOutputStream fos = new FileOutputStream(serializedFile);
            fos.write(serializedBytes);
                // Note: FindBugs complains that this test may fail to close
                // the fos output stream. We don't really care.
            fos.close();
            
            // NOTE: FindBugs complains about this (OS_OPEN_STREAM). It apparently
            //       is too lame to know that 'fis.read()' is a serious side-effect.
            FileInputStream fis = new FileInputStream(serializedFile);
            int avail = fis.available();
            byte[] bytes = new byte[avail];
            fis.read(bytes, 0, avail);
            
            // Sleep one second to prove that the timestamp on the original
            // CipherText object is the one that we use and not just the
            // current time. Only after that, do we restore the serialized bytes.
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                ;    // Ignore
            }       
            CipherText restoredCipherText = CipherText.fromPortableSerializedBytes(bytes);
//          System.err.println("Restored ciphertext: " + restoredCipherText);
            assertTrue( ciphertext.equals(restoredCipherText));
	    } catch (EncryptionException e) {
	        Assert.fail("Caught EncryptionException: " + e);
        } catch (FileNotFoundException e) {
            Assert.fail("Caught FileNotFoundException: " + e);
        } catch (IOException e) {
            Assert.fail("Caught IOException: " + e);
        } catch (Exception e) {
            Assert.fail("Caught Exception: " + e);
        } finally {
            // FindBugs complains that we are ignoring this return value. We really don't care.
            serializedFile.delete();
        }
	}
	
	/** Test <i>portable</i> serialization for backward compatibility with ESAPI 2.0. */
	@Test public final void testPortableSerializationBackwardCompatibility() {
	    System.out.println("testPortableSerializationBackwardCompatibility()starting...");
	    String filename = "src/test/resources/ESAPI2.0-ciphertext-portable.ser";  // Do NOT remove
	    File serializedFile = new File(filename);

	    try {
	    	// String expectedMsg = "This is my secret message!!!";
            
            // NOTE: FindBugs complains about this (OS_OPEN_STREAM). It apparently
            //       is too lame to know that 'fis.read()' is a serious side-effect.
            FileInputStream fis = new FileInputStream(serializedFile);
            int avail = fis.available();
            byte[] bytes = new byte[avail];
            fis.read(bytes, 0, avail);
            // We can't go as far and decrypt it because the file was encrypted using a
            // temporary session key.
            CipherText restoredCipherText = CipherText.fromPortableSerializedBytes(bytes);
            assertTrue( restoredCipherText != null );
            int retrievedKdfVersion = restoredCipherText.getKDFVersion();
	    } catch (EncryptionException e) {
	        Assert.fail("Caught EncryptionException: " + e);
        } catch (FileNotFoundException e) {
            Assert.fail("Caught FileNotFoundException: " + e);
        } catch (IOException e) {
            Assert.fail("Caught IOException: " + e);
        } catch (Exception e) {
            Assert.fail("Caught Exception: " + e);
        } finally {
        	; // Do NOT delete the file.
        }
	}
	
	/** Test Java serialization. */
	@Test public final void testJavaSerialization() {
        String filename = "ciphertext.ser";
      
        try {
            File serializedFile = tempFolder.newFile(filename);
            
            CipherSpec cipherSpec = new CipherSpec(encryptor, 128);
			cipherSpec.setIV(ivSpec.getIV());
			SecretKey key =
				CryptoHelper.generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			encryptor.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] raw = encryptor.doFinal("This is my secret message!!!".getBytes("UTF8"));
			CipherText ciphertext = new CipherText(cipherSpec, raw);

            FileOutputStream fos = new FileOutputStream(serializedFile);
            ObjectOutputStream out = new ObjectOutputStream(fos);
            out.writeObject(ciphertext);
            out.close();
            fos.close();

            FileInputStream fis = new FileInputStream(serializedFile);
            ObjectInputStream in = new ObjectInputStream(fis);
            CipherText restoredCipherText = (CipherText)in.readObject();
            in.close();
            fis.close();

            // check that ciphertext and restoredCipherText are equal. Requires
            // multiple checks. (Hmmm... maybe overriding equals() and hashCode()
            // is in order???)
            assertEquals("1: Serialized restored CipherText differs from saved CipherText",
            			 ciphertext.toString(), restoredCipherText.toString());
            assertArrayEquals("2: Serialized restored CipherText differs from saved CipherText",
            			 ciphertext.getIV(), restoredCipherText.getIV());
            assertEquals("3: Serialized restored CipherText differs from saved CipherText",
            			 ciphertext.getBase64EncodedRawCipherText(),
            			 restoredCipherText.getBase64EncodedRawCipherText());
            
        } catch(IOException ex) {
            ex.printStackTrace(System.err);
            fail("testJavaSerialization(): Unexpected IOException: " + ex);
        } catch(ClassNotFoundException ex) {
            ex.printStackTrace(System.err);
            fail("testJavaSerialization(): Unexpected ClassNotFoundException: " + ex);
        } catch (EncryptionException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected EncryptionException: " + ex);
		} catch (IllegalBlockSizeException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected IllegalBlockSizeException: " + ex);
		} catch (BadPaddingException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected BadPaddingException: " + ex);
		} catch (InvalidKeyException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected InvalidKeyException: " + ex);
		} catch (InvalidAlgorithmParameterException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected InvalidAlgorithmParameterException: " + ex);
		} 
	}
	
	/**
	 * Run all the test cases in this suite.
	 * This is to allow running from {@code org.owasp.esapi.AllTests} which
	 * uses a JUnit 3 test runner.
	 */
	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(CipherTextTest.class);
	}
}

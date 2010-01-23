package org.owasp.esapi.reference;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import junit.framework.JUnit4TestAdapter;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.esapi.CipherText;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.util.CipherSpec;
import org.owasp.esapi.util.CryptoHelper;

public class DefaultCipherTextTest {
	private static final Class<DefaultCipherTextTest> CLASS = DefaultCipherTextTest.class;
	private static final String CLASS_NAME = CLASS.getName();
	private CipherSpec cipherSpec = null;
	private Cipher encryptor = null;
	private Cipher decryptor = null;
	private IvParameterSpec ivSpec = null;

	@Before
	public void setUp() throws Exception {
		encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
		decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
		byte[] ivBytes = null;
		ivBytes = ESAPI.randomizer().getRandomBytes(encryptor.getBlockSize());
		ivSpec = new IvParameterSpec(ivBytes);
	}

	@After
	public void tearDown() throws Exception {
	}

	/** Test the default CTOR */
	@Test
	public final void testDefaultCipherText() {
		CipherText ct =  new DefaultCipherText();

		cipherSpec = new CipherSpec();
		assertTrue( ct.getCipherTransformation().equals( cipherSpec.getCipherTransformation()));
		assertTrue( ct.getBlockSize() == cipherSpec.getBlockSize() );
	}

	@Test
	public final void testDefaultCipherTextCipherSpec() {
		cipherSpec = new CipherSpec("DESede/OFB8/NoPadding", 112);
		CipherText ct = new DefaultCipherText( cipherSpec );
		assertTrue( ct.getRawCipherText() == null );
		assertTrue( ct.getCipherAlgorithm().equals("DESede") );
		assertTrue( ct.getKeySize() == cipherSpec.getKeySize() );
	}

	@Test
	public final void testDefaultCipherTextCipherSpecByteArray()
	{
		try {
			CipherSpec cipherSpec = new CipherSpec(encryptor, 128);
			cipherSpec.setIV(ivSpec.getIV());
			SecretKey key =
				CryptoHelper.generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			encryptor.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] raw = encryptor.doFinal("Hello".getBytes("UTF8"));
			CipherText ct = new DefaultCipherText(cipherSpec, raw);
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
			CipherText ct = new DefaultCipherText(cipherSpec, ctraw);
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
			// As far as test coverage goes, we really don't want this to be covered.
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
			DefaultCipherText ct = new DefaultCipherText(cipherSpec, ctraw);
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

	/** Test serialization */
	@Test public void testSerialization() {
		File serializedFile = null;

		try {
			serializedFile = File.createTempFile(CLASS_NAME,".ser");

			CipherSpec cipherSpec = new CipherSpec(encryptor, 128);
			cipherSpec.setIV(ivSpec.getIV());
			SecretKey key =
				CryptoHelper.generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			encryptor.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] raw = encryptor.doFinal("Hello".getBytes("UTF8"));
			CipherText ciphertext = new DefaultCipherText(cipherSpec, raw);

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
			fail("testSerialization(): Unexpected IOException: " + ex);
		} catch(ClassNotFoundException ex) {
			ex.printStackTrace(System.err);
			fail("testSerialization(): Unexpected ClassNotFoundException: " + ex);
		} catch (EncryptionException ex) {
			ex.printStackTrace(System.err);
			fail("testSerialization(): Unexpected EncryptionException: " + ex);
		} catch (IllegalBlockSizeException ex) {
			ex.printStackTrace(System.err);
			fail("testSerialization(): Unexpected IllegalBlockSizeException: " + ex);
		} catch (BadPaddingException ex) {
			ex.printStackTrace(System.err);
			fail("testSerialization(): Unexpected BadPaddingException: " + ex);
		} catch (InvalidKeyException ex) {
			ex.printStackTrace(System.err);
			fail("testSerialization(): Unexpected InvalidKeyException: " + ex);
		} catch (InvalidAlgorithmParameterException ex) {
			ex.printStackTrace(System.err);
			fail("testSerialization(): Unexpected InvalidAlgorithmParameterException: " + ex);
		}
		finally
		{
			if(serializedFile != null && serializedFile.exists() && !serializedFile.delete())
			{
				System.err.println("Unable to delete temporary file " + serializedFile + ". Another attempt will be made at JVM exit.");
				serializedFile.deleteOnExit();
			}
		}
	}

	/**
	 * Run all the test cases in this suite.
	 * This is to allow running from {@code org.owasp.esapi.AllTests} which
	 * uses a JUnit 3 test runner.
	 */
	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(DefaultCipherTextTest.class);
	}
}

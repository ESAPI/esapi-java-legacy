package org.owasp.esapi.reference;

import static org.junit.Assert.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.esapi.CipherText;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.util.CipherSpec;
import org.owasp.esapi.util.CryptoHelper;
import org.owasp.esapi.util.ObjFactory;

public class DefaultCipherTextTest {

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
		// Make sure we can get this via reflection.
		String cipherTextImpl = ESAPI.securityConfiguration().getCipherTextImplementation();
		CipherText ct =  (new ObjFactory<CipherText>()).make(cipherTextImpl, "CipherText");

		assertTrue( ct != null );
				// If someone overrides this in ESAPI.properties this would fail. While
				// not likely, it could happen.
		// assertTrue( ct.getClass().getName().equals(DefaultCipherText.class.getName()));
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
			ct.computeAndStoreMIC(key.getEncoded());
			try {
				ct.setIVandCiphertext(ivSpec.getIV(), ctraw);	// Expected to log & throw.
			} catch( Exception ex ) {
				assertTrue( ex instanceof EncryptionException );
			}
			try {
				ct.setCiphertext(ctraw);	// Expected to log and throw.
			} catch( Exception ex ) {
				assertTrue( ex instanceof EncryptionException );
			}
			decryptor.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ct.getIV()));
			byte[] ptraw = decryptor.doFinal( ct.getRawCipherText() );
			assertTrue( ptraw != null && ptraw.length > 0 );
			ct.validateMIC( key.getEncoded() );
		} catch( Exception ex) {
			// As far as test coverage goes, we really don't want this to be covered.
			ex.printStackTrace(System.err);
			fail("Caught unexpected exception: " + ex.getClass().getName() +
					"; exception message was: " + ex.getMessage());
		}
	}

}

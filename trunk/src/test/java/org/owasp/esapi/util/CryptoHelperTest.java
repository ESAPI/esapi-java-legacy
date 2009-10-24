package org.owasp.esapi.util;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;

import junit.framework.JUnit4TestAdapter;
import org.owasp.esapi.errors.EncryptionException;

public class CryptoHelperTest {
	
	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public final void testGenerateSecretKeySunnyDay() {
		try {
			SecretKey key =
				CryptoHelper.generateSecretKey("AES", 128);
			assertTrue( key.getAlgorithm().equals("AES") );
			assertTrue( 128/8 == key.getEncoded().length );
		} catch (EncryptionException e) {
			// OK if not covered in code coverage -- not expected.
			fail("Caught unexpected EncryptionException; msg was " + e.getMessage() );
		}
	}

	@Test(expected=EncryptionException.class)
	public final void testGenerateSecretKeyEncryptionException() throws EncryptionException
	{
		SecretKey key =
			CryptoHelper.generateSecretKey("NoSuchAlg", 128);
		assertTrue( key == null );	// Not reached!
	}

	@Test
	public final void testOverwriteByteArrayByte() {
		byte[] secret = "secret password".getBytes();
		int len = secret.length;
		CryptoHelper.overwrite(secret, (byte)'x');
		assertTrue( secret.length == len );					// Length unchanged
		assertTrue( checkByteArray(secret, (byte)'x') );	// Filled with 'x'
	}

	@Test
	public final void testCopyByteArraySunnyDay() {
		byte[] src = new byte[20];
		fillByteArray(src, (byte)'A');
		byte[] dest = new byte[20];
		fillByteArray(dest, (byte)'B');
		CryptoHelper.copyByteArray(src, dest);
		assertTrue( checkByteArray(src, (byte)'A') );	// Still filled with 'A'
		assertTrue( checkByteArray(dest, (byte)'A') );	// Now filled with 'B'
	}

	@Test(expected=NullPointerException.class)
	public final void testCopyByteArraySrcNullPointerException() {
		byte[] ba = new byte[16];
		CryptoHelper.copyByteArray(null, ba, ba.length);
	}

	@Test(expected=NullPointerException.class)
	public final void testCopyByteArrayDestNullPointerException() {
		byte[] ba = new byte[16];
		CryptoHelper.copyByteArray(ba, null, ba.length);
	}

	@Test(expected=IndexOutOfBoundsException.class)
	public final void testCopyByteArrayIndexOutOfBoundsException() {
		byte[] ba8 = new byte[8];
		byte[] ba16 = new byte[16];
		CryptoHelper.copyByteArray(ba8, ba16, ba16.length);
	}

	private void fillByteArray(byte[] ba, byte b) {
		for(int i = 0; i < ba.length; i++ ) {
			ba[i] = b;
		}
	}

	private boolean checkByteArray(byte[] ba, byte b) {
		for(int i = 0; i < ba.length; i++ ) {
			if ( ba[i] != b ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Run all the test cases in this suite.
	 * This is to allow running from {@code org.owasp.esapi.AllTests} which
	 * uses a JUnit 3 test runner.
	 */
	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(CryptoHelperTest.class);
	}
}
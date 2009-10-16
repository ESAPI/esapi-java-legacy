package org.owasp.esapi;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import junit.framework.JUnit4TestAdapter;
import junit.framework.TestCase;
import org.junit.Test;
import org.owasp.esapi.util.CryptoHelperTest;

public class PlainTextTest {
	
	private String unicodeStr = "A\u00ea\u00f1\u00fcC";	// I.e., "AêñüC"
	private String altString  = "AêñüC";				// Same as above.
	
	@Test
	public final void testUnicodeString() {
		assertTrue(unicodeStr.equals(altString));
		try {
			byte[] utf8Bytes = unicodeStr.getBytes("UTF-8");
			PlainText pt1 = new PlainText(unicodeStr);
			PlainText pt2 = new PlainText(altString);
			
			assertTrue( pt1.equals(pt2) );
			assertFalse( pt1.equals( unicodeStr ) );
			assertTrue( pt1.length() == utf8Bytes.length );
			assertTrue( Arrays.equals(utf8Bytes, pt1.asBytes()) );			
			assertTrue( pt1.hashCode() == unicodeStr.hashCode() );
			
		} catch (UnsupportedEncodingException e) {
			fail("No UTF-8 byte encoding: " + e);
			e.printStackTrace(System.err);
		}
	}

	@Test
	public final void testEmptyString() {
		PlainText mt  = new PlainText("");
		assertTrue( mt.length() == 0 );
		byte[] ba = mt.asBytes();
		assertTrue( ba != null && ba.length == 0 );
	}

	@Test
	public final void testOverwrite() {
		try {
			byte[] utf8Bytes = altString.getBytes("UTF-8");
			PlainText pt = new PlainText(utf8Bytes);
			assertTrue( pt.toString().equals(altString) );
			assertTrue( Arrays.equals(utf8Bytes, pt.asBytes()) );			
			assertTrue( pt.hashCode() == unicodeStr.hashCode() );
			
			int origLen = utf8Bytes.length;

			pt.overwrite();
			assertTrue( utf8Bytes != null );
			assertTrue( pt.asBytes() != null );
			assertTrue( utf8Bytes == pt.asBytes() );

// DISCUSS:
// See discussion note regarding method PlainText.overwrite(). Uncomment this
// try / catch block if we set 'rawBytes' in this method to null.
//
//			try {
//				@SuppressWarnings("unused")
//				int len = pt.length();
//			} catch( NullPointerException npe ) {
//				assertTrue( "Caught expected NullPointerException", true );
//			}
			int afterLen = utf8Bytes.length;
			assertTrue( origLen == afterLen );
			System.out.println("Length after overwritting: " + afterLen);
			for (int i = 0; i < afterLen; i++ ) {
				System.out.println("utf8Bytes[" + i + "] = " + utf8Bytes[i]);
			}
		} catch (UnsupportedEncodingException e) {
			fail("No UTF-8 byte encoding: " + e);
			e.printStackTrace(System.err);
		}
	}

	/**
	 * Run all the test cases in this suite.
	 * This is to allow running from {@code org.owasp.esapi.AllTests} which
	 * uses a JUnit 3 test runner.
	 */
	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(PlainTextTest.class);
	}
}

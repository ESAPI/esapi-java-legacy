package org.owasp.esapi.crypto;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import junit.framework.JUnit4TestAdapter;
import org.junit.Test;
import org.owasp.esapi.crypto.PlainText;

public class PlainTextTest {
	
	private String unicodeStr = "A\u00ea\u00f1\u00fcC";	// I.e., "AêñüC"
	private String altString  = "AêñüC";				// Same as above.
	
	/* NOTE: This test will not work on Windows unless executed under
	 * Eclipse and the file is stored / treated as a UTF-8 encoded file
	 * rather than the Windows native OS encoding of Windows-1252 (aka,
	 * CP-1252). Therefore this test case has a check to not run the test
	 * unless
	 *     unicodeStr.equals(altString)
	 * is true. If not the test is skipped and a message is printed to stderr.
	 * Jim Manico made an attempt to address this (see private email to
	 * kevin.w.wall@gmail.com on 11/26/2009, subject "Re: [OWASP-ESAPI] Unit
	 * Tests Status") to correct this problem by setting some SVN attribute
	 * to standardize all source files to UTF-8, but not all Subversion clients
	 * are either honoring this or perhaps Windows just overrides this. Either
	 * way, this test (which used to be an assertTrue() expression) was
	 * introduced to account for this.
	 */
	@Test
	public final void testUnicodeString() {
	    // These 2 strings are *meant* to be equal. If they are not, please
	    // do *NOT* change the test. It's a Windows thing. Sorry. Change your
	    // OS instead. ;-)
	    if ( ! unicodeStr.equals(altString) ) {
	        System.err.println("Skipping JUnit test case " +
	                           "PlainTextTest.testUnicodeString() on OS " +
	                           System.getProperty("os.name") );
	        return;
	    }
		try {
			byte[] utf8Bytes = unicodeStr.getBytes("UTF-8");
			PlainText pt1 = new PlainText(unicodeStr);
			PlainText pt2 = new PlainText(altString);
			
			assertTrue( pt1.equals(pt1) );   // Equals self
			assertFalse( pt1.equals(null) );
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
	public final void testNullCase() {
	    int counter = 0;
	    try {
            byte[] bytes = null;
            @SuppressWarnings("unused")
            PlainText pt = new PlainText(bytes);
            fail("testNullCase(): Expected NullPointerException or AssertionError");
        } catch (NullPointerException e) {
            // Will get this case if assertions are not enabled for PlainText.
            // System.err.println("Caught NullPointerException; exception was: " + e);
            // e.printStackTrace(System.err);
            counter++;
        } catch (AssertionError e) {
            // Will get this case if assertions *are* enabled for PlainText.
            // System.err.println("Caught AssertionError; exception was: " + e);
            // e.printStackTrace(System.err);
            counter++;
        } finally {
            assertTrue( counter > 0 );
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
			byte[] origBytes = unicodeStr.getBytes("UTF-8");
			PlainText pt = new PlainText(origBytes);
			assertTrue( pt.toString().equals(unicodeStr) );
			assertTrue( Arrays.equals(origBytes, pt.asBytes()) );			
			assertTrue( pt.hashCode() == unicodeStr.hashCode() );
			
			int origLen = origBytes.length;

			pt.overwrite();
	        byte[] overwrittenBytes = pt.asBytes();
			assertTrue( overwrittenBytes != null );
			assertFalse( Arrays.equals( origBytes, overwrittenBytes ) );

			// Ensure that ALL the bytes overwritten with '*'.
			int afterLen = overwrittenBytes.length;
			assertTrue( origLen == afterLen );
			int sum = 0;
			for( int i = 0; i < afterLen; i++ ) {
			    if ( overwrittenBytes[i] == '*' ) {
			        sum++;
			    }
			}
			assertTrue( afterLen == sum );
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

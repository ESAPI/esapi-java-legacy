package org.owasp.esapi;

import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.owasp.esapi.StringUtilities;

public class StringUtilitiesTest extends TestCase {

	/**
     * Run all the test cases in this suite.
     * This is to allow running from {@code org.owasp.esapi.AllTests}.
     * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(StringUtilitiesTest.class);
        return suite;
    }
    
    /** Test the getLevenshteinDistance() method. */
    public void testGetLevenshteinDistance() {
    	String src    = "GUMBO";
    	String target = "GAMBOL";
    	assertTrue( 2 == StringUtilities.getLevenshteinDistance(src, target) );
    	assertTrue( 2 == StringUtilities.getLevenshteinDistance(target, src) );
    	assertTrue( 0 == StringUtilities.getLevenshteinDistance(src, src) );
    	assertTrue( 5 == StringUtilities.getLevenshteinDistance(src, "") );
    	assertTrue( 6 == StringUtilities.getLevenshteinDistance("", target) );

    	try {
    		@SuppressWarnings("unused")
			int ldist = StringUtilities.getLevenshteinDistance(null, "abc");
    	} catch ( IllegalArgumentException ex ) {
    		assertTrue( ex.getClass().getName().equals( IllegalArgumentException.class.getName() ));
    	}

    	try {
    		@SuppressWarnings("unused")
			int ldist = StringUtilities.getLevenshteinDistance("abc", null);
    	} catch ( IllegalArgumentException ex ) {
    		assertTrue( ex.getClass().getName().equals( IllegalArgumentException.class.getName() ));
    	}
    }

    /** Test the union() method. */
    public void testUnion() {
		char[] a1 = { 'a', 'b', 'c' };
		char[] a2 = { 'c', 'd', 'e' };
		char[] union = StringUtilities.union(a1, a2);
		assertTrue( Arrays.equals( union, new char[] {'a','b','c','d','e' } ) );
    }
    
    /** Test the contains() method. */
    public void contains() {
		StringBuilder sb = new StringBuilder( "abc" );
		assertTrue( StringUtilities.contains(sb, 'b') );
		assertFalse( StringUtilities.contains(sb, 'x') );
    }

    /** Test the notNullOrEmpty() method. */
    public void testNotNullOrEmpty() {
    	String str = "A string";
    	assertTrue( StringUtilities.notNullOrEmpty(str, false) );
    	assertTrue( StringUtilities.notNullOrEmpty(str, true) );
    	str = "   A  string  ";
       	assertTrue( StringUtilities.notNullOrEmpty(str, false) );
    	assertTrue( StringUtilities.notNullOrEmpty(str, true) );
    	str = "   ";
       	assertTrue( StringUtilities.notNullOrEmpty(str, false) );
    	assertFalse( StringUtilities.notNullOrEmpty(str, true) );
    	str = "";
       	assertFalse( StringUtilities.notNullOrEmpty(str, false) );
    	assertFalse( StringUtilities.notNullOrEmpty(str, true) );
    	str = null;
       	assertFalse( StringUtilities.notNullOrEmpty(str, false) );
    	assertFalse( StringUtilities.notNullOrEmpty(str, true) );
    }

    public void testReplaceNull() {
        assertEquals( "TEST", StringUtilities.replaceNull( "TEST", "ABCD" ) );
        assertEquals( "REPLACED", StringUtilities.replaceNull( "NULL", "REPLACED" ) );
        assertEquals( "Replaced", StringUtilities.replaceNull( null, "Replaced" ) );
        assertEquals( "Replaced", StringUtilities.replaceNull( "         ", "Replaced" ) );
        assertEquals( "   Test   ", StringUtilities.replaceNull( "   Test   ", "Replaced" ) );
        assertEquals( "Replaced", StringUtilities.replaceNull( "     NULL ", "Replaced" ) );
    }
}

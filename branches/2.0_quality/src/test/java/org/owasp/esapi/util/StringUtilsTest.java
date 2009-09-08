package org.owasp.esapi.util;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class StringUtilsTest extends TestCase {

	/**
     * Run all the test cases in this suite.
     * This is to allow running from {@code org.owasp.esapi.AllTests}.
     * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(StringUtilsTest.class);
        return suite;
    }
    
    /** Test the getLevenshteinDistance() method. */
    public void testGetLevenshteinDistance() {
    	String src    = "GUMBO";
    	String target = "GAMBOL";
    	assertTrue( 2 == StringUtils.getLevenshteinDistance(src, target) );
    	assertTrue( 2 == StringUtils.getLevenshteinDistance(target, src) );
    	assertTrue( 0 == StringUtils.getLevenshteinDistance(src, src) );
    	assertTrue( 5 == StringUtils.getLevenshteinDistance(src, "") );
    	assertTrue( 6 == StringUtils.getLevenshteinDistance("", target) );

    	try {
    		@SuppressWarnings("unused")
			int ldist = StringUtils.getLevenshteinDistance(null, "abc");
    	} catch ( IllegalArgumentException ex ) {
    		assertTrue( ex.getClass().getName().equals( IllegalArgumentException.class.getName() ));
    	}

    	try {
    		@SuppressWarnings("unused")
			int ldist = StringUtils.getLevenshteinDistance("abc", null);
    	} catch ( IllegalArgumentException ex ) {
    		assertTrue( ex.getClass().getName().equals( IllegalArgumentException.class.getName() ));
    	}
    }
    
    /** Test the notNullOrEmpty() method. */
    public void testNotNullOrEmpty() {
    	String str = "A string";
    	assertTrue( StringUtils.notNullOrEmpty(str, false) );
    	assertTrue( StringUtils.notNullOrEmpty(str, true) );
    	str = "   A  string  ";
       	assertTrue( StringUtils.notNullOrEmpty(str, false) );
    	assertTrue( StringUtils.notNullOrEmpty(str, true) );
    	str = "   ";
       	assertTrue( StringUtils.notNullOrEmpty(str, false) );
    	assertFalse( StringUtils.notNullOrEmpty(str, true) );
    	str = "";
       	assertFalse( StringUtils.notNullOrEmpty(str, false) );
    	assertFalse( StringUtils.notNullOrEmpty(str, true) );
    	str = null;
       	assertFalse( StringUtils.notNullOrEmpty(str, false) );
    	assertFalse( StringUtils.notNullOrEmpty(str, true) );
    }
}

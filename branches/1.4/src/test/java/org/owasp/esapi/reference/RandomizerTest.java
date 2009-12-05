/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.reference;

import java.util.ArrayList;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Randomizer;
import org.owasp.esapi.errors.EncryptionException;

/**
 * The Class RandomizerTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class RandomizerTest extends TestCase {
    
    /**
	 * Instantiates a new randomizer test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public RandomizerTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     */
    protected void setUp() throws Exception {
    	// none
    }

    /**
     * {@inheritDoc}
     */
    protected void tearDown() throws Exception {
    	// none
    }

    /**
	 * Suite.
	 * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(RandomizerTest.class);        
        return suite;
    }

    /**
	 * Test of getRandomString method, of class org.owasp.esapi.Randomizer.
	 */
    public void testGetRandomString() {
        System.out.println("getRandomString");
        int length = 20;
        Randomizer instance = ESAPI.randomizer();
        for ( int i = 0; i < 100; i++ ) {
            String result = instance.getRandomString(length, DefaultEncoder.CHAR_ALPHANUMERICS );
            for ( int j=0;j<result.length();j++ ) {
            	if ( !((DefaultEncoder)ESAPI.encoder()).isContained(DefaultEncoder.CHAR_ALPHANUMERICS, result.charAt(j))) {
            		fail();
            	}
            }
            assertEquals(length, result.length());
        }
    }

    /**
	 * Test of getRandomInteger method, of class org.owasp.esapi.Randomizer.
	 */
    public void testGetRandomInteger() {
        System.out.println("getRandomInteger");        
        int min = -20;
        int max = 100;
        Randomizer instance = ESAPI.randomizer();        
        int minResult = ( max - min ) / 2;
        int maxResult = ( max - min ) / 2;
        for ( int i = 0; i < 100; i++ ) {
            int result = instance.getRandomInteger(min, max);
            if ( result < minResult ) minResult = result;
            if ( result > maxResult ) maxResult = result;
        }
        assertEquals(true, (minResult >= min && maxResult < max) );
    }

    /**
	 * Test of getRandomReal method, of class org.owasp.esapi.Randomizer.
	 */
    public void testGetRandomReal() {
        System.out.println("getRandomReal");
        float min = -20.5234F;
        float max = 100.12124F;
        Randomizer instance = ESAPI.randomizer();
        float minResult = ( max - min ) / 2;
        float maxResult = ( max - min ) / 2;
        for ( int i = 0; i < 100; i++ ) {
            float result = instance.getRandomReal(min, max);
            if ( result < minResult ) minResult = result;
            if ( result > maxResult ) maxResult = result;
        }
        assertEquals(true, (minResult >= min && maxResult < max));
    }
    
    
    /**
     * Test of getRandomGUID method, of class org.owasp.esapi.Randomizer.
     */
    public void testGetRandomGUID() throws EncryptionException {
        System.out.println("getRandomGUID");
        Randomizer instance = ESAPI.randomizer();
        ArrayList list = new ArrayList();
        for ( int i = 0; i < 100; i++ ) {
            String guid = instance.getRandomGUID();
            if ( list.contains( guid ) ) fail();
            list.add( guid );
        }
    }

     
}

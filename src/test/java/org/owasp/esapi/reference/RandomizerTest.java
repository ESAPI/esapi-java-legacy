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

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.Randomizer;
import org.owasp.esapi.codecs.Codec;
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
     * @throws Exception
     */
    protected void setUp() throws Exception {
    	// none
    }

    /**
     * {@inheritDoc}
     * @throws Exception
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
        int trials = 1000;
        Randomizer instance = ESAPI.randomizer();
        int[] counts = new int[128];
        for ( int i = 0; i < 1000; i++ ) {
            String result = instance.getRandomString(length, EncoderConstants.CHAR_ALPHANUMERICS );
            for ( int j=0;j<result.length();j++ ) {
            	char c = result.charAt(j);
            	counts[c]++;
            }
            assertEquals(length, result.length());
        }
        
        // Simple check to see if the overall character counts are within 10% of each other
        int min=Integer.MAX_VALUE;
        int max=0;
        for ( int i = 0; i < 128; i++ ) {
        	if ( counts[i] > max ) { max = counts[i]; } 
        	if ( counts[i] > 0 && counts[i] < min ) { min = counts[i]; }
        	if ( max - min > trials/10 ) {
        		fail( "getRandomString randomness counts are off" );
        	}
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
     * @throws EncryptionException
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

    
    /**
     * Run this class to generate a file named "tokens.txt" with 20,000 random 20 character ALPHANUMERIC tokens.
     * Use Burp Pro sequencer to load this file and run a series of randomness tests.
     * 
     * NOTE: be careful not to include any CRLF characters (10 or 13 ASCII) because they'll create new tokens
     * Check to be sure your analysis tool loads exactly 20,000 tokens of 20 characters each.
     */
    
	public static void main(String[] args) throws IOException {
		FileWriter fw = new FileWriter("tokens.txt");
		for (int i = 0; i < 20000; i++) {
			String token = ESAPI.randomizer().getRandomString(20, EncoderConstants.CHAR_ALPHANUMERICS);
			fw.write(token + "\n");
		}
		fw.close();
	}


     
}

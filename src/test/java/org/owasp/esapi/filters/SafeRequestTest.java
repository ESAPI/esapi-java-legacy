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
package org.owasp.esapi.filters;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.http.MockHttpServletRequest;


/**
 * The Class SafeRequestTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class SafeRequestTest extends TestCase {

	/**
	 * Instantiates a new access controller test.
	 * 
	 * @param testName
     *            the test name
     * @throws Exception
	 */
	public SafeRequestTest(String testName) throws Exception {
		super(testName);
	}

    /**
     * {@inheritDoc}
     *
     * @throws Exception
     */
	protected void setUp() throws Exception {
	}

    /**
     * {@inheritDoc}
     *
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
		TestSuite suite = new TestSuite(SafeRequestTest.class);
		return suite;
	}

    /**
     *
     */
    public void testGetRequestParameters() {
    	System.out.println( "getRequestParameters");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter( "one","1" );
        request.addParameter( "two","2" );
        request.addParameter( "one","3" );
        request.addParameter( "one","4" );
        SecurityWrapperRequest safeRequest = new SecurityWrapperRequest( request );
        String[] params = safeRequest.getParameterValues("one");
        String out = "";
        for (int i = 0; i < params.length; i++ ) out += params[i];
        assertEquals( "134", out );
	}
	

}

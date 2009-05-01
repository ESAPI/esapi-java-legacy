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
package org.owasp.esapi.waf.internal;

import java.util.ArrayList;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.internal.InterceptingServletOutputStream;

/**
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class InterceptingHttpServletResponseTest extends TestCase {
    
    /**
	 * Instantiates a new test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public InterceptingHttpServletResponseTest(String testName) {
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
        TestSuite suite = new TestSuite(InterceptingHttpServletResponseTest.class);
        return suite;
    }

    
    /**
	 * Test.
     */
    public void testRequest() throws Exception {
        System.out.println("InterceptingHTTPServletResponse");
   	    MockHttpServletResponse mres = new MockHttpServletResponse();
        InterceptingHTTPServletResponse ires = new InterceptingHTTPServletResponse(mres, false, new ArrayList() );
        InterceptingServletOutputStream isos = (InterceptingServletOutputStream)ires.getOutputStream();
        // isos.println( "Hello" );
        // ires.getOutputStream().println( "Hello" );
        ires.getWriter().println("Hello");
        assertEquals( "Hello\r\n", new String( isos.getResponseBytes() ) );
    }
}

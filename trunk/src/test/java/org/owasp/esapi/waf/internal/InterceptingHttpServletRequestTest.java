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

import org.owasp.esapi.waf.WAFFilterTest;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterConfig;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.http.MockFilterChain;
import org.owasp.esapi.http.MockFilterConfig;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.waf.ESAPIWebApplicationFirewallFilter;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletRequest;

/**
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class InterceptingHttpServletRequestTest extends TestCase {

    /**
	 * Instantiates a new test.
	 *
	 * @param testName
	 *            the test name
	 */
    public InterceptingHttpServletRequestTest(String testName) {
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
        TestSuite suite = new TestSuite(InterceptingHttpServletRequestTest.class);
        return suite;
    }


    /**
	 * Test.
     */
    public void testRequest() throws Exception {
        System.out.println("InterceptingHTTPServletRequest");
   	    MockHttpServletRequest mreq = new MockHttpServletRequest();
   	    mreq.setMethod( "GET" );
        InterceptingHTTPServletRequest ireq = new InterceptingHTTPServletRequest(mreq);
        assertEquals( mreq.getMethod(), ireq.getMethod() );
    }
}

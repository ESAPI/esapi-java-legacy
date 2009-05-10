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

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletResponse;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;
import org.owasp.esapi.http.MockFilterChain;
import org.owasp.esapi.http.MockFilterConfig;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.reference.DefaultEncoder;

/**
 * The Class ClickjackFilterTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ClickjackFilterTest extends TestCase {
    
    /**
	 * @param testName
	 *            the test name
	 */
    public ClickjackFilterTest(String testName) {
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
        TestSuite suite = new TestSuite(ClickjackFilterTest.class);
        return suite;
    }

    
    /**
	 * Test of update method, of class org.owasp.esapi.AccessReferenceMap.
     * @throws Exception
     */
    public void testFilter() throws Exception {
        System.out.println("ClickjackFilter");

        Map map = new HashMap();
    	FilterConfig mfc = new MockFilterConfig( map );
    	ClickjackFilter filter = new ClickjackFilter();        
    	filter.init( mfc );
   	    MockHttpServletRequest request = new MockHttpServletRequest();
		
		// the mock filter chain writes the requested URI to the response body
		MockFilterChain chain = new MockFilterChain();

        URL url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "\nTest request: " + url );
        request = new MockHttpServletRequest( url );
    	MockHttpServletResponse response = new MockHttpServletResponse();
    	try {
        	filter.doFilter(request, response, chain);
        } catch( Exception e ) {
        	e.printStackTrace();
        	fail();
        }
        String header = response.getHeader( "X-FRAME-OPTIONS");
        System.out.println(">>>" + header );
        assertEquals( "DENY", header );
    }

}

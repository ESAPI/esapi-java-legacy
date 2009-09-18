/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf;

import java.net.URL;

import javax.servlet.http.HttpServletResponse;

import junit.framework.TestSuite;

import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

public class EnforceHTTPSTest extends WAFTestCase {

	public static TestSuite suite() {
		return new TestSuite(EnforceHTTPSTest.class);
	}
	
	public void setUp() throws Exception {
		super.setUp();
    	WAFTestUtility.setWAFPolicy( waf, "waf-policy.xml" );
	}

	public void testGoodScheme() throws Exception {
	    // test good scheme
		url = new URL( "https://www.example.com/" );
		System.out.println( "\nTest good scheme (https): " + url );
	    request = new MockHttpServletRequest( url );
	    request.getSession(true);
		response = new MockHttpServletResponse();
		createAndExecuteWAFResponseCodeTest( waf, request, response, HttpServletResponse.SC_OK );		
	}

     
	public void testBadScheme () throws Exception {
	    // test bad scheme
	    url = new URL( "http://www.example.com/images/test.jpg" );
		System.out.println( "\nTest bad scheme (no ssl): " + url );
	    request = new MockHttpServletRequest( url );
	    request.getSession(true);
		response = new MockHttpServletResponse();
		createAndExecuteWAFResponseCodeTest( waf, request, response, HttpServletResponse.SC_MOVED_PERMANENTLY );		
	}

}
